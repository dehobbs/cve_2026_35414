#!/usr/bin/env python3
"""
CVE-2026-35414 Authorized OpenSSH Exposure Auditor

Safe capabilities:
- Remote SSH banner/version check
- Optional authenticated config review over SSH
- Searches authorized_keys for cert-authority + principals=
- Produces human, JSON, or CSV output

This tool does NOT:
- exploit the vulnerability
- attempt authentication bypass
- brute force credentials
- craft or use malicious certificates
"""

import argparse
import csv
import json
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional


CVE_ID = "CVE-2026-35414"


@dataclass
class Finding:
    host: str
    port: int
    banner: str = ""
    openssh_version: str = ""
    version_status: str = "UNKNOWN"
    authenticated: bool = False
    cert_authority_found: bool = False
    principals_found: bool = False
    multi_principal_found: bool = False
    exposure: str = "UNKNOWN"
    evidence: List[str] = None
    error: str = ""

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []


def grab_ssh_banner(host: str, port: int, timeout: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(255).decode(errors="ignore").strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def parse_openssh_version(banner: str) -> Optional[str]:
    match = re.search(r"OpenSSH[_-](\d+\.\d+(?:p\d+)?)", banner, re.IGNORECASE)
    return match.group(1) if match else None


def version_is_less_than_10_3(version: str) -> bool:
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match:
        return False

    major = int(match.group(1))
    minor = int(match.group(2))

    return major < 10 or (major == 10 and minor < 3)


def run_ssh_command(
    host: str,
    port: int,
    user: str,
    key: Optional[str],
    command: str,
    timeout: int,
) -> subprocess.CompletedProcess:
    ssh_cmd = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=8",
    ]

    if key:
        ssh_cmd.extend(["-i", key])

    ssh_cmd.append(f"{user}@{host}")
    ssh_cmd.append(command)

    return subprocess.run(
        ssh_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def authenticated_audit(
    finding: Finding,
    user: str,
    key: Optional[str],
    timeout: int,
) -> Finding:
    command = r"""
set -o pipefail 2>/dev/null || true

echo "### SSH_VERSION"
ssh -V 2>&1 || true

echo "### SSHD_CONFIG"
(sshd -T 2>/dev/null | egrep -i 'trustedusercakeys|authorizedprincipalsfile|pubkeyauthentication|authorizedkeysfile') || true

echo "### AUTHORIZED_KEYS_CA_PRINCIPALS"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  grep -nE 'cert-authority|principals=' "$f" 2>/dev/null | sed "s|^|$f:|"
done
"""

    try:
        result = run_ssh_command(
            finding.host,
            finding.port,
            user,
            key,
            command,
            timeout,
        )
    except subprocess.TimeoutExpired:
        finding.error = "Authenticated SSH audit timed out"
        return finding
    except Exception as exc:
        finding.error = f"Authenticated SSH audit failed: {exc}"
        return finding

    if result.returncode != 0:
        finding.error = result.stderr.strip() or "Authenticated SSH audit failed"
        return finding

    finding.authenticated = True
    output = result.stdout

    for line in output.splitlines():
        line_clean = line.strip()

        if not line_clean:
            continue

        lower = line_clean.lower()

        if "cert-authority" in lower:
            finding.cert_authority_found = True
            finding.evidence.append(line_clean)

        if "principals=" in lower:
            finding.principals_found = True
            finding.evidence.append(line_clean)

            principal_match = re.search(r'principals="([^"]+)"', line_clean)
            if principal_match and "," in principal_match.group(1):
                finding.multi_principal_found = True

    return finding


def classify_exposure(finding: Finding) -> Finding:
    if finding.banner.startswith("ERROR:"):
        finding.exposure = "UNREACHABLE"
        finding.error = finding.banner
        return finding

    version = parse_openssh_version(finding.banner)

    if not version:
        finding.version_status = "UNKNOWN_VERSION"
        finding.exposure = "UNKNOWN"
        return finding

    finding.openssh_version = version

    if version_is_less_than_10_3(version):
        finding.version_status = "POTENTIALLY_AFFECTED_VERSION"
    else:
        finding.version_status = "LIKELY_FIXED_VERSION"
        finding.exposure = "LOW"
        return finding

    if not finding.authenticated:
        finding.exposure = "POSSIBLE"
        return finding

    if (
        finding.cert_authority_found
        and finding.principals_found
        and finding.multi_principal_found
    ):
        finding.exposure = "CONFIRMED_EXPOSURE_CONDITION"
    elif finding.cert_authority_found and finding.principals_found:
        finding.exposure = "REVIEW_REQUIRED"
    elif finding.cert_authority_found:
        finding.exposure = "LOW_TO_MEDIUM_REVIEW_REQUIRED"
    else:
        finding.exposure = "LOW"

    return finding


def audit_host(
    host: str,
    port: int,
    timeout: int,
    user: Optional[str],
    key: Optional[str],
) -> Finding:
    finding = Finding(host=host, port=port)

    finding.banner = grab_ssh_banner(host, port, timeout)
    finding = classify_exposure(finding)

    if user and not finding.banner.startswith("ERROR:"):
        finding = authenticated_audit(finding, user, key, timeout)
        finding = classify_exposure(finding)

    return finding


def load_targets(target: Optional[str], file_path: Optional[str]) -> List[str]:
    targets = []

    if target:
        targets.append(target)

    if file_path:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Target file not found: {file_path}")

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    return sorted(set(targets))


def print_human(results: List[Finding]) -> None:
    print(f"\n{CVE_ID} OpenSSH Authorized Exposure Audit")
    print("=" * 80)

    for r in results:
        print(f"\nHost: {r.host}:{r.port}")
        print(f"Exposure: {r.exposure}")
        print(f"Banner: {r.banner}")
        print(f"OpenSSH Version: {r.openssh_version or 'Unknown'}")
        print(f"Version Status: {r.version_status}")
        print(f"Authenticated Audit: {'Yes' if r.authenticated else 'No'}")
        print(f"cert-authority Found: {r.cert_authority_found}")
        print(f"principals= Found: {r.principals_found}")
        print(f"Comma-Separated Principals Found: {r.multi_principal_found}")

        if r.error:
            print(f"Error: {r.error}")

        if r.evidence:
            print("Evidence:")
            for item in r.evidence[:20]:
                print(f"  - {item}")

        print("-" * 80)


def write_json(results: List[Finding], output: str) -> None:
    with open(output, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)


def write_csv(results: List[Finding], output: str) -> None:
    fields = [
        "host",
        "port",
        "banner",
        "openssh_version",
        "version_status",
        "authenticated",
        "cert_authority_found",
        "principals_found",
        "multi_principal_found",
        "exposure",
        "error",
    ]

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for r in results:
            row = asdict(r)
            row.pop("evidence", None)
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Safe authorized exposure auditor for {CVE_ID}"
    )

    parser.add_argument("-t", "--target", help="Single target hostname or IP")
    parser.add_argument("-f", "--file", help="File containing targets, one per line")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent workers")

    parser.add_argument(
        "-u",
        "--user",
        help="Optional SSH username for authenticated audit",
    )

    parser.add_argument(
        "-i",
        "--identity-file",
        help="Optional SSH private key for authenticated audit",
    )

    parser.add_argument(
        "--json",
        dest="json_output",
        help="Write JSON report to file",
    )

    parser.add_argument(
        "--csv",
        dest="csv_output",
        help="Write CSV report to file",
    )

    args = parser.parse_args()

    try:
        targets = load_targets(args.target, args.file)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not targets:
        print("No targets provided. Use -t <host> or -f targets.txt", file=sys.stderr)
        return 1

    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(
                audit_host,
                host,
                args.port,
                args.timeout,
                args.user,
                args.identity_file,
            )
            for host in targets
        ]

        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: x.host)

    print_human(results)

    if args.json_output:
        write_json(results, args.json_output)
        print(f"\nJSON report written to: {args.json_output}")

    if args.csv_output:
        write_csv(results, args.csv_output)
        print(f"CSV report written to: {args.csv_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
