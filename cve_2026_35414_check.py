#!/usr/bin/env python3
import socket
import argparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

VULN_CVE = "CVE-2026-35414"

def parse_openssh_version(banner):
    """
    Extract OpenSSH version from banners like:
    SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
    SSH-2.0-OpenSSH_10.3
    """
    match = re.search(r"OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?", banner, re.I)
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0

    return major, minor, patch


def is_version_potentially_vulnerable(version):
    """
    OpenSSH before 10.3 is affected upstream.
    Distro backports may fix older-looking versions.
    """
    major, minor, patch = version

    if major < 10:
        return True
    if major == 10 and minor < 3:
        return True

    return False


def grab_ssh_banner(host, port=22, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(255).decode(errors="ignore").strip()
            return banner
    except Exception as e:
        return f"ERROR: {e}"


def check_host(target, port, timeout):
    banner = grab_ssh_banner(target, port, timeout)

    result = {
        "host": target,
        "port": port,
        "banner": banner,
        "status": "UNKNOWN",
        "finding": "",
    }

    if banner.startswith("ERROR:"):
        result["status"] = "UNREACHABLE"
        result["finding"] = banner
        return result

    version = parse_openssh_version(banner)

    if not version:
        result["status"] = "UNKNOWN"
        result["finding"] = "SSH service detected, but OpenSSH version could not be parsed."
        return result

    if is_version_potentially_vulnerable(version):
        result["status"] = "POSSIBLY VULNERABLE"
        result["finding"] = (
            f"OpenSSH version appears to be before 10.3. "
            f"This may be affected by {VULN_CVE}, but exploitability cannot be confirmed remotely "
            f"without checking authorized_keys certificate-authority principals configuration."
        )
    else:
        result["status"] = "LIKELY NOT VULNERABLE"
        result["finding"] = "OpenSSH version appears to be 10.3 or newer."

    return result


def load_targets(args):
    targets = []

    if args.target:
        targets.append(args.target)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    return sorted(set(targets))


def main():
    parser = argparse.ArgumentParser(
        description="Safe remote exposure checker for CVE-2026-35414 OpenSSH"
    )

    parser.add_argument("-t", "--target", help="Single target hostname or IP")
    parser.add_argument("-f", "--file", help="File containing targets, one per line")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port, default 22")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")

    args = parser.parse_args()

    targets = load_targets(args)

    if not targets:
        print("No targets provided. Use -t <host> or -f targets.txt")
        return

    print(f"\n{VULN_CVE} OpenSSH Remote Exposure Check")
    print("=" * 70)
    print("Note: This is a non-invasive version/banner check only.")
    print("It cannot confirm exploitability without authenticated config review.\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(check_host, target, args.port, args.timeout)
            for target in targets
        ]

        for future in as_completed(futures):
            r = future.result()

            print(f"[{r['status']}] {r['host']}:{r['port']}")
            print(f"  Banner : {r['banner']}")
            print(f"  Finding: {r['finding']}")
            print("-" * 70)


if __name__ == "__main__":
    main()
