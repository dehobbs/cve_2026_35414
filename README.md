# CVE-2026-35414 — OpenSSH Exposure Checker

## Overview

This repository contains a **safe, non-invasive assessment tool** for identifying potential exposure to **CVE-2026-35414**, a vulnerability affecting **OpenSSH** prior to version **10.3**.

The vulnerability stems from improper parsing of SSH certificate principals when comma-separated values are used, potentially allowing unintended authentication under specific configurations.

---

## Important Disclaimer

This tool **does NOT exploit the vulnerability**.

Due to the nature of CVE-2026-35414, **remote exploitation is not possible without**:

* Access to the target system’s SSH configuration
* Use of SSH certificate authentication
* Control of (or access to) a trusted Certificate Authority (CA)

This tool is designed for:

* **Red Team reconnaissance**
* **Blue Team exposure identification**
* **Security audits and asset inventory**

---

## What This Tool Does

* Connects to remote hosts over SSH (TCP/22 by default)
* Retrieves the SSH service banner
* Parses the reported OpenSSH version
* Flags systems running **potentially vulnerable versions (< 10.3)**

---

## Understanding the Vulnerability

CVE-2026-35414 affects environments using:

* SSH certificate authentication
* `authorized_keys` entries with:

  ```bash
  cert-authority,principals="user1,user2"
  ```
* Certificate Authorities that may issue principals containing commas

In these conditions, OpenSSH may incorrectly interpret principals, potentially allowing authentication bypass.

---

## Usage

### Single Target

```bash
python3 cve_2026_35414_check.py -t 192.168.1.10
```

### Multiple Targets

```bash
python3 cve_2026_35414_check.py -f targets.txt --threads 25
```

### Options

| Flag        | Description                  |
| ----------- | ---------------------------- |
| `-t`        | Single target IP or hostname |
| `-f`        | File containing targets      |
| `-p`        | SSH port (default: 22)       |
| `--threads` | Number of concurrent checks  |
| `--timeout` | Connection timeout           |

---

## Sample Output

```text
[POSSIBLY VULNERABLE] 192.168.1.10:22
  Banner : SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
  Finding: OpenSSH version appears to be before 10.3...
```

---

## Interpreting Results

| Status                  | Meaning                         |
| ----------------------- | ------------------------------- |
| `POSSIBLY VULNERABLE`   | OpenSSH version < 10.3 detected |
| `LIKELY NOT VULNERABLE` | OpenSSH 10.3+                   |
| `UNKNOWN`               | Could not determine version     |
| `UNREACHABLE`           | Host not accessible             |

---

## Limitations

This tool **cannot confirm exploitability**.

To validate the vulnerability, you must have:

* Access to `authorized_keys`
* Visibility into SSH CA configuration
* Ability to test certificate-based authentication

---

## Detection Guidance (Blue Team)

To confirm exposure internally:

```bash
grep -R "cert-authority" /home/*/.ssh/authorized_keys
grep -R "principals=" /home/*/.ssh/authorized_keys
```

Look specifically for:

```bash
principals="user1,user2"
```

---

## Mitigation

* Upgrade to **OpenSSH 10.3 or later**
* Restrict SSH certificate principal formats
* Avoid comma-separated principals where possible
* Prefer:

  * `TrustedUserCAKeys`
  * `AuthorizedPrincipalsFile`

---

## Future Enhancements

* Authenticated audit module
* SSH config parsing
* Fleet-wide reporting integration
* Integration with pentesting toolkits

---

## License

MIT License

---

## ⚡ Final Notes

This vulnerability is:

* Not remotely exploitable at scale
* Not an unauthenticated RCE
* High impact in environments using SSH certificate authentication

Use this tool as part of a broader security assessment strategy.
