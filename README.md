# CVE-2026-35414 — OpenSSH Authorized Exposure Auditor

## Overview

This repository contains a **safe, authorized assessment tool** for identifying potential exposure to
**CVE-2026-35414** in environments running **OpenSSH** prior to version **10.3**.

The vulnerability relates to improper handling of SSH certificate principals when comma-separated values are used in combination with `authorized_keys` restrictions.

---

## Safety & Scope

This tool is intentionally designed to be **non-exploitative**.

It **does NOT**:

* Attempt authentication bypass
* Generate or use malicious SSH certificates
* Perform brute-force or credential attacks

It **DOES**:

* Identify potentially vulnerable OpenSSH versions
* Perform **authenticated configuration audits (optional)**
* Detect risky SSH certificate configurations
* Provide structured output for reporting and remediation

---

## Vulnerability Context

CVE-2026-35414 affects OpenSSH when:

* SSH certificate authentication is used
* `authorized_keys` contains:

  ```bash
  cert-authority,principals="user1,user2"
  ```
* Certificate principals include comma-separated values

In these scenarios, OpenSSH may incorrectly interpret principals, potentially allowing unintended access.

---

## Features

### Unauthenticated Checks

* SSH banner grabbing
* OpenSSH version detection
* Exposure classification (version-based)

### Authenticated Audit (Optional)

* Reads `authorized_keys` across user accounts
* Detects:

  * `cert-authority` usage
  * `principals=` restrictions
  * Comma-separated principal lists
* Reviews relevant `sshd` configuration

### Reporting

* Human-readable output
* JSON export
* CSV export

---

## Installation

```bash
git clone https://github.com/dehobbs/cve_2026_35414.git
cd cve-2026-35414-auditor
chmod +x cve_2026_35414_audit.py
```

No external dependencies required (Python 3.8+ recommended).

---

## Usage

### Single Target (Unauthenticated)

```bash
python3 cve_2026_35414_audit.py -t 192.168.1.10
```

---

### Multiple Targets

```bash
python3 cve_2026_35414_audit.py -f targets.txt --threads 25
```

---

### Authenticated Audit

```bash
python3 cve_2026_35414_audit.py \
  -t 192.168.1.10 \
  -u auditor \
  -i ~/.ssh/id_ed25519
```

---

### Export Results

```bash
python3 cve_2026_35414_audit.py \
  -f targets.txt \
  -u auditor \
  -i ~/.ssh/id_ed25519 \
  --json report.json \
  --csv report.csv
```

---

## Sample Output

```text
Host: 192.168.1.10:22
Exposure: CONFIRMED_EXPOSURE_CONDITION
Banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
OpenSSH Version: 9.6p1
Version Status: POTENTIALLY_AFFECTED_VERSION
Authenticated Audit: Yes
cert-authority Found: True
principals= Found: True
Comma-Separated Principals Found: True
```

---

## 🎯 Exposure Classification

| Level                          | Meaning                                   |
| ------------------------------ | ----------------------------------------- |
| `CONFIRMED_EXPOSURE_CONDITION` | All vulnerable conditions detected        |
| `REVIEW_REQUIRED`              | Partial risky configuration               |
| `POSSIBLE`                     | Vulnerable version only (unauthenticated) |
| `LOW`                          | No risky config detected                  |
| `UNREACHABLE`                  | Host not accessible                       |

---

## What to Look For

High-risk configurations:

```bash
cert-authority,principals="admin,root"
```

Risk factors:

* Multiple principals in a single string
* Use of SSH certificate authorities
* Lack of principal validation controls

---

## Mitigation

* Upgrade to **OpenSSH 10.3+**
* Avoid comma-separated principals
* Enforce strict CA issuance policies
* Prefer:

  * `TrustedUserCAKeys`
  * `AuthorizedPrincipalsFile`

---

## Limitations

* Cannot confirm exploitability without:

  * SSH CA access
  * Certificate issuance control
  * Banner-based detection may be inaccurate due to distro backports
  * Requires valid credentials for full audit capability

---

## Lab Validation (Recommended)

To fully validate exposure:

* Build a test SSH CA environment
* Issue certificates with comma-separated principals
* Observe authentication behavior

Perform only in authorized lab environments.

---


## 📄 License

MIT License

---

## Final Notes

This vulnerability is:

* Not remotely exploitable without access
* Not mass-exploitable
* High impact in SSH certificate-based environments

Use this tool as part of a broader security assessment strategy.
