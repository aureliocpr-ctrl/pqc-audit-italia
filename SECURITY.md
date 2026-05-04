# Security policy

## Supported versions

`pqc-audit-italia` is in **alpha**. Security fixes target the latest commit on `main`. Once a 1.0 release is out, the latest two minor versions will be supported.

| Version | Supported           |
| ------- | ------------------- |
| `main`  | :white_check_mark:  |
| < 1.0   | :x: (alpha, no SLA) |

## Reporting a vulnerability

**Do not open a public issue** for security vulnerabilities.

Send a detailed report to `aureliocpr@gmail.com` with the subject prefix `[pqc-audit-italia security]`. Encrypt sensitive details with the maintainer's PGP key (fingerprint will be published in `docs/security-pgp.txt` before 1.0).

Please include:

- Affected version / commit hash
- Description of the vulnerability
- Reproduction steps
- Suggested fix or mitigation if known
- Whether you would like to be credited

## Response timeline

- **48 hours**: acknowledgement
- **7 days**: initial assessment, severity classification
- **30 days**: target for patch availability for high / critical severity
- **90 days**: target for advisory publication

## Scope

In scope:

- Code execution, crash, or memory corruption in the scanner
- Authentication / authorization bypass in the CLI / API
- Sensitive data leakage (e.g. accidental logging of private key material)
- Supply-chain risks (build script, CI workflow)

Out of scope:

- Findings about target systems scanned by the tool — those belong to the target's vulnerability disclosure program.
- Issues in third-party dependencies — please report upstream.
- Findings that require physical access to the host running the scanner.

## Hall of fame

Security researchers who responsibly disclose valid vulnerabilities will be credited in `SECURITY-HALL-OF-FAME.md` (created on first acknowledgement) unless they prefer to remain anonymous.
