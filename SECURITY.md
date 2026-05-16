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

## Threat model — what the scanner intentionally does NOT verify

This section documents design choices that look like vulnerabilities at first glance but are intentional, so external reviewers do not raise them as findings.

### TLS scanner runs with `verify_mode = ssl.CERT_NONE`

The `TLSScanner` (`pqc_audit/scanners/tls_scanner.py`) disables certificate-chain validation in the underlying `ssl.SSLContext` (`ctx.check_hostname = False`, `ctx.verify_mode = ssl.CERT_NONE`, `# noqa: S501`). This is *required* for the tool's primary use case: surfacing endpoints that present expired, self-signed, or otherwise broken certificates as findings (CWE-295 / CWE-298). A standard validating client would refuse the handshake and the auditor would never see the broken cert.

**Operational guidance**:

- Run `pqc-audit scan tls` only against endpoints you are explicitly authorized to audit. The handshake is unauthenticated and inspection-only — no fuzzing, no downgrade — but the verifier-less mode means you should not run it inside an HSTS preload context for any host you don't own.
- Output of the TLS scanner is descriptive, not prescriptive: the operator is responsible for re-validating findings before acting on them.

### PDF reporter is sandboxed against SSRF (since 0.2.1)

`pqc_audit/reporters/pdf_reporter.py` installs a custom `url_fetcher` for WeasyPrint (`_no_network_fetcher`) that rejects every URL scheme except `data:`. A tainted `AuditReport` that contains Markdown image / link syntax in vulnerability descriptions cannot turn the PDF render into an outbound HTTP / local-file fetch (CWE-918 / CWE-200).

### CBOM IDs are deterministic SHA-256-truncated (since 0.2.1)

`cbom_reporter.py` derives vulnerability IDs from `hashlib.sha256(title).hexdigest()[:8]` rather than Python's built-in `hash()`, which is per-interpreter randomized (PEP 456). This guarantees stable IDs across runs so consumers like Dependency-Track can de-duplicate findings.

### Policy names are whitelisted (since 0.2.1)

`pqc_audit/policies/__init__.py` validates the `--policy` argument against `^[A-Za-z0-9][A-Za-z0-9_-]*$` and verifies the resolved path stays inside the bundled policies directory. A hostile `--policy ../../etc/foo` is rejected before reaching `yaml.safe_load` (CWE-22 / CWE-73).

## Hall of fame

Security researchers who responsibly disclose valid vulnerabilities will be credited in `SECURITY-HALL-OF-FAME.md` (created on first acknowledgement) unless they prefer to remain anonymous.
