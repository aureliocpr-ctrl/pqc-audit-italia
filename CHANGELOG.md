# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Scope note — what "audit reproducibility" means in this codebase

The Sprint 7 + Sprint 8 work refers to **audit reproducibility and
tamper-evidence**: a byte-stable canonical JSON, a SHA-256 fingerprint
of the report, a SHA-256 fingerprint of every rule-pack YAML that
drove the verdict, and frozen-clock + report-id env vars so two
re-runs produce a bit-identical digest.

This is the *technical* substrate. It is **not** by itself an eIDAS-
qualified electronic seal, an AgID-accredited qualified timestamp, or
a conformant *conservazione a norma* deliverable. Those statuses
require external certified authorities (Aruba PEC, Namirial, Infocert,
ETSI EN 319 421 TSAs, AgID-accredited conservation services). The
output of this codebase is engineered to feed those pipelines
unchanged — a regulator can detach the digest, hand it to a qualified
TSA, and obtain a qualified timestamp token over it.

Sprint 8 steps D + E add the bring-your-own signer hooks (RFC 3161
client + sigstore keyless wrapper) so the report can be sealed
before being sent to a qualified service. Anything beyond that
(qualified accreditation paperwork, eIDAS conformance assessment)
sits outside this repository.

## [Unreleased] — Sprint 9d (TLS chain validation)

Sprint 9d (2026-05-17) extends the TLS scanner from leaf-only to
**full-chain** introspection: every certificate the server sends on
the wire (leaf + intermediates + optional root) is parsed, classified
by structural position, surfaced as its own `CryptoAsset`, and
assessed individually for crypto weaknesses.

### Why this matters for a real audit

A leaf-only auditor misses **chain-wide weaknesses** that browsers,
ETSI, and CA/B Forum care about:

- An **RSA-1024 intermediate** in the chain breaks the security of an
  otherwise pristine ECDSA-P-256 leaf — the auditor must see both.
- A **SHA-1 signed intermediate or root** is a hard CA/B Forum
  retirement (>2017). Surfacing it in the SARIF/CBOM lets compliance
  teams find legacy stacks before browsers do.
- An **incomplete chain** (server forgets to ship intermediates) is
  the single most common AgID/PA TLS misconfiguration — silently
  works in Chrome (AIA chasing) but fails on hardened clients.
- Knowing **whether the chain terminates at a self-signed root** vs.
  a public CA intermediate is the eIDAS-relevant pedigree question:
  Let's Encrypt → ISRG vs. a qualified CA (Aruba, Namirial, Infocert)
  → AgID-accredited root.

### Added

- `pqc_audit.scanners.tls_scanner.classify_chain_positions(chain)` —
  pure helper that labels each cert in leaf-first order as
  `leaf` | `intermediate-N` | `root`. The `root` label is reserved
  for a last cert whose `subject == issuer` (TLS rarely ships the
  root on the wire — Let's Encrypt agid.gov.it 2026-05 chain is
  `[leaf, E7 intermediate]`, confirmed empirically).
- `pqc_audit.scanners.tls_scanner.extract_chain_summary(chain)` —
  CBOM/SARIF-ready dict (`chain_length`, `terminates_at_root`,
  `positions`, `subjects`, `issuers`, `signature_hashes`, plus per-
  cert `algorithms`). Stable schema contract for reporters.
- `pqc_audit.scanners.tls_scanner.assess_chain(chain, leaf_asset_id)` —
  per-cert vulnerability findings keyed to position-suffixed asset
  ids (`tls://host:port#intermediate-1`). Leaf is NOT re-assessed to
  avoid double-reporting. Adds a chain-wide LOW finding when the
  server presents only a non-self-signed leaf (incomplete chain).
- `TLSScanner.scan` now emits one `CryptoAsset` per chain element:
  the leaf retains its canonical `tls://host:port` id (back-compat
  for existing dashboards / pivots); intermediates and roots get
  `#intermediate-N` / `#root` suffixes. The leaf asset carries a
  `chain_length` + `terminates_at_root` + `chain_signature_hashes`
  + `chain_subjects` metadata block for downstream reporters.
- `_handshake` returns `chain_der: list[bytes]` via the Python 3.13
  `ssl.SSLSocket.get_unverified_chain()` API. Pre-3.13 runtimes
  degrade gracefully to `[leaf_der]` (single-element chain).
- 16 new pytest cases in `tests/unit/test_scanners_tls_chain.py`
  covering position classification (leaf-only, leaf+intermediate,
  leaf+intermediate+root, root recognized via self-issuance),
  summary fields, incomplete-chain finding, RSA-1024 intermediate
  finding, SHA-1 intermediate finding (uses openssl CLI to forge a
  real DER since cryptography 46+ refuses to sign SHA-1), and the
  end-to-end scanner integration (3 assets emitted for a 3-cert
  chain, weak intermediate finding points at `#intermediate-1`).

### Empirically verified end-to-end (REAL endpoint)

Two back-to-back scans of `www.agid.gov.it:443` with
`PQC_AUDIT_FROZEN_AT=2026-05-17T00:00:00Z` +
`PQC_AUDIT_REPORT_ID=sprint9d-chain-validation`:

| Field | Observed value |
|---|---|
| chain length | 2 (leaf + intermediate, no root — Let's Encrypt practice) |
| leaf | ECDSA-256 secp256r1, sha384 signature, `CN=www.agid.gov.it`, valid 2026-04-01 → 2026-06-30 (90 days) |
| intermediate-1 | ECDSA-384 secp384r1, sha256 signature, `CN=E7,O=Let's Encrypt,C=US`, issued by `CN=ISRG Root X1,...` |
| terminates_at_root | `false` (root sits in client trust store) |
| CBOM crypto-asset count | 2 (`crypto:tls://...:443` + `crypto:tls://...:443#intermediate-1`) |
| SARIF results | 2 (leaf + intermediate, both `PQC.QUANTUM_VULNERABLE.ECDSA-*` / `PQC.INTERMEDIATE_1.ECDSA-384`) |
| CycloneDX 1.6 schema validation | **PASS** (0 errors) |
| OASIS SARIF 2.1.0 schema validation | **PASS** (0 errors) |

The output JSON went from 2.2 KB (leaf-only) to 4.0 KB (chain) — the
extra 1.8 KB carries the position-suffixed asset, the chain metadata
block, and the per-cert finding. Same envelope, more truth.

### Honest gap list (not done in 9d — explicit roadmap)

- **No cryptographic chain verification.** We surface what the server
  sent, not whether the signatures actually chain. A malicious server
  could send unrelated cert blobs and we would still emit two assets.
  Cryptographic chain verification (issuer key → signature match) is
  a separate sprint (9d.2) because it requires a trust store
  consultation we do not ship.
- **No root cert lookup.** When the server omits the root (best
  practice), we do NOT walk the local trust store to fetch it. Two
  consequences: (1) we can't tell Let's Encrypt → ISRG vs. Aruba →
  AgID-accredited root from a single scan, (2) we never assess the
  root crypto. Both are 9d.3 candidates if PwC scope demands.
- **No SAN / hostname matching.** The leaf cert's
  `Subject Alternative Name` extension is parsed implicitly by the
  cryptography library but we don't surface a finding for `CN` vs.
  `host` drift. That belongs to a separate "TLS posture" sprint.
- Python <3.13 runtimes lose chain information silently (fall back
  to leaf-only). CI matrix should add a 3.11 leg with a recorded skip
  rather than a silent feature degradation.

## [Unreleased] — Sprint 4 (regulatory layer + security bump)

Sprint 4 (2026-05-17, continued same day as Sprint 1-3) layers four
additional regulation-anchored rule packs on top of the Sprint 1
baseline, and bumps `cryptography` to the patched 46.0.x series.

### Added — four regulation-anchored rule packs

- `pqc_audit/rule_packs/eu-crypto-regulatory-2026.yaml` — combined EU
  baseline anchored to CRA (Reg (EU) 2024/2847), DORA (Reg (EU)
  2022/2554), eIDAS2 (Reg (EU) 2024/1183), the ENISA Post-Quantum
  Cryptography recommendation (hybrid-first 2025-2030) and ETSI TS
  119 312 cryptographic suites. Discourages RSA-2048 / ECDSA-P-256
  ahead of the NIST 2030 deadline for new EU product placements.
- `pqc_audit/rule_packs/it-recepimento-nis2-2026.yaml` — Italian
  national layer anchored to D.Lgs. 4 settembre 2024 n. 138 (NIS2
  recepimento, GU 2024-10-01), ACN as competent authority, Banca
  d'Italia Circolare 285/2013 for bank ICT risk, and AGID for PA.
- `pqc_audit/rule_packs/agid-absc-2026.yaml` — AGID Misure Minime di
  Sicurezza ICT (ABSC) per the PA, plus a PQC-ready procurement
  baseline for new capitolato d'oneri from 2026 onward.
- `pqc_audit/rule_packs/fips-203-204-205-strict-2026.yaml` — STRICT
  variant aligned to NSA CNSA 2.0 (2022-09-07) that forbids classical
  RSA / ECDSA / ECDH outright instead of using the lenient NIST IR
  8547 transition window. Documented compose semantics: STRICT
  overlay adds RSA-2048 to `forbidden_algorithms` while leaving the
  lenient `deprecate_after` entry intact (callers enforce STRICT by
  reading `forbidden_algorithms` first).
- 11 new pytest cases in `tests/unit/test_rule_packs.py` pin the
  effective dates, regulatory anchors, and compose semantics. Total
  rule-pack tests: 25 (all green local Windows + cryptography 46.0.7).

### Security — cryptography 45.x → 46.0.7

- `pyproject.toml`: bumped `cryptography>=46.0.7,<47.0` (was
  `>=42.0,<46.0`) to address three pip-audit advisories in 45.0.x:
  CVE-2026-26007 (fix 46.0.5), CVE-2026-34073 (fix 46.0.6),
  CVE-2026-39892 (fix 46.0.7). The 45→46 line did not change the
  public Python API used by pqc-audit (X509, EC, RSA, hazmat). Full
  local unit suite re-ran green on 46.0.7.

### Added — Infrastructure-as-Code scanner (Sprint 4 #3)

- `pqc_audit.scanners.iac_scanner` — new regex-based scanner walking
  Terraform `.tf`, Kubernetes YAML, CloudFormation JSON / YAML files.
  V1 pattern catalog flags AWS KMS `customer_master_key_spec`
  (RSA-2048/3072/4096, ECC-NIST-P256/P384), AWS ACM `key_algorithm`
  (RSA-1024 CRITICAL), TLS version pinning (1.0/1.1 CRITICAL per RFC
  8996), and forbidden primitives RC4 / 3DES / MD5 / SHA-1 appearing
  as bounded tokens. False-positive guard: word-boundary regex and a
  comment stripper for `#` and `//` leaders so brand names like
  `ELBSecurityPolicy-WithRC4` do not trigger.
- New CLI subcommand `pqc-audit scan iac --path DIR_OR_FILE`.
- New `ScanTarget` literal `iac` mapped to `ScanCategory.CODE`.
- 14 unit tests pin the v1 pattern catalog +
  2 CLI tests for the subcommand.
- File walker caps at 10 000 files and 5 MiB per file (CWE-400).

### Changed — repo-wide `ruff format`

- Applied `ruff format` to the entire repo (14 files) to align with
  the CI gate `ruff format --check .`. No logic changes — purely
  whitespace / quote-style / line-break normalization.

### Added — JWKS endpoint live fetch scanner (Sprint 5 #2)

- `pqc_audit.scanners.jwks_scanner` — new scanner that fetches an
  RFC 7517 JWKS document (typical path
  `/.well-known/jwks.json`) and classifies every key by algorithm
  + size. Complementary to the existing `jwt_scanner`: that one
  inspects tokens at rest, this one inspects the *signing material*
  exposed by the authority. Findings:
    * `kty=RSA, n < 2048 bits` → CRITICAL (sub-FIPS minimum,
      SP 800-131A Rev. 2).
    * `kty=RSA, n in {2048, 3072}` → HIGH (NIST IR 8547
      deprecate-after-2030).
    * `kty=EC, crv in {P-256, P-384}` → HIGH (same IR 8547
      deprecation).
    * `kty=EC, crv=secp256k1` → MEDIUM (non-FIPS curve).
    * `kty=oct` → MEDIUM (symmetric distribution discouraged by
      RFC 8725 §3.5).
    * `alg=RS1 / HS1 / ES1` → HIGH (SHA-1 was withdrawn from FIPS
      approval in 2024).
- Security architecture (matches the security argument in
  SECURITY.md): HTTPS-only (no http://, no file://); SSRF guard
  refuses any hostname resolving to loopback / private / link-local /
  multicast / reserved / unspecified (incl. AWS metadata
  169.254.169.254); response cap 1 MiB; redirects refused (no 302
  to an internal endpoint that would bypass the SSRF guard);
  cert+hostname verification via the default SSL context.
- Offline mode: `--path local.json` for airgapped audits and
  reproducible fixtures.
- Stdlib-only: uses `urllib.request` + `ssl` — no new third-party
  dependency added.
- New `ScanTarget` literal `jwks` mapped to
  `ScanCategory.NETWORK`.
- New CLI subcommand
  `pqc-audit scan jwks --url https://.../jwks.json` or
  `--path local.json` (mutually exclusive).
- 24 unit tests in `tests/unit/test_jwks_scanner.py` cover each
  finding type, the SSRF guard (8 hostnames including
  169.254.169.254), the scheme guard, the both-host-and-path
  guard, the malformed JSON path, and the live fetch via
  monkeypatch. 2 CLI tests for the subcommand wiring.

### Changed — version bump 0.2.1 → 0.3.0-beta1 (Sprint 9 step C)

`__version__` in `pqc_audit/__init__.py` and `version` in
`pyproject.toml` had drifted: the tag `v0.3.0-beta1` was already
published on `main` but the running binary still self-identified
as `0.2.1`. Caught while dissecting a real `scan tls` output —
`tool_version: 0.2.1` appeared in every JSON / CBOM / SARIF
report.

Now coherent: `python -m pqc_audit version` → `0.3.0-beta1`,
JSON / CBOM (`metadata.tools[0].version`) / SARIF
(`runs[0].tool.driver.version`) all stamp the bumped value.

### End-to-end smoke against a real public endpoint (Sprint 9 step C)

Verified manually (not in the unit suite — network-bound) against
`https://www.agid.gov.it:443`, a public IT-government endpoint that
constitutes legitimate consumer-side scanning:

```
$ pqc-audit scan tls --host www.agid.gov.it --port 443 --compact > r.json
$ pqc-audit report --input r.json --format cbom  --output r.cbom.json
$ pqc-audit report --input r.json --format sarif --output r.sarif.json
```

Empirical results:

  * `scan tls` exit 0, 1.3 s, 2.2 kB JSON.
  * Discovered asset: `ECDSA-256 secp256r1`, cipher
    `TLS_AES_256_GCM_SHA384`, signature SHA-384, validity
    2026-04-01 → 2026-06-30 (Let's Encrypt 90 d), public-key
    SHA-256 fingerprint `261c3879...`.
  * Finding: 1 × `HIGH / CWE-327` "Quantum-vulnerable algorithm
    in use (ECDSA-256)".
  * CBOM output (2.6 kB) validates **0 errors** against the
    vendored CycloneDX 1.6 schema → Dependency-Track / Anchore /
    Microsoft SBOM Tool would ingest it.
  * SARIF output (2.4 kB) validates **0 errors** against the
    vendored OASIS SARIF 2.1.0 schema → GitHub Code Scanning /
    GitLab SAST / Azure DevOps would ingest it.
  * CBOM crypto-asset:
    ```
    bom-ref: crypto:tls://www.agid.gov.it:443
    primitive: signature
    parameterSetIdentifier: ECDSA-256
    classicalSecurityLevel: 256
    nistQuantumSecurityLevel: 0
    executionEnvironment: unknown
    ```
  * SARIF result:
    ```
    level: error
    ruleId: PQC.QUANTUM_VULNERABLE.ECDSA-256
    ```

Honest gap list (the smoke confirmed these are missing, not
present-but-broken):
  * Only the negotiated cipher is reported, not the full server
    cipher-suite enumeration.
  * The TLS chain validation stops at the leaf certificate — the
    intermediate and root are not introspected.
  * No OCSP / CRL revocation check.
  * No HSTS / cookie-flag / cert-pinning detection (these are
    HTTP-layer, not TLS).
  * No JA3 / JA4 fingerprint.
  * No PQC hybrid handshake detection (X25519+ML-KEM-768 etc.) —
    the algorithm map does not yet include the in-flight TLS
    draft codepoints.

### Fixed — rule-pack SHA-256 was NOT cross-OS stable (Sprint 9 step B)

`critic-orchestrator` adversarial review (job `a0302e7b67e46711`,
3 workers, $2.14, 147 s) returned `consensus=claim_holds (2-1-0)`
but the counterexample worker produced empirical proof of a real
regression in the reproducibility argument:

> Windows checkout with the Git default `autocrlf=true` materializes
> `pqc_audit/rule_packs/nist-core-2026.yaml` as 7279 bytes with CRLF
> → SHA-256 `02cd5e7bbc323a16b84b9ee64be27445a8d4f68ff22e3d4a85a8bde1ad6c66d7`.
> Same commit on Linux/macOS (or Windows `autocrlf=input/false`):
> 7067 bytes with LF → SHA-256 `a0650a024cf94073bf1ecb69ab6d95dfec2ba30b9863238fb50bbfef9e2c9241`.
> Hash mismatch with no semantic change in the file.

For PA Italian audits (target audience predominantly Windows, Git
for Windows installs with autocrlf=true by default), this would
have produced a false "rule pack tampered" signal on every Linux-
emitted audit when verified on a Windows reviewer's machine.
Sprint 7's reproducibility argument was empirically broken.

Two-layer fix:

  * **Load-bearing**: `_compile_pack_overlay()` now hashes
    `pack_path.read_bytes().replace(b"\r\n", b"\n")` instead of
    the raw working-tree bytes. The digest is now identical
    regardless of client autocrlf policy.
  * **Defense in depth**: new `.gitattributes` forces
    `eol=lf` on `pqc_audit/rule_packs/*.yaml`,
    `pqc_audit/policies/*.yaml`, and
    `tests/fixtures/schemas/*.json`, so the materialized file on
    disk matches the canonical form on every checkout.

2 new tests in `tests/unit/test_policy_engine.py`:
  * Synthetic rule pack written twice (LF and CRLF) produces the
    SAME `file_sha256` (no drift).
  * `file_sha256` equals
    `sha256(pack_path.read_bytes().replace(b"\r\n", b"\n"))` for
    `nist-core-2026.yaml` — hard-pins the normalization rule so
    anyone reproducing the audit by hand knows exactly which bytes
    to hash.

Total local tests: 465 / 3 skipped (was 463 / 3, +2 new).

This is the kind of bug only an adversarial verifier catches —
my own tests were all running on the same filesystem in the same
process, so CRLF/LF drift was invisible. Counterexample worker
output reproduced and the fix lands two-tier so the auditor never
has to think about line endings again.

### Fixed — CBOM `executionEnvironment` was not valid CycloneDX 1.6 (Sprint 9 step A)

Schema validation against the official upstream CycloneDX 1.6
schema (`tests/fixtures/schemas/cyclonedx-1.6.schema.json`) found
the reporter was emitting `"executionEnvironment": "software"`, but
the spec's `cryptoExecutionEnvironment` enum is::

    software-plain-ram | software-encrypted-ram | software-tee |
    hardware | other | unknown

Result: any CBOM emitted by 0.3.0-beta1 would have been REJECTED
at upload time by Dependency-Track, Anchore, Microsoft SBOM Tool,
and every other CycloneDX-aware consumer. A real auditor handing
the CBOM to a procurement reviewer would have hit a hard error.

Fix: emit `"unknown"` (the conservative, schema-valid default).
A later sprint can downgrade to `software-plain-ram` for software
discoveries and `hardware` when an HSM is detected, but those
classifications require runtime introspection that pqc-audit does
not yet perform — claiming a sharper value without the evidence
would be fuffa.

### Added — official-schema validation of CBOM + SARIF outputs (Sprint 9 step A)

Vendored the two upstream JSON Schemas under
`tests/fixtures/schemas/` (bit-identical mirrors of CycloneDX
1.6 and OASIS SARIF 2.1.0). Four new pytest cases:

  * CBOM output validates against `cyclonedx-1.6.schema.json`
    (Draft 7) — currently 0 errors after the fix above.
  * SARIF output validates against `sarif-2.1.0.schema.json`
    (Draft 4) — currently 0 errors.
  * CBOM declares `bomFormat: CycloneDX` + `specVersion: 1.6`.
  * SARIF declares `version: 2.1.0` + the canonical `$schema` URL.

These tests are the empirical proof that "CycloneDX 1.6" and
"SARIF 2.1.0" in the README are accurate, not marketing.
`jsonschema 4.26.0` is already a transitive dep (no new top-level
dependency added).

### Added — RFC 3161 Time-Stamp Protocol client (Sprint 8 step D)

New module `pqc_audit.signing.tsa_client` with two pure-stdlib
helpers:

  * `build_timestamp_request(digest, hash_algo="sha256",
    cert_req=True) -> bytes` — DER-encoded RFC 3161 §2.4.1
    TimeStampReq. Hand-rolled ASN.1 (no pyasn1 / asn1crypto
    dependency added) for SEQUENCE / INTEGER / OID / OCTET STRING
    / BOOLEAN / NULL. Supports sha256 / sha384 / sha512.
  * `request_timestamp_token(tsa_url, digest, ...) -> bytes` —
    POSTs the request to a TSA endpoint over HTTPS, returns the
    raw TimeStampResp body. Reuses the same security posture as
    the JWKS scanner: HTTPS-only (CWE-918 scheme), SSRF guard
    (refuses loopback / RFC1918 / link-local / multicast / AWS
    metadata), 256 KiB response cap (CWE-400), full certificate +
    hostname verification.

What this module does NOT do (kept honest):
  * It does NOT parse the TimeStampResp — the bundle is shipped
    as an opaque blob to the verifier, who uses
    `openssl ts -verify` or an equivalent library.
  * It does NOT promise qualified status. ETSI EN 319 421 +
    AgID accreditation are paperwork on top of this protocol;
    out of scope for this codebase.

**Interop verified empirically** with `openssl ts -query`:

```
$ openssl ts -query -in audit.tsq -text
Version: 1
Hash Algorithm: sha256
Message data:
    0000 - 9f 84 d2 e1 98 07 a5 89-bd 78 34 c4 04 eb 13 29
    0010 - 9d 60 30 79 38 80 17 10-02 49 c9 0a f8 90 98 e3
Policy OID: unspecified
Nonce: unspecified
Certificate required: yes
```

OpenSSL 3.5.5 (industry-standard reference implementation) parses
the 59-byte DER blob without errors, recognises version 1,
sha256, the embedded digest, and the certReq flag.

10 new tests in `tests/unit/test_tsa_client.py`:
  * DER starts with `0x30` (SEQUENCE),
  * digest appears verbatim in the DER,
  * cert_req flag changes the DER,
  * digest length validation (32 bytes for sha256),
  * unsupported hash algo rejected,
  * Content-Type header is `application/timestamp-query`,
  * non-https URL rejected,
  * SSRF private host rejected (127.0.0.1, 169.254.169.254),
  * non-2xx response raises,
  * oversize response capped at 256 KiB.

Total local tests: 459 / 3 skipped (was 449 / 3, +10 new).

### Added — deterministic clock + report id for legally reproducible audits (Sprint 8 step C)

Closes the end-to-end smoke finding from Sprint 8 step B: two
back-to-back runs of the same scan on the same fixture were
producing different SHA-256 fingerprints because `datetime.now(UTC)`
and `uuid.uuid4()` were sprinkled across `AuditReport.generated_at`,
`ScanResult.{started_at,finished_at}`, `CryptoAsset.discovered_at`,
`PolicyEvaluation.evaluated_at`, and `report_id`.

Two env vars now control determinism (defaults preserve the
old ad-hoc behaviour):

```
PQC_AUDIT_FROZEN_AT=2026-05-17T12:00:00Z   # ISO 8601 UTC instant
PQC_AUDIT_REPORT_ID=audit-<your-id>        # any non-empty string
```

New module `pqc_audit.core.clock` with two helpers:
  * `frozen_now() -> datetime` — returns the env-frozen instant if
    `PQC_AUDIT_FROZEN_AT` is set, else `datetime.now(UTC)`. Accepts
    naive ISO (interpreted as UTC) and the `Z` short suffix.
    Invalid value → warning + fall back to real now (auditor's run
    continues but determinism is documented as lost).
  * `report_id_override() -> str | None` — returns
    `PQC_AUDIT_REPORT_ID` when non-empty, else `None`.

Surgical replace of `datetime.now(UTC)` → `frozen_now()` across the
11 modules that contribute timestamps to the canonical JSON
(auditor + policy_engine + every scanner). `Auditor.scan` now
honors `report_id_override()` before falling back to its random
`audit-<hex>` default.

12 new tests in `tests/unit/test_clock.py` (frozen_now + override
contract, env-var name pinning, whitespace stripping, invalid-value
fallback, two consecutive calls return identical value when frozen).

Smoke E2E confirmation (this commit message):

```
PQC_AUDIT_FROZEN_AT=2026-05-17T12:00:00Z \
PQC_AUDIT_REPORT_ID=audit-determ-001 \
pqc-audit scan iac --path /fixture --compact > r.json
pqc-audit hash --input r.json
```

Run twice, the two digests are bit-identical
(`0f13eb92a17736dac1349ebe049a81a47bb14083ebab302598b3ec9cc597933b`).

Total local tests: 449 passed, 3 skipped (was 444, +5 net after
adding 7 frozen_now + 5 report_id_override = 12 minus the 7
already present after Sprint 8c-prep).

### Added — `pqc-audit hash` CLI subcommand (Sprint 8 step B)

New subcommand that closes the verification loop opened by step A.
Usage:

```
pqc-audit hash --input report.json     # file path
pqc-audit hash --input -                # stdin
```

Prints the SHA-256 of the canonical JSON form of the parsed report
(lowercase 64-hex). A regulator who receives `report.json` and the
auditor's published digest runs this command and compares — match
means the report has not been tampered with since publication.

Tests: 7 new CLI cases in `tests/unit/test_cli_hash.py` (stable
across runs, differs on payload change, missing file → non-zero
exit, invalid JSON → non-zero exit, stdin via `-`, subcommand
listed in top-level help).

**End-to-end smoke finding**: two back-to-back `scan iac` runs on
the same Terraform fixture produced *different* digests, because
`AuditReport.generated_at` and `CryptoAsset.discovered_at` are
populated with `datetime.now(UTC)` at scan time. For deterministic
legal audits the timestamps must be either frozen by an explicit
flag or excluded from the canonical form. Tracked as Sprint 8 step
C2 — does NOT block the signing chain (a TSA-stamped + sigstore-
signed report is still authoritative, even if two re-runs differ).

### Added — canonical JSON + report SHA-256 (Sprint 8 step A)

Foundation for the report-signing chain prescribed by the
`audit-evidence-emit-2026` rule pack. Without a byte-stable
serialization the downstream signers (RFC 3161 TSA, sigstore
keyless) cannot produce a hash a regulator can independently
recompute. This step builds *only* that foundation — signing
itself lands in step B (TSA) and step C (sigstore).

New module `pqc_audit.reporters.canonical`:
  * `canonical_json(payload) -> str` — JSON serialization with
    `sort_keys=True`, compact separators, `ensure_ascii=False`,
    `allow_nan=False`. Approximate JCS-style canonical form — NOT
    full RFC 8785 (the report does not use IEEE-754 floats in any
    normative field). Italian / French / German accented characters
    are emitted verbatim, not `\uXXXX`-escaped, so the canonical
    bytes match what a regulator visually reads.
  * `report_sha256(payload) -> str` — lowercase 64-hex SHA-256 of
    the canonical bytes. The published digest is the legal
    fingerprint of the report; a regulator parses the JSON, runs
    `canonical_json` on the parsed object, and hash-compares.

11 new tests pin the contract:
  * key reordering invariance,
  * byte stability across runs,
  * NaN / Infinity rejection,
  * non-ASCII preserved (no `\uXXXX` escapes),
  * end-to-end smoke against a real `AuditReport` via
    `json_reporter._to_jsonable`.

Total test count: 430 pass / 3 skip (was 419 / 3).

### Added — rule pack provenance for legal-value audits (Sprint 7)

The Sprint 6 integration made rule packs functionally enforceable.
Sprint 7 makes the resulting audit **legally auditable** by pinning
which exact pack drove every verdict.

New pydantic model `RulePackProvenance` (name, version, source,
url, retrieved, file_sha256). New field
`PolicyEvaluation.rule_pack_provenance: list[RulePackProvenance]`.
At evaluation time `_compile_pack_overlay()`:
  * calls `load_rule_pack(name)` to read the declared
    `version` + `provenance.{source,url,retrieved}`;
  * reads the YAML file via the new traversal-safe public helper
    `pqc_audit.rule_packs.rule_pack_file_path(name)` and computes
    SHA-256 of the bytes as shipped.

The combination (declared version + content hash) is the legal
fingerprint: a regulator or PA procurement reviewer can re-fetch
the file at the same commit and hash-compare. A silent edit
between audits = hash mismatch = audit not reproducible.

4 new tests pin the contract:
  * `test_policy_evaluation_exposes_rule_pack_provenance_when_packs_used`
    (presence + 64-hex SHA shape + NIST anchor URL).
  * `test_policy_evaluation_provenance_is_stable_across_runs`
    (two evaluations yield the same hash — no clock drift).
  * `test_policy_evaluation_provenance_empty_when_no_rule_packs`
    (legacy policies still work).
  * `test_policy_evaluation_provenance_distinct_packs_distinct_hashes`
    (two packs => two different SHAs).

Total policy_engine tests: 40 (was 36). Full local suite: 419 pass,
3 skip.

### Added — rule_packs ↔ policy_engine integration (Sprint 6)

Before this commit the six bundled rule packs (`nist-core-2026`,
`audit-evidence-emit-2026`, `eu-crypto-regulatory-2026`,
`it-recepimento-nis2-2026`, `agid-absc-2026`,
`fips-203-204-205-strict-2026`) were decorative: policies
couldn't consume them. Now any policy YAML can opt in via:

```yaml
rule_packs:
  - nist-core-2026
  - it-recepimento-nis2-2026
```

At evaluation time `_compile_pack_overlay()` calls
`compile_rule_packs([...])` and unions the resulting
`forbidden_algorithms` / `discouraged_algorithms` into the effective
policy (the caller's dict is never mutated). Unknown pack name →
loud `FileNotFoundError` (no silent over-permissive verdict).

New checker `_check_deprecate_after`: emits a HIGH severity
violation when an asset's `Algorithm.canonical_name` matches a
deprecate_after key whose effective date is `<=` today. Honors
optional `evaluation_date: "2031-01-01"` policy field for point-
in-time audits and deterministic tests.

Schema additions to `_KNOWN_POLICY_KEYS`: `rule_packs`,
`evaluation_date`. Tests: 5 new in `tests/unit/test_policy_engine.py`
(merge forbid set, union with explicit list, deprecate_after post-
date HIGH, deprecate_after pre-date no-op, invalid pack name
raises). Total policy_engine tests: 36 (was 31). Full local
suite: 415 passed, 3 skipped.

### Tested — JWKS defense-in-depth coverage (Sprint 5 #4 critic follow-up)

- `critic-orchestrator` adversarial review (job `dd90dffc32b766c2`,
  3 workers, $2.37, 216 s) returned `consensus=claim_holds, votes
  3-0-0`. The falsification worker flagged a "present-but-untested"
  gap: `_NoRedirectHandler` and the 1 MiB `_MAX_JWKS_BYTES` cap had
  no regression test. Closed the gap with seven new cases:
    * Parametrized `test_no_redirect_handler_raises_on_every_3xx`
      across status codes 301 / 302 / 303 / 307 / 308 — each must
      raise `urllib.error.HTTPError`.
    * `test_fetch_jwks_bytes_caps_oversize_response` mocks the
      urllib opener to return a fake response whose `read()` produces
      more than `_MAX_JWKS_BYTES` bytes, asserts `ValueError`.
    * `test_fetch_jwks_bytes_rejects_http_non_2xx` mocks a 404
      response, asserts `ValueError` mentioning the status code.
- Total JWKS scanner tests now 33 (was 26). Full local suite: 410
  passed, 3 skipped.

### Fixed — CI test suite green on ubuntu/macOS (Sprint 5 #1)

- 8 pytest cases were failing on the Linux/macOS CI runners while
  passing on Windows since Sprint 1. Two distinct root causes
  diagnosed and fixed:
    1. **Rich ANSI escapes fragment the flag name on Linux/macOS**.
       On a CI runner Rich auto-detects a writable stdout and emits
       `\x1b[1;36m--csv\x1b[0m` etc., so the `"--csv" in help_out`
       substring check misses. Fix: `CliRunner(env={"NO_COLOR": "1",
       "TERM": "dumb"})` for both the lock-in runner in
       `tests/unit/test_cli_signature_lock_in.py` and a new
       `help_runner` in `tests/unit/test_cli_batch.py`. Standard
       no-color.org env + dumb-terminal fallback.
    2. **Rich panel still truncates long flag names at 80 cols** even
       with `COLUMNS=200` because CliRunner has no TTY and Rich
       ignores the env. Fix: helper `_flag_present_in_help(out,
       flag)` that accepts both the full flag name and the
       Rich-truncated `--prefix…` / `--prefix...` form (only when the
       prefix covers ≥60% of the flag, to avoid silently approving
       a real rename).
- Reproduced locally with `FORCE_COLOR=1`: 7 fails before the fix,
  12 / 12 green after. Full unit suite: 375 passed, 3 skipped.

### Changed — dashboard enterprise polish (Sprint 4 #4)

- `dashboard/src/styles.css`: refined Big4-style palette with auditor
  navy/ivory/red, pill-shaped severity badges (no colored text so the
  meaning survives colour-deficient viewing and print), gradient
  sidebar, card hover micro-interactions, soft shadows, custom
  scrollbar, monospace stack for `code` and algorithm cells.
- `dashboard/src/App.tsx`: added a topbar with audit summary +
  worst-severity pill, replaced colored severity text with proper
  `<span class="badge severity-X">` pills in both tables, added a
  sidebar tagline and offline-by-design footer to make the read-only
  nature explicit for procurement reviewers.
- Deliberate choice: NO Tailwind / shadcn / Radix dependency added —
  the viewer ships as a Vite bundle ~5.6 kB CSS + 148 kB JS gzipped
  to 47 kB, well within the airgap-friendly deliverable size target.
- Vite build: clean (799 ms). TypeScript: strict mode green.

---

## Sprint 1-3 (global-grade transformation, tag v0.3.0-alpha1)

Sprint 1 of the global-grade transformation announced 2026-05-17.
The package is still alpha — these changes are not part of a tagged
release yet. Branch: `sprint-1-global-grade`.

### Added — composable rule packs

- New `pqc_audit.rule_packs` module distinct from the legacy
  end-to-end `policies/` profiles. Rule packs are versioned,
  regulation-anchored, parametric units composable on a per-engagement
  basis via `compile_rule_packs([...])`.
- `pqc_audit/rule_packs/nist-core-2026.yaml` — FIPS 203/204/205 +
  SP 800-227 allow list plus the NIST IR 8547 classical-deprecation
  timetable (RSA-2048 / ECDSA-P-256 deprecated 2030, disallowed 2035).
- `pqc_audit/rule_packs/audit-evidence-emit-2026.yaml` — mandates
  CycloneDX 1.6 CBOM, SARIF 2.1.0, SLSA v1.0 provenance, in-toto v1
  attestation and sigstore-bundle-v0.3 signed report as deliverables.
- Strict pydantic schema (`pqc_audit.rule_packs.schema`) rejects packs
  without provenance or with unknown artifact types — non-auditable
  evidence fails closed at load time.

### Added — new offline scanners

- `pqc_audit.scanners.jwt_scanner` — JWT / JOSE algorithm enumeration
  (RFC 8725 BCP). Flags `alg=none` (CWE-347) as CRITICAL, SHA-1 based
  JOSE algorithms as HIGH, and recognises the draft-ietf-jose-pqc
  ML-DSA / SLH-DSA algorithm ids as a target end state.
- `pqc_audit.scanners.dnssec_scanner` — parses DNSKEY records from
  zone files / `dig +dnssec` output, maps DNSSEC algorithm numbers
  against IANA + RFC 8624 implementation status, flags MUST NOT (1, 3,
  6, 12) as CRITICAL and NOT RECOMMENDED (5, 7) as HIGH.
- `pqc_audit.scanners.saml_scanner` — walks SAML XML for
  `ds:SignatureMethod`, `ds:DigestMethod`, `xenc:EncryptionMethod`.
  Flags SHA-1, 3DES and AES-CBC (padding-oracle exposure). Parses
  through `defusedxml` to refuse XXE / billion-laughs payloads
  (CWE-611, CWE-776).
- `pqc_audit.scanners.mtls_scanner` — audits PEM-bundled mutual-TLS
  client certificate chains for `digitalSignature` Key Usage,
  `clientAuth` Extended Key Usage, intermediate CA constraints, chain
  consistency (issuer/subject linkage) and per-cert expiry/strength
  via the shared TLS assessor.

### Added — supply chain

- `.github/workflows/publish-pypi.yml` — release pipeline emitting
  Sigstore keyless signatures, SLSA v1.0 provenance via
  `slsa-framework/slsa-github-generator` and publishing to PyPI via
  Trusted Publishing (OIDC, no long-lived API tokens). Verification
  instructions documented in `SECURITY.md`.

### Changed

- New runtime dependency: `defusedxml>=0.7,<1.0` (pinned upper bound
  in line with existing dependency policy). Required by the SAML
  scanner; kept as a hard dep because the SAML scanner is part of the
  core scanner set from Sprint 1.
- Wheel artifacts include `pqc_audit/rule_packs/*.yaml` alongside the
  legacy `pqc_audit/policies/*.yaml`.
- `pqc_audit.__version__` synced to `0.2.1` (drift vs `pyproject.toml`
  introduced during 0.2.1 release).

### Tests

- 47 new unit tests across `tests/unit/test_rule_packs.py`,
  `test_jwt_scanner.py`, `test_dnssec_scanner.py`,
  `test_saml_scanner.py`, `test_mtls_scanner.py`. Total suite: 347
  passed, 4 skipped (Windows-GTK + SHA-1 cert generation; preexisting).

## [0.2.1] - 2026-05-16

Security + correctness release driven by an external adversarial audit
(security architect + code reviewer + NIS2 gap analysis, run as parallel
subagents on 2026-05-16). 9 findings actioned. Adversarial review gate
(``critic-orchestrator``) returned ``claim_holds`` 2-0-0 on the full diff
before commit.

### Fixed

- **PDF reporter SSRF (CWE-918, HIGH)** — `pdf_reporter._html_to_pdf`
  now installs `_no_network_fetcher` as WeasyPrint's `url_fetcher`,
  rejecting every URL scheme except `data:`. A tainted
  `AuditReport.vulnerabilities[].description` containing Markdown
  image / link syntax can no longer turn the PDF render into an
  outbound HTTP fetch or local-file read (e.g.
  `![x](http://169.254.169.254/...)` or `file:///etc/passwd`).
- **CBOM vulnerability IDs non-deterministic (CWE-330, MEDIUM)** —
  `cbom_reporter` derived vuln IDs from built-in `hash()`, which is
  PEP-456 randomized per Python interpreter and produced a different
  CBOM id on every run. Replaced with
  `hashlib.sha256(title).hexdigest()[:8]` so consumers (Dependency-
  Track, Anchore) can de-duplicate findings across snapshots.
- **CBOM `metadata.tools` shape non-spec compliant (MAJOR)** — emitted
  the newer CycloneDX 1.6 `{components: [...]}` form with a non-
  standard `vendor` field on the embedded Component. Switched to the
  legacy Tool array `[{vendor, name, version}]`, which is accepted by
  every consumer in the wild (Dependency-Track 4.x/5.x, cyclonedx-cli,
  Anchore, GitHub SBOM ingest).
- **Markdown compliance section dead code (MAJOR)** — `--enforce`
  emits `policy_evaluation` at the top level of the JSON output, but
  `markdown_reporter` reads `report.metadata['policy_evaluation']`.
  Result: the `## Compliance` block silently disappeared whenever a
  user re-rendered an enforced JSON via `pqc-audit report -i scan.json
  -f markdown`. `cli._load_audit_report` now transposes top-level
  `policy_evaluation` into `metadata`, and `scan tls --enforce` writes
  to both locations. Regression test added.
- **Policy engine ignored 2 documented keys (MAJOR)** —
  `discouraged_algorithms` and `thresholds.{hndl_max_score,
  qday_max_score, min_agility_score}` were in `_KNOWN_POLICY_KEYS` and
  populated by every bundled YAML, but no checker evaluated them. Two
  new checkers (`_check_discouraged_algorithms` MEDIUM severity,
  `_check_thresholds` HIGH/MEDIUM) recompute risk scores on the fly
  via `core.risk` and emit per-asset violations. `pa_critical`,
  `agid_2026` and `nist_baseline` thresholds are now enforced
  end-to-end.
- **Path traversal on `--policy <name>` (CWE-22, LOW)** —
  `policies.load_policy` previously concatenated the user-supplied
  name into a filesystem path without validation. A hostile
  `../../etc/foo` would walk the YAML loader outside the bundled
  policies dir. Whitelist regex `^[A-Za-z0-9][A-Za-z0-9_-]*$` is now
  enforced before any filesystem access, and the resolved path is
  re-checked with `path.relative_to(_POLICY_DIR.resolve())` to close
  the symlink vector.
- **EdDSA migration hybrid was a KEM (correctness)** —
  `auditor._hybrid_for("EdDSA")` fell through to the default
  `next(HYBRID_SCHEMES)` and returned `X25519+ML-KEM-768`, a key-
  encapsulation hybrid. EdDSA is a signature primitive — fixed to
  `ECDSA-P256+ML-DSA-65` so the migration recommendation is
  semantically coherent.

### Changed

- **Runtime dependencies trimmed** — `httpx`, `structlog`, `rich` were
  declared in `[project.dependencies]` but never imported by
  `pqc_audit/`. Removed to shrink the supply-chain footprint (no more
  transitive `anyio`/`h11`/`httpcore`/`sniffio`/`idna`/`certifi`
  install on every `pip install pqc-audit-italia`). Upper bounds
  pinned for libraries with a history of breaking minor bumps:
  `pydantic<3.0`, `cryptography<46.0`, `typer<1.0`, `pyyaml<7.0`.
- `_KNOWN_POLICY_KEYS` extended with `required_pqc_algorithms` so the
  forward-compatibility warning stays quiet against the
  `pa_critical_2027` experimental policy.

### Documentation

- `docs/compliance/nis2-mapping.md` rewritten with:
  - Coverage matrix for NIS2 art. 21(2) levers a-j with explicit
    tool support per lever (FULL / PARTIAL / OUT-OF-SCOPE).
  - Scope assessment section (essential vs important under D.Lgs.
    138/2024 art. 3).
  - Dedicated sections for art. 21(2)(d) supply chain via CBOM and
    art. 21(2)(f) effectiveness assessment via ``batch-diff``.
  - Art. 23 reporting obligations with the ACN incident notification
    field mapping (``event_timestamp``, ``vulnerability.cwe``, ...).
  - Art. 24 D.Lgs. 138/2024 — misure tecniche di base — explicit
    matrix.
  - Art. 38 D.Lgs. sanctions table (10M€ / 2% turnover essential,
    7M€ / 1.4% important).
- `SECURITY.md` extended with a Threat Model section documenting
  intentional design choices (TLS `verify_mode = CERT_NONE`, PDF SSRF
  sandbox, CBOM deterministic IDs, policy name whitelist).

### Tests

- 28 new / updated tests covering every fix above. Falsification
  worker confirmed each fix has at least one regression test that
  fails on master pre-fix.
- `test_pdf_reporter` now uses a `_weasyprint_runtime_available()`
  helper that catches `OSError` alongside `ImportError`, so test
  suites on Windows hosts without GTK runtime skip cleanly instead of
  hard-failing.

### Quality gates

- ``pytest`` — **295 passed, 4 skipped** (3 weasyprint-runtime-only on
  Windows-without-GTK, 1 pre-existing SHA-1 cert generation on modern
  cryptography lib)
- ``ruff check .`` — 0 issues
- ``ruff format --check .`` — clean (modulo 3 unrelated pre-existing
  files: `bench_run.py`, `test_batch_json_schema_stable.py`,
  `test_cli_signature_lock_in.py`)
- ``mypy --strict pqc_audit/`` — 0 issues across 24 source files
- ``bandit -r pqc_audit -ll`` — 0 issues at any severity / confidence
- coverage on the package: **90 %** (was 92 % pre-0.2.1; minor
  reduction due to new untested error branches in
  `_no_network_fetcher`)

## [Unreleased — superseded] DX & supply-chain hardening — 2026-05-06

- **Makefile** con target `make test`, `make gates`, `make build`,
  `make publish-test`, `make publish`, `make clean`. Investor /
  contributor possono riprodurre la due-diligence in un comando.
- **`.pre-commit-config.yaml`**: hook locale (ruff, ruff-format,
  mypy strict, bandit, pytest unit) per ergonomia commit
  quotidiana. Install: `pip install pre-commit && pre-commit install`.
- **`examples/bench/`**: benchmark performance reproducibile (
  bench_run.py + pa_30hosts.csv + README + .gitignore). Sweet spot
  concurrency=8, 1.5× speedup vs sequential, plateau ~3.3 host/sec.
- **`examples/customer_scenarios.md`**: 3 use case eseguibili
  (PMI single-domain, PA multi-host con trend mensile, banca con
  GitHub Code Scanning + DORA gate).
- **`test_cli_signature_lock_in.py`**: 8 test parametrizzati che
  pinnano i nomi delle opzioni CLI per ogni subcomando. Una rinomina
  silenziosa (`--targets` → `--target`) fa fallire il commit.
- **`CITATION.cff`**: riferimento accademico/regolatorio (Citation
  File Format).
- **`.github/FUNDING.yml`**: placeholder per future sponsor button
  (commentato finché non c'è canale pubblico).
- **`.github/dependabot.yml`**: weekly auto-update Python + GitHub
  Actions con grouping per minor/patch.
- **`.editorconfig`**: coerenza cross-editor.

## [0.2.0] - 2026-05-06

### Added

- **Phase 6.5 — Reporter HTML self-contained** (2026-05-06): il
  subcomando `pqc-audit batch` emette ora `batch_report.html`
  oltre a `.md` e `.json`. Documento autonomo, CSS+JS inline,
  filtro per host + bottone "Scarica CSV".
- **Phase 6.6 — `pqc-audit batch-diff`** (2026-05-06): nuovo
  subcomando per confrontare due `batch_report.json` snapshot
  (caso d'uso "snapshot mensile"): improved / regressed /
  unchanged / added / removed con rendering Markdown italiano.
- **Edge-case detection** (2026-05-06): TLS scanner ora flagga
  certificati scaduti (`not_valid_after < now()`, severity HIGH,
  CWE-298) e certificati non-ancora-validi (`not_valid_before
  > now()`, severity MEDIUM). Bug pre-esistente trovato dal
  TDD strict — il scanner mancava interamente il check di
  validità.
- **Integration test suite** (2026-05-06): tre nuovi job in CI
  per blindare il path scanner ↔ socket ↔ TLS handshake reale:
  ECDSA-P256 cert detection, batch CLI end-to-end, edge-case
  scenari (expired, RSA-1024 offline, SHA-1 skip).

### Changed

- Pulizia lint completa: ruff zero errori, ruff format pulito,
  bandit zero issues. Lavoro di igiene CI.
- Sostituiti 3 `assert` come type-guard con `if x is None: raise`
  per sopravvivere a `python -O` (flag che strippa gli assert).

### Fixed

- TLS scanner ora rileva certificati scaduti (era un silent
  pass — il deliverable non avvertiva il CISO che il sito era
  servendo un cert scaduto).

### Security

- Test XSS esteso da 1 payload a 9 (parametrizzato): script
  inline, attribute escape, SVG namespace, `javascript:` URL,
  iframe srcdoc, polyglot, CR/LF injection, payload pre-encoded.

### CI

- `tests/integration` ora gira nella matrice CI (3 OS × 3
  Python). Era escluso, lasciando un blind spot sul path
  network/TLS reale.
- `lint.yml` workflow ora green sul ruff check + ruff format.

## [0.1.0] - 2026-05-04 — first preview

### Added

- **Phase 6 — `pqc-audit batch`** (2026-05-06): nuovo subcomando
  per scan multi-host in unica esecuzione.
  - Input mutex `--targets` inline (comma-separated `host[:port]`)
    oppure `--csv` (header opzionale, BOM UTF-8 di Excel ingerito
    via `utf-8-sig`).
  - Output aggregato `batch_report.md` (sintesi italiana) +
    `batch_report.json` (lista di report per-host completi).
  - `--enforce` propaga la valutazione policy a ogni host.
  - `--concurrency / -j N` (1..32) cap di scan paralleli via
    `asyncio.gather` + `asyncio.Semaphore`. Default 1 sequenziale
    backward-compatible.
  - `--fail-on-violations` exit code 3 se almeno un host ha verdict
    FAIL o errore — CI/CD gate, artefatti scritti comunque.
  - `examples/ci_cd/` — workflow drop-in per GitHub Actions e
    GitLab CI con pattern weekly cron + per-PR gate + artefact
    upload + PR comment.
  - Pure-helper layer in `pqc_audit.batch` (`Target`,
    `parse_csv`, `parse_inline_targets`, `run_one`, `summarize_one`,
    `render_markdown`, `run_batch`) testato senza il typer runner.
  - 20 unit test nuovi: parsing CSV/inline, BOM handling,
    summarising, rendering Markdown, CliRunner end-to-end con stub
    `run_one`, fail-on-violations nei due rami, concurrency
    in-flight cap.

- **Phase 0** — repository scaffold, `pyproject.toml` (hatch backend, py3.11+),
  AGPL-3.0 LICENSE, bilingual README (EN + IT), CONTRIBUTING with CLA,
  CODE_OF_CONDUCT (Contributor Covenant 2.1), SECURITY responsible disclosure
  policy, GitHub Actions workflows (test / lint / security with bandit +
  pip-audit), issue templates, package skeleton with `pqc_audit.cli`
  typer entrypoint, smoke tests.
- **Phase 1.a** — core pydantic v2 data models: `Algorithm`, `KeyMaterial`,
  `Vulnerability`, `MigrationRecommendation`, `CryptoAsset`, `ScanResult`,
  `AuditReport`, plus `RiskLevel` (IntEnum) and `ScanCategory` (StrEnum).
  Frozen models, mypy-strict clean, 12 unit tests.
- **Phase 1.b** — algorithm classification registry: `QUANTUM_VULNERABLE`,
  `QUANTUM_WEAKENED`, `QUANTUM_RESISTANT` buckets covering NIST FIPS 203
  (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA all variants), HQC backup, LMS / XMSS
  stateful, plus hybrid transition profiles. Helpers `classify_algorithm`,
  `is_deprecated`, `recommend_pqc_replacement`. 15 unit tests.
- **Phase 1.c** — risk scoring: `calculate_hndl_risk`, `calculate_qday_risk`,
  `calculate_agility_score`, `aggregate_risk`. Inspectable, defensible math
  with clamped `[0, 100]` scores. 14 unit tests.
- **Phase 1.d** — `BaseScanner` Protocol, `ScanTarget` model, and
  `TLSScanner` (pure parsing layer + async stdlib `ssl` handshake in a
  worker thread). Defensive identification only — no downgrade or fuzzing.
  8 unit tests.
- **Phase 1.f** — JSON reporter (`render(report, *, pretty=True) -> str`),
  recursive coercion of pydantic / datetime / Enum, top-level summary
  block. 9 unit tests.
- **Phase 1.g** — `Auditor` orchestrator + `enrich_report` pipeline:
  - `metadata['risk_summary']` from `aggregate_risk`
  - `metadata['per_asset_risk']` per-asset HNDL / Q-Day / agility
  - auto-generated `MigrationRecommendation`s, deduped per canonical name
  - hybrid intermediate guidance per algorithm family
  - 1-5 priority bucket from `(hndl, qday)` high-water mark
  - concurrent target scanning bounded by `max_concurrency` (default 16)
- **CLI** — `pqc-audit version`, `pqc-audit scan tls --host ... --port ...
  [--policy ...] [--pretty/--compact]`. Stubs (exit 2) for `scan certs`,
  `scan ssh`, `report`, `cbom`. 8 typer CliRunner tests.
- **Examples** — `scan_single_host.py`, `scan_infrastructure.py` (YAML
  driven), `generate_compliance_report.py` (Markdown summary with NIS2 /
  DORA / AgID mapping).
- **Bundled policies** — `nist_baseline.yaml`, `agid_2026.yaml`,
  `banking_italy.yaml`, `pa_critical.yaml` with YAML loader resolving
  `inherits` chains. 9 unit tests.
- **Documentation** — `docs/architecture.md` (layer overview + data flow),
  `docs/algorithms.md` (full NIST PQC variant tables), and three compliance
  mappings under `docs/compliance/`: `nis2-mapping.md`, `dora-mapping.md`,
  `agid-mapping.md`.
- **Integration test** — `tests/integration/test_tls_scanner_local_server.py`
  spins a stdlib SSL listener on `127.0.0.1`, presents a fresh self-signed
  RSA-2048 / SHA-256 certificate, and verifies the full enriched report
  pipeline end-to-end.
- **Phase 1.e** — local X.509 certificate file scanner and SSH KEXINIT
  scanner. `CertificateScanner` walks PEM / DER / CRT / CER trees with
  symlink-skip and an 8 MB-per-file safety cap (RFC 5280 certs are
  measured in kB; the cap protects against accidentally `.pem`-named
  multi-GB blobs). `SSHScanner` performs a defensive RFC 4253 §7.1
  KEXINIT parse with a 35 000-byte packet cap and bounded banner read.
  ~30 unit tests + 2 hardening regression tests.
- **Phase 4** — Markdown / SARIF 2.1.0 / CBOM (CycloneDX 1.6) /
  PDF (WeasyPrint) reporters. Markdown is Italian-language and
  executive-friendly; SARIF maps each `Vulnerability` to a `result`
  with rule metadata; CBOM emits `cryptographic-component` entries
  per asset. PDF is opt-in via `pip install pqc-audit-italia[pdf]`.
  ~28 unit tests.
- **Phase 5** — policy engine. `evaluate_against_policy(report,
  policy)` returns a `PolicyEvaluation` with per-rule status
  (`PASS`/`PARTIAL`/`FAIL`) and overall verdict. CLI flag
  `--enforce` embeds the evaluation in JSON output. 4 bundled
  policies cover NIST baseline, AgID 2026, banking Italy, and
  PA critical profiles, with YAML inheritance for trimming
  duplication. ~25 unit tests.
- **CLI completeness** — `scan certs`, `scan ssh`, and `report
  --format {json,markdown,sarif,cbom,pdf}` are now real (no longer
  stubs). All three `scan` subcommands accept `--data-sensitivity-years`
  to drive HNDL scoring per engagement profile.

### Quality gates

- `ruff check .` — clean
- `ruff format --check .` — clean
- `mypy --strict pqc_audit/` — 0 issues across 21 source files
- `bandit -r pqc_audit -ll` — 0 issues at any severity / confidence
- `pytest -q` — **189 passed, 2 skipped** (skipped require optional `weasyprint`), coverage **≥ 92%** on the package
- `hatch build -t wheel` — produces a clean wheel including the
  bundled YAML policies and `SOURCE.md` attribution

## [0.1.0] - TBD

Initial beta release placeholder.
