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

## [Unreleased] — Sprint 9j.2 (MySQL / MariaDB SSL probe via passive handshake read)

Sprint 9j.2 (2026-05-17) extends the database axis to MySQL /
MariaDB. The protocol mechanic is different from PostgreSQL: the
server speaks FIRST, sending an Initial Handshake Packet
(Protocol::HandshakeV10) that advertises its capabilities. The
``CLIENT_SSL`` bit (``0x0800``, bit 11) inside ``capability_flags_1``
indicates SSL support.

**The probe is purely passive** — no client request, no perturbation
of server state, no possibility of disrupting an active production
database. Just one TCP connect + one read.

### New module: `pqc_audit/scanners/mysql_ssl.py`

* `CLIENT_SSL_BIT = 0x0800` (constant, verified against MySQL docs).
* `parse_handshake_v10_capabilities(payload)` — pure parser, returns
  7-key dict (`ssl_status` / `error_message` / `protocol_version` /
  `server_version` / `capability_flags` (int 32-bit) /
  `capability_flags_hex` (lowercase) / `client_ssl_supported`).
  Rejects v9 packets (obsolete) and truncated payloads with
  `ssl_status="error"`.
* `probe_mysql_ssl(host, port=3306, timeout=5.0)` — socket connect,
  read 4-byte packet header (3-byte LE length + 1-byte seq),
  drain N-byte payload, delegate to the parser. Catches
  `ConnectionRefused` / `TimeoutError` / `gaierror` / `OSError`;
  bounds the payload length at 16 KB to reject framing-error reads.

Wire layout (verified against
https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html):

```
Packet header (4 bytes):
  3 bytes payload-length (LE) + 1 byte sequence-id
Payload (HandshakeV10):
  1 byte    protocol_version (always 0x0a)
  var       server_version (NUL-terminated)
  4 bytes   thread_id
  8 bytes   auth-plugin-data-part-1
  1 byte    filler (0x00)
  2 bytes   capability_flags_1 (low 16 bits, LE)  ← CLIENT_SSL HERE
  1 byte    character_set
  2 bytes   status_flags
  2 bytes   capability_flags_2 (high 16 bits, LE)
```

### CLI wiring

```
pqc-audit scan mysql-ssl --host db.example.com --port 3306 --timeout 5.0
```

Output JSON: `host`, `port`, `probe = "mysql-handshake-v10-capability-flags"`,
`reference` (dev.mysql.com docs URL), `result` (the 7-key parser dict
+ host + port).

### Test coverage — real tests, not just monkeypatch

* **11 unit tests**:
  * 1 `CLIENT_SSL_BIT == 0x0800 == 2048` constant verification;
  * 7 `parse_handshake_v10_capabilities` cases (extracts
    `protocol_version` + `server_version`, SSL bit set/clear,
    capability_flags reported as int and hex, rejects v9,
    rejects truncated, rejects non-NUL-terminated server_version);
  * 3 `probe_mysql_ssl` schema + error handling (refused, timeout,
    gaierror).
* **3 integration tests** with in-process mock TCP server (REAL
  socket I/O, REAL handshake bytes, no monkeypatch):
  * MySQL 8.0.36 with SSL → `ssl_status="supported"`;
  * MySQL 5.7.42 with CLIENT_SSL bit explicitly cleared →
    `ssl_status="not_supported"`;
  * MariaDB 10.11.6 → CLI subcommand via CliRunner → valid JSON.

Full suite: 622 passed, 4 skipped (preexisting).
Ruff clean.

### Audit value

A MySQL/MariaDB server without `CLIENT_SSL` violates **NIS2 art.
21(2)(h) / D.Lgs. 138/2024 art. 24(2)(h)** (encryption in transit
for confidential data). This sprint emits the probe result; Sprint
9j.3 will wire it into the `Auditor.scan` pipeline as a HIGH
`Vulnerability(CWE-319, Cleartext Transmission)` so it propagates
to the markdown report and NIS2 mapping automatically.

### Critic gate

`critic-orchestrator` 3-worker adversarial review (204s, $2.36):

| Worker | Verdict | Confidence | Note |
|---|---|---|---|
| falsification | claim_holds | 0.97 | Stash module + CLI mod + test file (untracked), restored only test → `ImportError`. Restored everything → 14/14 pass in 2.75s, 88% coverage on `mysql_ssl.py`. |
| caller_verification | claim_holds | 0.97 | `probe_mysql_ssl` invoked at `cli.py:244` inside `scan_mysql_ssl_cmd` decorated by `@scan_app.command("mysql-ssl")` at `cli.py:224`. Mount at `cli.py:60` + `pyproject.toml:111` console script `pqc-audit`. Real user reach: `pqc-audit scan mysql-ssl --host ... --port 3306`. |
| counterexample | claim_holds | 0.88 | 8 invariants verified: CLIENT_SSL bit position, offset math post-server_version-NUL, capability_flags 32-bit LE concatenation, all error paths return `ssl_status="error"` without raise, `_read_n_bytes` handles TCP fragmentation, mock-server hermetic. Disclosed nitpick: `_error()` payload omits `protocol_version` key (schema asymmetry on network-error path) — not a counterexample because the claim does not promise uniform schema across all error paths. |

**Consensus: hold 3-0-0.**

---

## [Unreleased] — Sprint 9j (PostgreSQL SSL probe via wire protocol)

Sprint 9j (2026-05-17) opens the **database** axis of the audit
toolkit, which until now covered only network TLS / certs / SSH /
JWT / SAML / DNSSEC / mTLS / IaC / JWKS. The first database is
PostgreSQL because it is the most common open-source choice for
Italian PA backends.

### Why a dedicated probe is necessary

PostgreSQL servers do NOT speak TLS on connect — they speak the
PostgreSQL wire protocol. A client that wants encryption must first
send a 8-byte ``SSLRequest`` message:

```
00 00 00 08   ← Int32 BE length = 8
04 d2 16 2f   ← Int32 BE magic = 80877103 (= 1234 MSW + 5679 LSW)
```

The server responds with **exactly one byte**:

* ``'S'`` (0x53) — SSL supported, upgrade the socket to TLS;
* ``'N'`` (0x4E) — SSL not supported, server expects plaintext only.

A naive ``ssl.create_default_context().wrap_socket()`` against
``host:5432`` would fail because the server is not yet in TLS state
— the standard TLS probe would record an "error", losing the
distinction between *server refused TLS* and *server up but no SSL*.
This module implements the correct two-step probe.

Source: PostgreSQL docs, Message Formats → SSLRequest
(https://www.postgresql.org/docs/current/protocol-message-formats.html).

### New module: `pqc_audit/scanners/postgres_ssl.py`

```python
from pqc_audit.scanners.postgres_ssl import (
    SSL_REQUEST_BYTES,        # b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    parse_ssl_response_byte,  # bytes -> "supported"/"not_supported"/"error"
    probe_postgres_ssl,       # host, port -> 5-key dict
)

result = probe_postgres_ssl("db.example.com", 5432, timeout=5.0)
# {"host": ..., "port": 5432,
#  "ssl_status": "supported" | "not_supported" | "error",
#  "error_message": Optional[str],
#  "raw_response_hex": "53" | "4e" | ""}
```

`probe_postgres_ssl` catches `ConnectionRefusedError`, `TimeoutError`,
`socket.gaierror`, and generic `OSError`, surfacing them via
`ssl_status="error"` + `error_message` — the function never raises.

### CLI wiring (production caller, closes the dead-code gap)

```
pqc-audit scan postgres-ssl --host db.example.com --port 5432 --timeout 5.0
```

Emits a JSON payload with stable top-level keys `host`, `port`,
`probe` = `"postgres-sslrequest"`, `reference` (Postgres docs URL),
and `result` (the 5-key dict).

### Audit value

A `not_supported` result on a production database carries weight:
**NIS2 art. 21(2)(h) / D.Lgs. 138/2024 art. 24(2)(h)** require
encryption in transit for confidential data. Future sprints will
elevate this to a HIGH `Vulnerability` finding when integrated into
the `Auditor.scan` pipeline.

### Test coverage — REAL tests, not just monkeypatch

Per the directive "test reali non solo empirici":

* **12 unit tests** (monkeypatch-based, fast):
  * 2x wire-format constants (`SSL_REQUEST_BYTES` exact bytes +
    magic 80877103 decoding);
  * 5x `parse_ssl_response_byte` cases (`'S'`, `'N'`, empty,
    unknown byte, extra bytes ignored);
  * 4x probe error handling (refused, timeout, gaierror, schema).
* **3 integration tests** with an **in-process mock TCP server**
  (real socket I/O, real 8-byte wire send, real `recv`, NO
  monkeypatch — hermetic, no Postgres install required):
  * `'S'` response → `ssl_status == "supported"`,
    `raw_response_hex == "53"`;
  * `'N'` response → `ssl_status == "not_supported"`,
    `raw_response_hex == "4e"`;
  * connection refused on unbound port → `ssl_status == "error"`.

* **1 CLI integration test** drives `typer.testing.CliRunner` against
  the mock TCP server and validates the JSON payload schema.

Full suite: 608 passed, 4 skipped (preexisting).
Ruff: clean.

### Empirical E2E live

```
python -m pqc_audit scan postgres-ssl --host 127.0.0.1 --port 5432 --timeout 2.0
```

Output (no Postgres running on localhost — expected behavior):

```json
{
  "host": "127.0.0.1",
  "port": 5432,
  "probe": "postgres-sslrequest",
  "reference": "https://www.postgresql.org/docs/current/protocol-message-formats.html",
  "result": {
    "host": "127.0.0.1",
    "port": 5432,
    "ssl_status": "error",
    "error_message": "timed out",
    "raw_response_hex": ""
  }
}
```

The pipeline (CLI → probe → socket I/O → JSON) is verified end-to-end
on the real subprocess. The mock-server integration tests verify the
same pipeline against a server that actually answers with the wire
bytes — a strict superset of the empirical CLI verification.

### Honest gap list

- **No MySQL / MariaDB / Oracle / MSSQL probes yet** — each speaks
  its own pre-TLS wire dance. Sprint 9j.2 et seq. will add them.
- **No `Vulnerability` emission** — the probe returns a raw dict.
  Wiring into `Auditor.scan` to produce a HIGH CWE-319
  (cleartext transmission) finding when `ssl_status="not_supported"`
  is a separate sprint.
- **Probe does NOT actually negotiate TLS** after receiving `'S'` —
  it only verifies the server is *willing* to upgrade. Reusing the
  existing `TLSScanner` chain extraction code post-upgrade is a
  future sprint.

### Critic gate

`critic-orchestrator` 3-worker adversarial review (211s, $1.96):

| Worker | Verdict | Confidence | Note |
|---|---|---|---|
| falsification | claim_holds | 0.97 | Stash production module → 15 test fail con `ImportError: cannot import name 'postgres_ssl' from 'pqc_audit.scanners'`. Restore → 15/15 pass in 5.14s, 94% coverage sul nuovo modulo. |
| caller_verification | claim_holds | 0.97 | `probe_postgres_ssl` invocata a `cli.py:212` dentro `scan_postgres_ssl_cmd` (decorator `@scan_app.command("postgres-ssl")` a `cli.py:192`, mount `app.add_typer(scan_app, name="scan")` a `cli.py:60`). User entry point: `pqc-audit scan postgres-ssl --host <H> --port <P>`. |
| counterexample | claim_holds | 0.88 | 10 invarianti verificati: wire format magic 80877103, `parse_ssl_response_byte` boundary (empty/single/unknown/extra), error handling completo OSError-subclass (BrokenPipeError, ConnectionResetError, InterruptedError tutti catched), `contextlib.suppress(OSError)` no socket leak, CliRunner sub-app dispatch corretto, mock-server hermetic (bind+listen prima di thread.start), `raw_response_hex` lowercase coerente. **PostgreSQL `ErrorResponse` ('E' 0x45) → classificato `error` correttamente.** No counterexample. |

**Consensus: hold 3-0-0.**

---

## [Unreleased] — Sprint 9f.2 (ML-DSA signature_algorithms TLS 1.3 probe)

Sprint 9f.2 (2026-05-17) is the signature-side companion to Sprint 9f
(PQC hybrid KEM handshake probe). 9f answers *"is the server PQC
key-exchange ready?"*; 9f.2 answers *"is the server PQC
signature ready?"*.

### Scope — ML-DSA only

Three NIST FIPS 204 codepoints from **draft-ietf-tls-mldsa-03** (IETF
TLS WG, Informational, expires 2026-11-07,
https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa):

| Name | Codepoint | Reference |
|---|---|---|
| `MLDSA44` | 0x0904 | draft-ietf-tls-mldsa-03 |
| `MLDSA65` | 0x0905 | draft-ietf-tls-mldsa-03 |
| `MLDSA87` | 0x0906 | draft-ietf-tls-mldsa-03 |

**SLH-DSA is intentionally excluded.** As of 2026-05-17 no TLS 1.3
SignatureScheme codepoint is registered for SLH-DSA — RFC 9909
defines only the X.509 OIDs, RFC 9814 covers only CMS. Probing
SLH-DSA in TLS 1.3 would require inventing codepoints, which the
project's anti-fuffa stance bans. The honest gap is documented; a
future sprint can add SLH-DSA once a TLS draft is published with
official codepoints.

### Method

OpenSSL 3.5.5 (the audit machine's `openssl`) supports MLDSA-{44,65,87}
natively as sigalg names. The probe drives:

```
openssl s_client -sigalgs <MLDSA*> -connect host:443 -servername host -tls1_3
```

The empirical signal validated on agid.gov.it, cloudflare.com, and
google.com on 2026-05-17:

* `Negotiated TLS1.3 group: <NULL>` AND no Certificate chain block →
  server refused the MLDSA-only sigalg restriction → `not_supported`;
* non-NULL group AND Certificate chain block present → server returned
  a cert compatible with the MLDSA-only restriction → `supported`;
* DNS error / connect refused / OpenSSL not installed → `error`,
  surfaced separately so the reporter does not conflate
  network-layer issues with "PQC not supported".

### Public API

```python
from pqc_audit.scanners.tls_pqc_sig import (
    MLDSA_CODEPOINTS,
    MLDSA_SIGALGS,
    parse_negotiated_signature_status,
    probe_mldsa_sigalg,
    probe_all_mldsa_sigalgs,
)

results = probe_all_mldsa_sigalgs("agid.gov.it", 443)
# {"MLDSA44": {"sigalg": "MLDSA44", "codepoint": 0x0904,
#              "status": "not_supported", "host": ..., "port": 443}, ...}
```

### Test coverage

13 tests in `tests/unit/test_scanners_tls_pqc_sig.py`:

* 2x codepoint constants (`MLDSA_SIGALGS` ordering,
  `MLDSA_CODEPOINTS` matches draft);
* 6x `parse_negotiated_signature_status` (supported, NULL-group
  not_supported, handshake_failure alert not_supported, DNS error,
  connect refused, empty inputs → error);
* 3x `probe_mldsa_sigalg` (5-key dict contract, TimeoutExpired
  handled, FileNotFoundError handled when openssl is missing);
* 2x `probe_all_mldsa_sigalgs` (aggregator schema, mixed-status
  propagation).

Full suite: 590 passed, 4 skipped (preexisting).
Ruff: clean (3 noqa justified — `S105` for the OpenSSL marker
`<NULL>` which is not a credential, `PLR0911` for the 7-branch
status classifier, `S603` for `subprocess.run` with a fixed argv).

### Empirical E2E

```python
for host in ["agid.gov.it", "cloudflare.com", "google.com"]:
    for sigalg, result in probe_all_mldsa_sigalgs(host, 443).items():
        print(f"  {sigalg}: {result['status']}")
```

Output:

```
=== agid.gov.it ===
  MLDSA44 (0x0904): not_supported
  MLDSA65 (0x0905): not_supported
  MLDSA87 (0x0906): not_supported
=== cloudflare.com ===
  MLDSA44 (0x0904): not_supported
  MLDSA65 (0x0905): not_supported
  MLDSA87 (0x0906): not_supported
=== google.com ===
  MLDSA44 (0x0904): not_supported
  MLDSA65 (0x0905): not_supported
  MLDSA87 (0x0906): not_supported
```

Honest baseline: **no public server has a ML-DSA-signed certificate
in production as of 2026-05-17**. This is the expected result — the
probe's job is to register that fact reliably, not to invent
positives.

### Honest gap list

- **SLH-DSA TLS 1.3 codepoints absent** — add once a TLS draft
  publishes them.
- **No scanner-class integration** — the module exposes pure
  functions only. A future sprint can wire `PQCSignatureScanner` as
  an `is_applicable + scan` class analogous to `PQCHybridScanner`,
  and add `pqc-audit scan pqc-mldsa-sig` CLI subcommand.
- **No markdown_reporter section yet** — when probe results are
  embedded in an `AuditReport`, the reporter should emit a
  "## PQC signature readiness" block analogous to 9d.4's trust
  anchor section.
- **Sequential probing** of three sigalgs adds ~3× the OpenSSL
  subprocess overhead per host. Acceptable for MVP (~3-5s/host
  total), parallelizable later.
- **OpenSSL ≥ 3.5.0 required** — older OpenSSL releases do not
  know MLDSA sigalg names. The probe returns `status=error`
  (FileNotFoundError or empty output) on those, which the caller
  must surface distinctly from `not_supported`.

### Critic gate

The v1 review (3-worker, 208s) was **2-1-0** — falsification ✅,
counterexample ✅, but **caller_verification FAILED** (0.95): the
module was technically dead-code, reachable only by tests. Aurelio's
A3 stop-check protocol declined a "tests are green, ship it"
shortcut.

Fix applied **before** commit: added `@scan_app.command("pqc-mldsa-sig")`
subcommand in `pqc_audit/cli.py` that lazily imports
`probe_all_mldsa_sigalgs` and emits a stable-schema JSON payload, plus
a 14th unit test (`test_cli_scan_pqc_mldsa_sig_subcommand_wires_probe`)
that drives the subcommand via `typer.testing.CliRunner` and verifies
the JSON contract.

The v2 review (3-worker, 420s, $1.80) is **claim_holds 2-0-1**:

| Worker | Verdict | Confidence | Note |
|---|---|---|---|
| falsification | claim_holds | 0.97 | Double-pass stash. Pass 1: scanner module + CLI both removed → `ImportError`. Pass 2 (isolated CLI rigor): only `cli.py` reverted → CliRunner gets `exit_code == 2` (typer SystemExit for unknown subcommand). With fix fully restored → 1 passed in 2.38s. **Both production artifacts are load-bearing**; neither is decorative. |
| caller_verification | claim_holds | 0.97 | Path: `pqc_audit/cli.py:155` decorator `@scan_app.command("pqc-mldsa-sig")` → `cli.py:60` `app.add_typer(scan_app, name="scan")` → `pyproject.toml:111` console_scripts entry `pqc-audit = "pqc_audit.cli:app"`. Reachable via `pqc-audit scan pqc-mldsa-sig --host X --port Y` and `python -m pqc_audit scan pqc-mldsa-sig ...`. Non-test caller confirmed. |
| counterexample | **INVALID** | — | Timeout 420s (worker did not complete). $0 cost. No verdict either way — declined to factor into consensus. |

**Consensus: hold 2-0-1.** The invalid counterexample is a limitation
of the review, not an endorsement. Disclosed verbatim, not glossed.

### Real-network integration tests

Per Aurelio's directive "test reali non solo empirici", added
`tests/integration/test_tls_pqc_sig_real_endpoints.py` (2 tests,
marked `pytest.mark.integration`, skip-by-default):

* `test_probe_real_endpoint_returns_stable_schema` — drives
  `probe_all_mldsa_sigalgs("google.com", 443)` with a real OpenSSL
  subprocess and verifies the 5-key dict contract.
* `test_cli_real_endpoint_emits_valid_json` — invokes the actual
  subcommand against google.com via `CliRunner` and verifies the
  JSON schema.

Both **PASSED** in 9.05s wall-clock against the live target on
2026-05-17. The tests assert only schema and classification range
(`status in {supported, not_supported, error}`) — not a specific
verdict — so they remain stable when Google rolls out MLDSA.

Run on demand: `pytest -m integration tests/integration/test_tls_pqc_sig_real_endpoints.py`.

---

## [Unreleased] — Sprint 9d.4 (trust anchor section in executive Markdown)

Sprint 9d.4 (2026-05-17) ships the user-facing payoff of Sprint 9d.3:
the resolved trust anchor + CA pedigree are now displayed inline in
every `pqc-audit report --format markdown` invocation. A DPO/CISO
can see at a glance whether the audited target's root is an
AgID-accredited qualified TSP or a commercial global CA, **without
parsing the JSON metadata**.

### New section: `## Trust anchor — CA radice`

Inserted between `## Asset analizzati` and `## Vulnerabilità` (i.e.
adjacent to the asset table, where the trust anchor logically
belongs as the load-bearing endpoint of each chain).

Layout: one row per leaf-position asset that carries the
`trust_anchor` metadata key. Columns:

| Target | Stato | Fonte | Root subject | Pedigree | Algoritmo | Key size | Hash | Trust store source |

Italian-language labels:

* **Pedigree** (`qualified_it_tsp` → `AgID-accreditata (TSP
  qualificato italiano)`, `commercial_global` → `CA commerciale
  globale`, `unknown` → `Sconosciuta — richiede verifica manuale`).
* **Fonte** (`on_wire` → `presente sulla wire (server-shipped
  root)`, `trust_store` → `risolta dal trust store locale`,
  `unknown` → `non risolto`).
* **Trust store source** is displayed verbatim (e.g. `certifi`,
  `system_ca_bundle`) — we never relabel `certifi` as "the Windows
  trust store" because it isn't.

### Anti-fuffa contracts

- **Skip on empty.** Section omitted when no leaf asset carries the
  `trust_anchor` metadata key. Silence honest.
- **Unresolved surfaced, not dropped.** When `resolved=False`, the
  row is rendered with `Stato = non risolto` and `Fonte = non
  risolto`, so the reader sees the gap.
- **Pedigree disclaimer.** Section ends with a footnote stating that
  `Sconosciuta` requires manual verification and that the pattern
  list is a hand-curated subset, not a full AgID TSL catalogue.

### Test coverage

11 new tests in `tests/unit/test_markdown_reporter_trust_anchor.py`:

| Test | Verifies |
|---|---|
| `test_trust_anchor_section_present_when_leaf_has_trust_anchor` | section appears with the heading and "CA radice" subtitle |
| `test_trust_anchor_section_absent_when_no_leaf_carries_metadata` | section omitted gracefully |
| `test_pedigree_qualified_it_tsp_uses_italian_label` | `AgID-accreditata` + `TSP qualificato italiano` |
| `test_pedigree_commercial_global_uses_italian_label` | `CA commerciale globale` |
| `test_pedigree_unknown_uses_italian_label` | `Sconosciuta` + `verifica manuale` |
| `test_unresolved_trust_anchor_surfaced_as_non_risolto` | `non risolto` displayed |
| `test_trust_store_source_certifi_disclosed_honestly` | `certifi` label visible verbatim |
| `test_trust_store_source_system_ca_bundle_disclosed` | `system_ca_bundle` label visible |
| `test_root_subject_visible_in_section` | Actalis subject string present |
| `test_root_algorithm_and_key_size_visible` | RSA + 4096 in output |
| `test_multiple_leaves_each_have_a_row` | one row per leaf, multi-target |

Full suite: 577 passed, 4 skipped (preexisting).
Ruff: clean.

### Empirical E2E on aruba.it

```
python -m pqc_audit scan tls --host aruba.it --port 443 > aruba.json
python -m pqc_audit report -i aruba.json -f markdown
```

Output (excerpt):

```markdown
## Trust anchor — CA radice

| Target | Stato | Fonte | Root subject | Pedigree | Algoritmo | Key size | Hash | Trust store source |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tls://aruba.it:443` | risolto | risolta dal trust store locale | `CN=Actalis Authentication Root CA,O=Actalis S.p.A./03358520967,L=Milan,C=IT` | AgID-accreditata (TSP qualificato italiano) | RSA | 4096 | SHA256 | `certifi` |
```

This is the first audit Markdown that **autonomously** identifies a
production target as backed by an AgID-accredited Italian qualified
TSP, end-to-end from network handshake through trust-store lookup
through Italian-language report rendering.

### Critic gate

`critic-orchestrator` 3-worker adversarial review (144s, $1.67):

| Worker | Verdict | Confidence | Note |
|---|---|---|---|
| falsification | claim_holds | 0.98 | Stash markdown_reporter.py + CHANGELOG.md, test untracked. Pre-fix: **10/11 FAIL** (markdown rendered manca completamente della sezione `## Trust anchor`); 1/11 banale-pass è il test `absent` che passa per assenza. Post-fix: **11/11 PASSED** in 2.33s. Genuine RED→GREEN. |
| caller_verification | claim_holds | 0.95 | `_render_trust_anchor` definito a `markdown_reporter.py:213`, chiamato unconditional a `markdown_reporter.py:351` dentro `render()`. `render` importato come `render_markdown` in `cli.py:42`, invocato a `cli.py:459` sul branch `fmt == "markdown"`. Reachable via `pqc-audit report -f markdown` e indirettamente via `-f pdf` (pdf_reporter wraps markdown). |
| counterexample | claim_holds | 0.85 | 5 contratti verificati: section heading, 9-colonne congruenti header/row, 3 label IT pedigree, skip-graceful `if not leaves`, unresolved surfacing `non risolto`. Edge cases con fallback difensivi (metadata `or {}`, root_subject `or "—"`, pedigree `_PEDIGREE_IT_LABEL.get(k, k)`). Pedantic nit: `source=unknown` + `resolved=True` produce display incoerente "risolto/non risolto", non bug perché claim non contrattualizza coerenza source↔resolved. No counterexample concreto. |

**Consensus: hold 3-0-0.**

---

## [Unreleased] — Sprint 9d.3 (root trust-anchor resolution + CA pedigree)

Sprint 9d.3 (2026-05-17) answers the question every Italian PA audit
actually cares about: **who is the trust anchor, and is it an
AgID-accredited qualified TSP?** A TLS scan that names only the leaf
and intermediates the server shipped is missing the load-bearing
endpoint of the chain — and the legal effect (eIDAS art. 25) of every
signature the CA underwrites hangs on it.

### New module: `pqc_audit/scanners/tls_trust_store.py`

Cross-platform resolver with a documented fallback chain for the
trust store source:

1. explicit `override` (caller-supplied PEM path);
2. Linux/macOS system bundle via `ssl.get_default_verify_paths()`;
3. Mozilla CA bundle via `certifi.where()` (Windows fallback);
4. `("none", None)` — caller must surface unavailability honestly.

We never call certifi "the Windows trust store" because it isn't.
The returned label distinguishes `system_ca_bundle` from `certifi`,
and the reporter is meant to disclose the source verbatim.

### Canonical Name matching

Real-world cross-signed chains (e.g. GTS Root R4 → GlobalSign Root
CA) often encode the parent Name with a different RDN ordering, case,
or whitespace than the bundle's stored copy. A literal
`rfc4514_string()` match silently fails on those. The new
`_name_to_key(name)` produces a stable canonical key:

```
sorted(f"{oid.dotted_string}={value.strip().lower()}" for attr in rdns)
```

Result: order-independent, case-insensitive, whitespace-trimmed.
Verified against the GTS R4 / GlobalSign cross-sign case in
`tests/unit/test_scanners_tls_trust_store.py::test_resolve_root_matches_across_rdn_order_and_case_and_whitespace`.

### Pedigree classifier

`classify_ca_pedigree(subject_dn)` returns one of:

* `qualified_it_tsp` — AgID-accredited Italian qualified TSP
  (substring patterns: aruba, infocert, namirial, poste, actalis,
  trust italia, incertum, agid, buffetti). Pattern lists validated
  against AgID TSL (https://eidas.agid.gov.it/TL/TSL-IT.xml) as of
  2026-05-17. **NOT a complete catalogue** — a CA matching no IT
  pattern is `unknown`, never silently bucketed as commercial.
* `commercial_global` — well-known global commercial CAs (18
  patterns: ISRG, Let's Encrypt, DigiCert, GlobalSign, Sectigo,
  Comodo, GoDaddy, GeoTrust, Thawte, VeriSign, Entrust, IdenTrust,
  Amazon, Google Trust Services, Microsoft, Buypass, Starfield,
  QuoVadis).
* `unknown` — neither. The audit-trail cost of mislabeling a
  qualified TSP is too high to default to commercial.

### Public API

```python
def resolve_root_from_chain(
    chain: list[x509.Certificate],
    trust_store: dict[str, x509.Certificate],
) -> dict
```

Returns a 7-key dict:

| key | type | meaning |
|---|---|---|
| `resolved` | bool | `True` iff root was found on-wire or in trust store |
| `source` | str | `"on_wire"` / `"trust_store"` / `"unknown"` |
| `root_subject` | str \| None | RFC 4514 string of the resolved root subject |
| `root_signature_hash` | str \| None | e.g. `"SHA256"` |
| `root_key_size` | int \| None | 4096 for ISRG, 2048 for older roots |
| `root_algorithm` | str \| None | `"RSA"` / `"ECDSA"` / `"Ed25519"` / `"Ed448"` / `"DSA"` |
| `pedigree` | str | `"qualified_it_tsp"` / `"commercial_global"` / `"unknown"` |

### TLSScanner integration

The leaf `CryptoAsset.metadata` now carries two additional stable
keys:

* `trust_anchor` — the full 7-key dict from `resolve_root_from_chain`;
* `trust_store_source` — the label from `discover_trust_store_source`.

The resolution runs once per scan, after `verify_chain_signatures`.
No additional handshake; the trust store is read locally.

### Test coverage

22 unit tests in `tests/unit/test_scanners_tls_trust_store.py`,
including:

* `test_discover_returns_tuple_of_source_and_path`
* `test_discover_picks_explicit_override_first`
* `test_load_indexes_certs_by_subject_dn`
* `test_load_handles_garbage_in_bundle` (interleaved comments + bogus
  bytes between PEM blocks)
* `test_load_returns_empty_on_missing_file`
* 5x `test_classify_pedigree_qualified_it_tsp` (parametrized over
  Aruba, InfoCert, Namirial, PosteCert, Actalis subjects)
* 5x `test_classify_pedigree_commercial_global` (ISRG, DigiCert,
  GlobalSign, Sectigo, Let's Encrypt)
* `test_classify_pedigree_unknown`
* `test_resolve_root_finds_in_trust_store` (qualified_it_tsp flow)
* `test_resolve_root_when_last_cert_is_self_signed_uses_on_wire`
* `test_resolve_root_not_found_in_trust_store_returns_unresolved`
* `test_resolve_root_on_empty_chain_returns_unresolved`
* `test_resolve_root_matches_across_rdn_order_and_case_and_whitespace`
  (cross-sign canonical match)
* `test_resolve_root_metadata_contains_required_keys` (schema
  contract for callers)

Full suite: 566 passed, 4 skipped (preexisting).
Ruff: clean.

### Empirical E2E on 6 endpoints

| Host | source | resolved | root | pedigree |
|---|---|---|---|---|
| agid.gov.it | certifi | ✅ | ISRG Root X1 | commercial_global |
| **aruba.it** | certifi | ✅ | Actalis Authentication Root CA | **qualified_it_tsp** |
| digicert.com | certifi | ✅ | DigiCert Global Root G2 | commercial_global |
| namirial.com | certifi | ✅ | Starfield Services Root CA G2 | commercial_global |
| cloudflare.com | certifi | ❌ | — | unknown |
| inps.it | certifi | ❌ | — | unknown |

The **aruba.it → Actalis** resolution is the first production
endpoint that classifies as `qualified_it_tsp` — the entire chain
of motivation for this sprint. Note Namirial *as a TSP* would be
qualified, but their *web site* (namirial.com) uses Starfield, not
their own qualified root.

### Honest gap list

- **Cloudflare/INPS unresolved** is **not** a resolver bug: the
  GlobalSign Root CA (1999 original, used to cross-sign GTS Root
  R4) and INPS's CA are not present in the certifi 2024+ bundle.
  On a machine with the Windows native trust store wired up
  (`truststore` package's `SSLContext`), the resolution would
  succeed. Future sprint: optional `truststore`-backed source.
- **Pedigree lists are hand-curated subsets**, not the full
  AgID TSL or EU LOTL. False-negatives possible for less common
  qualified TSPs. Surface as a known limitation.
- **No automatic trust-anchor cross-check** against AgID's TSL XML.
  A future sprint could fetch and parse the TSL to confirm the
  resolved root is currently in the active qualified list.
- **Markdown reporter does not yet show trust anchor** — the data
  is in the JSON `metadata.trust_anchor` block. Sprint 9d.4 will
  add a dedicated section ("Trust anchor: Actalis Authentication
  Root CA — pedigree: qualified_it_tsp (AgID)"), analogous to the
  Sprint 9h-integration pattern.

### Critic gate

`critic-orchestrator` 3-worker adversarial review (222s, $2.39):

| Worker | Verdict | Confidence | Note |
|---|---|---|---|
| falsification | claim_holds | 0.97 | Adapted stash procedure for the mixed tracked/untracked fix (new module + tracked scanner mod): moved untracked module out, `git stash push -- pqc_audit/scanners/tls_scanner.py`, ran tests, restored. **22/22 fail pre-fix** (`ModuleNotFoundError: pqc_audit.scanners.tls_trust_store`), **22/22 pass post-fix** in 3.76s. Genuine RED→GREEN. |
| caller_verification | claim_holds | 0.95 | `resolve_root_from_chain` defined in `tls_trust_store.py:291`, imported in `tls_scanner.py:48`, called at `tls_scanner.py:872` inside `TLSScanner.scan`. Upward trace: `Auditor.scan` → `asyncio.run(auditor.scan([target]))` from every `pqc-audit` CLI scan subcommand (cli.py:108/149/169/192/221/252/281/312/346/389). Reachable via `pyproject.toml:111` entry point. |
| counterexample | claim_holds | 0.78 | 6 invariants verified empirically: canonical Name match, garbage-tolerant PEM parser, three resolve outcomes, integration into leaf metadata. Edge cases probed and rejected: hypothetical "Trust Italia (VeriSign Company)" / "Sectigo Aruba RSA CA" — no real Mozilla bundle match. Italian-wins precedence is documented design. Per-scan trust-store reload is a performance concern, not correctness. No counterexample found. |

**Consensus: hold 3-0-0.**

---

## [Unreleased] — Sprint 9h-integration (NIS2 inline in executive Markdown)

Sprint 9h-integration (2026-05-17) ships the user-facing payoff of
Sprint 9h: the `pqc_audit.compliance.nis2` mapping is now invoked
**automatically** by `pqc_audit.reporters.markdown_reporter.render()`,
which is the function behind every `pqc-audit report --format markdown`
invocation and the input to `pqc-audit report --format pdf`. A DPO /
CISO can hand the Markdown to a regulator without running the
secondary `pqc-audit compliance nis2` CLI.

### What's new in the executive Markdown

A new section titled `## NIS2 — D.Lgs. 138/2024 art. 24` is emitted
after the policy-engine `## Compliance` section (when present) and
before the footer. It contains three blocks:

1. **Per-finding citation table** — one row per distinct vulnerability
   title, with four columns: title, `D.Lgs. 138/2024, art. 24, comma
   2, lett. (X)`, `Direttiva (UE) 2022/2555 art. 21(2)(X)`, and the
   Italian topic. Multi-article matches are joined with `;`.
2. **Articoli implicati summary** — distinct list (order-preserving
   via `summarize_articles`) of every NIS2Article cited at least once
   in the table, with the EU directive reference appended.
3. **Quadro sanzionatorio art. 38** — the four constants from
   `pqc_audit.compliance.nis2` (`SANCTION_ESSENTIAL_FINE_CAP_EUR`,
   `SANCTION_ESSENTIAL_TURNOVER_PCT`, and the two `IMPORTANT_*` twins)
   formatted as `EUR 10,000,000 o 2.0%` and `EUR 7,000,000 o 1.4%`.
   Reporters cite the named constants instead of hard-coding the
   magic numbers, so any future correction to the decree propagates
   automatically.

### Anti-fuffa contracts

- **Skip on empty report.** `_render_nis2_compliance` returns `""`
  immediately when `report.total_vulnerabilities == 0`, *and* when
  `apply_nis2_mapping` returns an empty dict. The section is not
  rendered for clean scans — silence is honest.
- **Unmapped findings surfaced, not dropped.** When a vulnerability
  title does not match any pattern in `_TITLE_PATTERNS`, the row is
  emitted with `—` in the article column and the Italian marker
  `_da revisionare manualmente_` in the topic column. Inventing a
  regulation citation would be fuffa.
- **Heading anti-collision.** The section heading is `## NIS2 —
  D.Lgs. 138/2024 art. 24`, NOT `## Compliance NIS2`. The latter
  would silently break the pre-existing
  `test_markdown_reporter_no_compliance_section_when_evaluation_missing`
  test by introducing a false-positive `## Compliance` prefix.

### Test coverage

- New: `tests/unit/test_markdown_reporter_nis2.py` — 13 tests
  covering: section presence/absence, ordering wrt policy
  `## Compliance` section, lettered article citation `lett. (h)`,
  EU directive reference `Direttiva (UE) 2022/2555`, Italian topic
  text, unmapped finding `da revisionare manualmente` marker,
  distinct article dedup in summary block (count = 1 for two
  findings both mapping to ART_24_2_H), sanction caps essenziali
  (`10,000,000` / `2.0`) and importanti (`7,000,000` / `1.4`),
  `art. 38` citation, and the backwards-compat invariant that
  `## Compliance` never appears when `policy_evaluation` is absent.
- Full suite: **544 passed, 4 skipped** (3 weasyprint runtime
  unavailable on Windows, 1 SHA-1 cryptography refusal — both
  preexisting).
- Ruff: clean.

### Empirical E2E on agid.gov.it

```
python -m pqc_audit scan tls --host agid.gov.it --port 443 > agid.json
python -m pqc_audit report -i agid.json -f markdown
```

The output now contains:

```markdown
## NIS2 — D.Lgs. 138/2024 art. 24

| Vulnerability | Articolo D.Lgs. 138/2024 | Direttiva UE | Topic |
| --- | --- | --- | --- |
| `Quantum-vulnerable algorithm in use (RSA-2048)` | D.Lgs. 138/2024, art. 24, comma 2, lett. (h) | Direttiva (UE) 2022/2555 art. 21(2)(h) | Politiche e procedure relative all'uso della crittografia e cifratura |
| `[intermediate-1] Quantum-vulnerable algorithm in use (RSA-2048)` | D.Lgs. 138/2024, art. 24, comma 2, lett. (h) | Direttiva (UE) 2022/2555 art. 21(2)(h) | Politiche e procedure relative all'uso della crittografia e cifratura |

### Articoli implicati

- **D.Lgs. 138/2024, art. 24, comma 2, lett. (h)** — Politiche e procedure relative all'uso della crittografia e cifratura (Direttiva (UE) 2022/2555 art. 21(2)(h))

### Quadro sanzionatorio art. 38 D.Lgs. 138/2024

- Soggetti essenziali: fino a EUR 10,000,000 o 2.0% del fatturato mondiale annuo (applicato il maggiore).
- Soggetti importanti: fino a EUR 7,000,000 o 1.4% del fatturato mondiale annuo (applicato il maggiore).
```

### Critic gate

`critic-orchestrator` 3-worker adversarial review (167s, $1.79):

| Worker | Verdict | Confidence | Note |
|---|---|---|---|
| falsification | claim_holds | 0.97 | RED→GREEN empirical via stash/unstash. 13/13 fail pre-fix, 13/13 pass post-fix. |
| caller_verification | claim_holds | 0.97 | `_render_nis2_compliance` called unconditionally from `render()` at line 271; reachable via Typer CLI `pqc-audit report --format markdown` (cli.py:459, 467) and indirectly via `pdf_reporter` which wraps `markdown_reporter.render`. |
| counterexample | claim_holds | 0.88 | 7 critical points verified: heading anti-collision, sanction f-string locale-independence, summary dedup `lett. (h)` count = 1, unmapped path renders "_da revisionare manualmente_", zero-vuln short-circuit, ordering invariant. No counterexample. |

**Consensus: hold 3-0-0.**

### Honest gap list (still not done)

- Root trust-store lookup (CA pedigree) — Sprint 9d.3.
- ML-DSA / SLH-DSA signature_algorithms probe — Sprint 9f.2.
- sigstore keyless wrapper — Sprint 8e.
- Database TLS scanner (Postgres / MySQL / Oracle / MSSQL).
- Multi-article rows in the table use `; ` as separator. Markdown
  tables tolerate this but a future iteration may emit one row per
  (finding, article) pair for sortability.
- Unmapped-finding rows do not propose a candidate pattern; we just
  flag for human review. A future iteration could LLM-classify the
  title against the lettered measures, then human-confirm before
  adding it to `_TITLE_PATTERNS`.

---

## [Unreleased] — Sprint 9d.2 (cryptographic chain signature verification)

Sprint 9d.2 (2026-05-17) closes the explicit gap documented in Sprint
9d: *"No cryptographic chain verification. We surface what the server
sent, not whether the signatures actually chain."* A hostile server
could send three unrelated DER blobs and we would emit three "real"
crypto-asset findings — until now.

### What's verified

For every chain element, `cert.signature` is checked against the
issuer cert's public key using `cryptography.hazmat`:

- **RSA**: PKCS1v15 (default) or PSS (when
  `signature_algorithm_oid = 1.2.840.113549.1.1.10`), using PSS
  parameters from `cert.signature_algorithm_parameters` when
  available, otherwise a defensive `MGF1(hash_alg)` +
  `salt_length=hash_alg.digest_size`.
- **ECDSA**: `ec.ECDSA(hash_alg)`.
- **Ed25519 / Ed448**: pure `verify(signature, tbs)` (no padding
  argument).
- **DSA**: `pk.verify(sig, tbs, hash_alg)`.

The verifier returns one verdict dict per cert with **four** stable
keys: `index`, `label` (from `classify_chain_positions`), `verified`
(bool), and **`verifiable`** (bool — see below) plus an optional
`error` string.

### Critical anti-fuffa contract: the missing-root case

Standard TLS practice is for servers to ship `[leaf, intermediate]`
and let the client resolve the root from its trust store. AGID's
Let's Encrypt cert does exactly that: `chain_length=2`, last cert is
the LE E7 intermediate (non-self-signed), root `ISRG Root X1` is NOT
on the wire. A naive verifier would mark "intermediate's signature
cannot be verified" as a HIGH CWE-295 finding — **fuffa**: it's the
standard pattern, every modern cert chain trips it.

Sprint 9d.2 fix: a non-self-signed cert that is the LAST element of
the chain is marked `verifiable=False`. `assess_chain_signatures`
filters on `verifiable=True` before emitting findings — the LE
pattern produces **zero** false-positive broken-chain findings.
Empirically verified pre-fix → post-fix on AGID:

| Run | Vulnerability list |
|---|---|
| pre-fix | 2 HIGH ECDSA-vulnerable + **1 HIGH "Broken chain signature [intermediate-1]"** (fuffa) |
| post-fix | 2 HIGH ECDSA-vulnerable, **no broken-chain finding** |

This is the third anti-fuffa cycle this day after X448 (Sprint 9f)
and LE OCSP retirement (Sprint 9g.1). Pattern validated: a single
empirical scan against a REAL Italian PA endpoint catches the kind
of false positive a fixture-only test suite would miss.

### Added

- `pqc_audit.scanners.tls_scanner._verify_one(cert, issuer_cert)` —
  internal helper, never raises, returns `(verified, error_string)`
  across all 4 supported key types.
- `pqc_audit.scanners.tls_scanner.verify_chain_signatures(chain)` —
  returns `list[dict]` with the 5-key verdict structure above.
- `pqc_audit.scanners.tls_scanner.assess_chain_signatures(results,
  leaf_asset_id)` — emits HIGH CWE-295 findings for every BROKEN
  verifiable link. Filters out `verifiable=False` to avoid
  false-positives on the LE / DigiCert / Actalis pattern.
- `TLSScanner.scan` populates a new leaf metadata key
  `chain_signatures_verified: bool` aggregating the verdicts
  (True iff every verifiable link checked out). Existing chain_*
  metadata is unchanged.
- 10 new pytest cases in `tests/unit/test_scanners_tls_chain_verify.py`
  covering: intact 3-cert chain, tampered leaf, tampered intermediate,
  single-cert (root only) chain, error-string contract on failure,
  HIGH finding on broken leaf, no findings on intact chain, the
  empirical **LE-style 2-cert anti-fuffa regression test**, and the
  scanner-integration `chain_signatures_verified=True` propagation.

### Empirically verified end-to-end (REAL endpoint)

`www.agid.gov.it:443` with `PQC_AUDIT_FROZEN_AT=2026-05-17T00:00:00Z`:

| Field | Value |
|---|---|
| chain_signatures_verified | **`true`** (leaf ECDSA-256 signature verifies against LE E7 intermediate ECDSA-384 public key) |
| Broken-chain finding | **NOT emitted** (LE 2-cert pattern correctly handled) |
| Existing 2 HIGH ECDSA-vulnerable findings | preserved |

The leaf signature → intermediate public key verification was
hand-confirmed earlier with `pk.verify(leaf.signature,
leaf.tbs_certificate_bytes, ec.ECDSA(SHA384()))` against the real
DER fetched from agid.gov.it.

### Honest gap list (NOT done in 9d.2 — explicit roadmap)

- **No root trust-store lookup.** The non-verifiable last hop
  (root in client store) stays non-verifiable. We do NOT walk
  `/etc/ssl/certs` or the platform store to resolve it. Sprint
  9d.3 candidate; would let us tell "Let's Encrypt → ISRG" vs
  "Aruba → AgID-accredited root" from a single passive scan.
- **No revocation checking.** Verifying that a cert's signature
  is valid does NOT mean the cert is still valid. OCSP/CRL active
  fetch lives in Sprint 9g.2.
- **No chain path-length / EKU enforcement.** RFC 5280 imposes
  pathLenConstraint and ExtendedKeyUsage chaining rules; we don't
  audit either.
- **PSS-without-parameters** falls back to MGF1(hash_alg) +
  salt=hash.digest_size which is the *common* deployment but not
  universal. Real-world RSASSA-PSS chains needing different salt
  lengths would mis-verify.

## [Unreleased] — Sprint 9h (NIS2 / D.Lgs. 138/2024 article mapping)

Sprint 9h (2026-05-17) closes the gap between **technical** findings
and **legal** citations: every `Vulnerability` produced by the
scanners can be mapped to specific lettered measures of NIS2 art.
21(2) / D.Lgs. 138/2024 art. 24(2). A PwC-grade audit report can
now point at chapter-and-verse:

> *"This finding implicates art. 24, comma 2, lett. (h) del D.Lgs.
> 4 settembre 2024 n. 138 — politiche e procedure relative all'uso
> della crittografia e cifratura."*

### Why this matters

- The Italian transposition decree took effect 2024-10-16 with a
  three-tier sanction frame (`art. 38`):
  - **Soggetti essenziali**: fino a 10 000 000 EUR o 2 % del
    fatturato mondiale annuo (la maggiore delle due);
  - **Soggetti importanti**: fino a 7 000 000 EUR o 1.4 % del
    fatturato.
- A technical-only audit cannot quantify the regulatory exposure;
  citing the lettered measure makes it auditable.
- ACN is the competent authority (art. 4 D.Lgs. 138/2024) and
  expects audit deliverables to reference the decree text.

### Added

- `pqc_audit/compliance/__init__.py` — new compliance package.
- `pqc_audit/compliance/nis2.py`:
  - `NIS2Article` enum (10 lettered measures: `ART_24_2_A` ..
    `ART_24_2_J`), each carrying Italian `legal_reference`,
    `eu_directive_reference`, and `topic` strings.
  - `map_finding_to_nis2(vulnerability)` — substring-regex
    matching against the canonical scanner titles. Returns
    `list[NIS2Article]`, possibly empty for unmapped titles
    (we surface `[]` rather than inventing a citation — no fuffa).
  - `apply_nis2_mapping(report)` — produces a `title → [Article]`
    dict for an entire `AuditReport`.
  - `summarize_articles(articles)` — distinct, order-preserving
    article list for executive summary tables.
  - Sanction constants: `SANCTION_ESSENTIAL_FINE_CAP_EUR=10_000_000`,
    `SANCTION_ESSENTIAL_TURNOVER_PCT=2.0`,
    `SANCTION_IMPORTANT_FINE_CAP_EUR=7_000_000`,
    `SANCTION_IMPORTANT_TURNOVER_PCT=1.4` (art. 38 D.Lgs.
    138/2024).
- `pqc-audit compliance nis2 --input report.json --output mapping.md`
  CLI subcommand — emits a Markdown table with article citations
  + sanction frame.
- 13 new pytest cases in `tests/unit/test_compliance_nis2.py`
  covering all 10 enum letters, legal-reference exposure, eight
  finding-mapping patterns (quantum-vulnerable, deprecated hash,
  expired cert, undersized key, no-revocation, Must-Staple, PQC
  hybrid, unknown title returns `[]`), `apply_nis2_mapping`
  enrichment, `summarize_articles` distinctness, and the four
  sanction constants.

### Empirically verified end-to-end (REAL endpoint)

CLI invocation against the existing `www.agid.gov.it:443` scan
output:

```
$ pqc-audit compliance nis2 -i agid_rev.json -o agid_nis2.md
```

Generated Markdown contains:

- **Article summary table** — only `art. 24, comma 2, lett. (h)`
  hit (both quantum-vulnerable ECDSA findings map there).
- **Per-finding mapping table** — leaf ECDSA-256 finding +
  intermediate ECDSA-384 finding both cite the crypto article.
- **Sanction section** — €10M / 2% (essentiali) and €7M / 1.4%
  (importanti), with `art. 38 D.Lgs. 138/2024` citation.

The unmapped path is also tested empirically: a hand-crafted
finding with a wifi-related title (no scanner produces this today)
yields an empty list — the table cell shows "_(unmapped — rivedere
il titolo o aggiornare la mappatura)_" instead of fabricating an
article. Anti-fuffa contract enforced.

### Honest gap list (NOT done in 9h — explicit roadmap)

- **No automatic policy → article mapping.** The compliance layer
  reads `Vulnerability` titles only. Policy verdicts (Sprint 5/7
  policy_engine output) are not yet routed through NIS2 mapping.
- **No DORA / CRA / eIDAS mapping.** Single regulation supported
  (Italian NIS2 transposition). DORA (Reg 2022/2554), CRA (Reg
  2024/2847) and eIDAS2 (Reg 2024/1183) are separate sprints —
  each has its own article structure.
- **Pattern-based, not LLM-based.** Mapping changes require a
  code update. Pro: deterministic, reviewable, falsifiable.
  Con: new finding titles silently get `[]` until we add a
  pattern.
- **No incident notification mapping (art. 25).** We surface
  vulnerabilities, not incidents. CSIRT Italia notification
  workflows are outside this codebase's scope by design.

## [Unreleased] — Sprint 9g.1 (TLS revocation introspection, passive)

Sprint 9g.1 (2026-05-17) extends the TLS scanner from "what crypto"
to "what revocation mechanism": for every leaf cert it now surfaces
the OCSP responder URLs (RFC 6960 / AIA), CA Issuers URLs, CRL
Distribution Points (RFC 5280, 2.5.29.31), and the RFC 7633 TLS
Feature / Must-Staple bit. This is the substrate every regulator
asks about — "can clients learn the cert was revoked?" — and a
leaf-cert-only crypto auditor cannot answer it.

### Why this matters for a real audit

- **Let's Encrypt retired OCSP on 2024-12-05** (announcement at
  letsencrypt.org/2024/12/05/ending-ocsp/). Modern LE certs ship
  CRL DP + AIA caIssuers, **no OCSP responder URL**. Many auditing
  scripts written before 2024 flag this as a finding — wrongly.
- **OCSP Must-Staple (RFC 7633)** is a positive operational signal:
  the cert asks the client to require a stapled OCSP response and
  fail otherwise. Surfacing it in the report lets executive summaries
  recognize PA / banche that DO enforce stapling.
- **No-revocation-mechanism certs** (no AIA-OCSP AND no CRL DP) are
  the legacy / misissued / self-signed corner — worth a LOW finding.

### Added

- `pqc_audit.scanners.tls_scanner.extract_revocation_info(cert)` —
  pure helper returning a 5-field dict (`ocsp_responder_urls`,
  `ca_issuers_urls`, `crl_distribution_points`, `must_staple`,
  `has_revocation_mechanism`). Never raises on missing extensions.
- `pqc_audit.scanners.tls_scanner.assess_revocation(info, asset_id)` —
  two finding types: LOW `No revocation mechanism advertised by
  certificate` (CWE-295) when neither OCSP-URL nor CRL DP is present;
  INFO `OCSP Must-Staple asserted (RFC 7633)` when the cert opts in.
  Critically: a cert with CRL but no OCSP is **NOT** flagged
  (anti-fuffa: matches the post-2024 Let's Encrypt pattern).
- `TLSScanner.scan` extends the leaf asset metadata with four new
  keys: `ocsp_responder_urls`, `ca_issuers_urls`,
  `crl_distribution_points`, `must_staple`. Existing chain fields
  remain unchanged.
- 8 new pytest cases in `tests/unit/test_scanners_tls_revocation.py`
  covering empty cert, full cert, CRL-only (LE post-2024), Must-
  Staple-only, the LOW finding path, the INFO Must-Staple finding,
  the "CRL is enough" non-flag path, and TLSScanner end-to-end
  metadata propagation.

### Empirically verified end-to-end (REAL endpoint)

Scan of `www.agid.gov.it:443` with `PQC_AUDIT_FROZEN_AT=2026-05-17T00:00:00Z`:

| Field | Observed value |
|---|---|
| `ocsp_responder_urls` | `[]` (Let's Encrypt retired OCSP in 2024) |
| `ca_issuers_urls` | `['http://e7.i.lencr.org/']` |
| `crl_distribution_points` | `['http://e7.c.lencr.org/76.crl']` |
| `must_staple` | `False` |
| LOW "No revocation mechanism" finding | **NOT emitted** (CRL is enough) |
| INFO "Must-Staple" finding | **NOT emitted** (cert does not assert it) |

Both negative cases are operationally correct: the scanner does NOT
fabricate findings against a cert that ships modern revocation
hygiene minus OCSP. The two existing HIGH findings (ECDSA-256 leaf
+ ECDSA-384 intermediate quantum-vulnerable, from Sprint 9d) are
preserved.

### Honest gap list (NOT done in 9g.1 — explicit roadmap)

- **No active OCSP fetch.** We do not HTTP-GET the OCSP responder
  URL to learn the cert's revocation status. Active revocation
  checking (Sprint 9g.2) requires extra network round-trips, OCSP
  responder rate-limiting concerns, and DER parse of RFC 6960
  responses — separate sprint.
- **No stapling verification.** Must-Staple says "client MUST receive
  a stapled OCSP response". We can record the bit, but we don't
  verify that the server actually staples (would require parsing
  the TLS 1.3 `status_request` CertificateEntry extension —
  inaccessible via stdlib `ssl`). Sprint 9g.3 candidate.
- **No CRL download / parse.** We surface CRL DP URLs but do not
  fetch the CRL. Active CRL parse would let us tell "cert is in the
  CRL" — useful for audit, but slow (CRLs are MB-sized).
- **Only the leaf cert** is introspected for revocation info. The
  same fields exist on intermediate / root certs (e.g. an
  intermediate has its own CRL DP pointing at the root's CRL).
  Sprint 9g.4 could extend this.

## [Unreleased] — Sprint 9f (PQC hybrid handshake detection)

Sprint 9f (2026-05-17) adds an **active** TLS 1.3 probe scanner that
tells the auditor whether a service has begun its post-quantum
migration at the key-exchange layer. This is the single most-asked
question in a 2026 PQC readiness audit (PwC, ENISA, ACN) and a
leaf-cert auditor cannot answer it from a passive handshake.

### How it works (no marketing)

For each target, **three** `openssl s_client` handshakes are driven,
one per codepoint in `draft-ietf-tls-ecdhe-mlkem-04` (Feb 2026, in
RFC Ed Queue, awaiting IESG publication):

- `SecP256r1MLKEM768` (IANA `0x11EB` = 4587)
- `X25519MLKEM768` (IANA `0x11EC` = 4588)
- `SecP384r1MLKEM1024` (IANA `0x11ED` = 4589)

Note on **`X448MLKEM1024`**: the original Sprint 9f draft also probed
this group because `openssl list -kem-algorithms` shows it locally on
OpenSSL 3.5.x. Cross-checking the IETF working draft revealed that
`X448MLKEM1024` is **not** in the IANA TLS Supported Groups registry
and has **no codepoint** — no real server can negotiate it over the
wire. The probe matrix was reduced from 4 to 3 groups before commit.
This is the "no fuffa" cycle in action: web research → caught the
gap → fixed pre-commit. The empirical AGID + Cloudflare results
below are post-fix, on the corrected 3-group probe.

The scanner parses the OpenSSL `Negotiated TLS1.3 group:` line:

- Group name returned ⇒ the server accepted the offer ⇒ hybrid
  capability **confirmed**.
- `<NULL>` or absent + alert 40 (`handshake_failure`) ⇒ rejected.

Outputs:

- One `CryptoAsset` per endpoint (`pqc-hybrid://host:port`) with
  metadata: `probes: dict[group, negotiated_or_None]`,
  `hybrid_supported: list[str]`, `hybrid_supported_count: int`,
  `probe_tool: "openssl s_client"`, `probed_groups: list[str]`.
- A positive **INFO** finding (`PQC hybrid migration active (<groups>)`)
  when at least one group is accepted — useful for executive reports
  that want to flag *progress*, not just gaps.
- A **MEDIUM** finding (`No PQC hybrid key-exchange supported`,
  CWE-327) when zero groups are accepted, with explicit NIST IR 8547
  + tls-hybrid-design references.

### Why `openssl s_client` (and not stdlib `ssl`)

Empirically verified on Python 3.13.12 + OpenSSL 3.5.5
(`ssl.OPENSSL_VERSION`):

- `ssl.SSLContext.set_groups()` — does not exist.
- `ctx.set_ecdh_curve("X25519MLKEM768")` — `ValueError: unknown
  elliptic curve name` (OpenSSL classifies hybrids as KEMs, not
  curves; the stdlib API only ever accepted classical curves).
- `ssl.SSLSocket.group()` — does not exist; only `cipher()` and
  `shared_ciphers()` are exposed.

OpenSSL 3.5+ itself knows hybrid groups (visible in
`openssl list -kem-algorithms` → all four including `X448MLKEM1024`).
Driving it via `s_client` subprocess is therefore the only stdlib-
only path. We restrict the probe matrix to the THREE IETF-registered
groups (see above) — OpenSSL's local-only X448MLKEM1024 would never
fly over the wire. The scanner gracefully degrades with a soft error
if `openssl` is absent.

### Added

- `pqc_audit/scanners/pqc_hybrid_scanner.py` — new module with
  `parse_negotiated_group`, `probe_group`, `probe_all_hybrid_groups`
  pure helpers + the `PQCHybridScanner` class.
- `"pqc-hybrid"` added to `TargetType` literal and
  `_TYPE_TO_CATEGORY` (NETWORK).
- `PQCHybridScanner` registered as a default scanner in
  `Auditor.__init__` alongside `TLSScanner`, so any user-facing CLI
  Auditor invocation can scan a `pqc-hybrid` target without extra
  wiring.
- `pqc-audit scan pqc-hybrid --host H --port P` CLI subcommand.
- 12 new pytest cases in `tests/unit/test_scanners_pqc_hybrid.py`
  covering parse edge cases (`<NULL>`, absent line, whitespace),
  probe (mocked subprocess for argv assertion, timeout, handshake
  failure), the full-4-group probe matrix, scanner integration for
  both positive (1/3 succeed) and negative (0/3 succeed) cases, and
  the openssl-unavailable soft-error path.

### Empirically verified end-to-end (TWO REAL endpoints)

`PQC_AUDIT_FROZEN_AT=2026-05-17T00:00:00Z`:

| Endpoint | hybrid_supported | Negotiated example | Finding |
|---|---|---|---|
| `www.agid.gov.it:443` | `[]` (0/3) | none (alert 40 on all) | **MEDIUM** `No PQC hybrid key-exchange supported` (CWE-327) |
| `www.cloudflare.com:443` | `["X25519MLKEM768"]` (1/3) | `X25519MLKEM768` | **INFO** `PQC hybrid migration active (X25519MLKEM768)` |

CBOM + SARIF emitted for both:

| Output | AGID | Cloudflare |
|---|---|---|
| CycloneDX 1.6 schema | **PASS** (0 errors) | **PASS** (0 errors) |
| OASIS SARIF 2.1.0 schema | **PASS** (0 errors) | **PASS** (0 errors) |
| SARIF ruleId | `PQC.NO_PQC.TLS-HYBRID-PROBE` (warning) | `PQC.PQC_HYBRID.TLS-HYBRID-PROBE` (note) |

This is the first sprint that produces a **comparative** dataset:
two real endpoints, one PQC-ready, one not. The auditor's verdict on
each is empirically falsifiable (re-run with openssl and observe).

### Honest gap list (NOT done in 9f — explicit roadmap)

- **No KEM-extra group probe** beyond the IANA-registered four. Not
  all hybrid drafts have been retired in favor of `MLKEM*` IDs —
  some servers may still advertise `X25519Kyber768Draft00` (0x6399)
  which we do NOT probe. This is intentional: the draft codepoints
  are deprecated and should not earn a "PQC migration active" award.
- **No client-cert / authentication PQC.** The four hybrid groups
  cover KEY EXCHANGE (KEM). The signature-algorithm side
  (`ML-DSA-65` / `SLH-DSA-128s` in certificate chains, `ML-DSA-65`
  in CertificateVerify) is a separate question, currently invisible
  in the scanner. Sprint 9f.2 candidate.
- **No fingerprinting of WHICH hybrid the server prefers when
  multiple are offered**. We test one group at a time. A real
  client offers a list and lets the server pick. Trivial extension
  for 9f.3.
- **`openssl` 3.5+ required in PATH.** Older OpenSSL builds (3.4
  and below) don't know hybrid group names and will negotiate the
  classical fallback or fail. CI matrix should pin a known build.
- **Active probing — NOT passive.** Four extra handshakes per target.
  At default 8s timeout that's up to 32s per host; the Auditor's
  `max_concurrency=16` bounds the blast radius. Operators wishing
  to keep audits passive should skip the `pqc-hybrid` target type.

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
