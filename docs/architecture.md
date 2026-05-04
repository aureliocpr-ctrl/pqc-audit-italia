# Architecture

`pqc-audit-italia` is a layered toolkit. Each layer has a narrow job
and is independently testable.

```
+--------------------------------------------------+
|  CLI  (typer)         |  Python API  (Auditor)   |  <- entry points
+-----------------------+--------------------------+
|              Auditor (orchestration)             |
|  - picks scanners by target type                 |
|  - aggregates ScanResult into AuditReport        |
|  - calls enrich_report()                         |
+--------------------------------------------------+
|   Scanners              |     Reporters          |
|   - tls_scanner         |     - json_reporter    |
|   - cert_scanner (P1.e) |     - sarif (P4)       |
|   - ssh_scanner  (P1.e) |     - pdf    (P4)      |
|   - vpn / fs / ...      |     - cbom   (P4)      |
+--------------------------------------------------+
|                 Core (pure data)                  |
|   - models.py        (pydantic v2 dataclasses)    |
|   - algorithms.py    (NIST PQC registry)          |
|   - risk.py          (HNDL / Q-Day / agility)     |
+--------------------------------------------------+
|                  Policies (P5)                    |
|   - nist_baseline.yaml                            |
|   - agid_2026.yaml                                |
|   - banking_italy.yaml                            |
|   - pa_critical.yaml                              |
+--------------------------------------------------+
```

## Layer responsibilities

### Core (`pqc_audit.core`)

Pure data and pure functions. No I/O, no global state. Imports only
from the standard library and `pydantic`.

- `models.py` — pydantic v2 frozen dataclasses: `Algorithm`,
  `KeyMaterial`, `Vulnerability`, `MigrationRecommendation`,
  `CryptoAsset`, `ScanResult`, `AuditReport`, plus `RiskLevel`
  (IntEnum) and `ScanCategory` (StrEnum).
- `algorithms.py` — three classification buckets
  (`QUANTUM_VULNERABLE`, `QUANTUM_WEAKENED`, `QUANTUM_RESISTANT`),
  hybrid transition profiles, and helpers `classify_algorithm`,
  `is_deprecated`, `recommend_pqc_replacement`.
- `risk.py` — `calculate_hndl_risk`, `calculate_qday_risk`,
  `calculate_agility_score`, `aggregate_risk`. All scores are
  integers in `[0, 100]`. The math is deliberately simple so an
  auditor can defend each number.

### Scanners (`pqc_audit.scanners`)

Each scanner implements `BaseScanner` (Protocol), exposing a stable
`name`, `category`, `is_applicable(target)`, and async `scan(target)
-> ScanResult`. Scanners are *defensive*: they identify what the
target presents, never attempt downgrade or exploit.

The `tls_scanner` is split into a pure parsing layer (offline-tested
against in-memory self-signed certificates) and a thin async network
layer that performs a stdlib TLS handshake in a worker thread.

### Reporters (`pqc_audit.reporters`)

`render(report) -> str` pure functions, no file I/O. JSON ships in
Phase 1; SARIF / Markdown / PDF / CycloneDX CBOM follow in Phase 4.

### Auditor (`pqc_audit.auditor`)

Glue layer. Picks applicable scanners per target, runs them in
sequence, builds the raw `AuditReport`, and calls
`enrich_report(...)` to populate `metadata['risk_summary']`,
`metadata['per_asset_risk']`, and the deduped `recommendations`.

### CLI (`pqc_audit.cli`)

Thin typer wrapper over the Auditor. No business logic — only
argument parsing, async-bridge, and rendering.

## Data flow

```
ScanTarget(s)
   |
   v
Auditor.scan()
   |
   +--> for each target / each scanner:
   |       BaseScanner.is_applicable(target) ?
   |          |
   |          v
   |       BaseScanner.scan(target) -> ScanResult
   |
   v
AuditReport(scan_results=[...])
   |
   v
enrich_report(report, data_sensitivity_years=N)
   |
   +--> aggregate_risk(...)
   +--> calculate_hndl_risk / qday / agility per asset
   +--> recommend_pqc_replacement per distinct vulnerable algorithm
   |
   v
AuditReport with metadata['risk_summary']
                + metadata['per_asset_risk']
                + recommendations
   |
   v
reporters.json_reporter.render(report) -> JSON str
```

## Design principles

1. **Identification, not exploitation.** Every scanner is read-only.
   A scan is safe to run against production systems.
2. **Pure layers stay pure.** Core has no scanners imports, scanners
   never touch reporters. Cyclic dependencies are not allowed.
3. **No telemetry, no phone-home.** The toolkit must run inside
   air-gapped environments without graceful degradation.
4. **No private key material is ever stored.** Only sha256
   fingerprints of public keys.
5. **Frozen models.** Every pydantic model is `frozen=True`. Mutation
   is replaced by `model_copy(update=...)` at the orchestrator layer.
6. **Async-first for I/O, sync for parsing.** Network handshake is
   async; all algorithm classification, risk math, and reporter
   serialization stay synchronous.
7. **Defensible math.** Risk scoring formulas are documented inline,
   thresholds are named constants, and every score lives in `[0, 100]`.

## Phase roadmap

| Phase | Module(s)                                          | Status |
| ----- | -------------------------------------------------- | ------ |
| 0     | scaffold, CI, license, governance docs             | done   |
| 1.a   | core/models.py                                     | done   |
| 1.b   | core/algorithms.py                                 | done   |
| 1.c   | core/risk.py                                       | done   |
| 1.d   | scanners/base.py + scanners/tls_scanner.py         | done   |
| 1.e   | scanners/cert_scanner.py + scanners/ssh_scanner.py | next   |
| 1.f   | reporters/json_reporter.py                         | done   |
| 1.g   | Auditor + risk enrichment + recommendations        | done   |
| 2     | VPN / filesystem / binary / code / config / token  | next   |
| 3     | classifiers (HNDL / agility / compliance mapper)   | next   |
| 4     | reporters: SARIF / PDF / Markdown / CBOM           | next   |
| 5     | policies engine (nist_baseline / agid_2026 / ...)  | next   |
| 6     | docs site, examples, CLI polish                    | next   |
