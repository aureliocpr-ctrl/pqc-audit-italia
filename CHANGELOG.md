# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Quality gates

- `ruff check .` — clean
- `ruff format --check .` — clean
- `mypy pqc_audit` (strict) — 0 issues across 14 source files
- `bandit -r pqc_audit -ll` — 0 issues at any severity / confidence
- `pytest -q` — 94 passed, coverage **≥ 89%** on the package
- `hatch build -t wheel` — produces a clean wheel including the bundled
  YAML policies

## [0.1.0] - TBD

Initial alpha release placeholder.
