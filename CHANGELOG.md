# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Phase 6.5 — Reporter HTML self-contained** (2026-05-06): il
  subcomando `pqc-audit batch` emette ora anche `batch_report.html`
  oltre a `.md` e `.json`. Il file è un singolo documento con CSS+JS
  inline (no CDN, no font remoti), pensato per essere allegato a
  un'e-mail al CISO/CFO. Espone una text-input per filtrare la tabella
  per host e un pulsante "Scarica CSV" per pivot rapido a foglio
  elettronico. Hostname HTML-escaped (anti-XSS pinned in test).
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
