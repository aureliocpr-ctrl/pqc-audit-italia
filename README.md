# pqc-audit-italia

> Crypto-discovery and crypto-agility audit toolkit for the Italian market — PA, SMB, financial sector under Banca d'Italia oversight.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow)](#roadmap)
[![Tests: 187 green](https://img.shields.io/badge/tests-189%20green-success)](#development)

**Italiano:** see [README.it.md](README.it.md).

---

## What it is

`pqc-audit-italia` is an open-source scanner that identifies *where* an organization uses cryptography today, *how exposed* it is to **HNDL** (Harvest Now, Decrypt Later) and **Q-Day**, and *how* to plan migration toward NIST PQC standards (FIPS 203 / 204 / 205).

It targets the Italian regulatory landscape (NIS2 D.Lgs. 138/2024, DORA Reg. (EU) 2022/2554, AgID guidelines, Banca d'Italia circulars) with compliance-ready reports in Italian and English.

## What it is NOT

- It does **not** implement post-quantum algorithms — uses `pyca/cryptography` for classical and tracks NIST standards for the PQC roadmap.
- It is **not** an offensive tool — it identifies configurations, never exploits.
- It does **not** ship telemetry, analytics, or phone-home. Runs fully air-gapped.

## Capabilities

| Feature | Status | Detail |
|---|---|---|
| TLS / SSL scanner | Ready | Handshake, X.509 chain, cipher suites, signature algo, hash, key size |
| Certificate inventory | Ready | Recursive PEM / DER / CRT / CER walker, symlink-safe, 8 MB cap per file |
| SSH (KEXINIT) scanner | Ready | Banner + KEX/cipher/MAC algorithms, RFC 4253-safe |
| HNDL & Q-Day risk scoring | Ready | 0-100 score per asset, configurable confidentiality lifetime |
| Crypto-agility scoring | Ready | Measures crypto path reusability in software |
| Policy engine | Ready | 4 bundled policies (see below), PASS / PARTIAL / FAIL evaluation |
| JSON reporter | Ready | Structured output for pipelines and dashboards |
| Markdown reporter | Ready | Italian, executive-friendly |
| SARIF 2.1.0 reporter | Ready | GitHub code scanning, GitLab SAST |
| CBOM CycloneDX 1.6 reporter | Ready | Emerging standard for crypto BOM |
| PDF reporter | Ready | WeasyPrint-backed (optional) |
| Compliance mapping | Ready | NIS2 art. 21, DORA art. 9, AgID Linee Guida, ISO 27001 A.10 |

### Bundled policies

| Name | Audience | Reference |
|---|---|---|
| `nist_baseline` | Conservative default | NIST FIPS 203/204/205 + SP 800-227 |
| `agid_2026` | Italian PA | AgID Linee Guida + Misure minime di sicurezza ICT |
| `banking_italy` | Banks and SIMs | Banca d'Italia + DORA |
| `pa_critical` | Healthcare, public safety, infrastructure | NIS2 D.Lgs. 138/2024 strict profile |

## Quick start

### Install

```bash
git clone https://github.com/<your-org>/pqc-audit-italia.git
cd pqc-audit-italia
pip install -e ".[dev]"
```

### TLS scan

```bash
pqc-audit scan tls --host www.agid.gov.it --port 443 \
                   --policy agid_2026 \
                   --data-sensitivity-years 30
```

### Local certs scan

```bash
pqc-audit scan certs --path /etc/ssl/certs \
                     --policy banking_italy \
                     --data-sensitivity-years 20
```

### SSH scan

```bash
pqc-audit scan ssh --host server.example.it --port 22 \
                   --policy nist_baseline
```

### Re-render reports

The flow is `scan` → JSON, then `report` to derive other formats:

```bash
pqc-audit scan tls --host example.it > scan.json
pqc-audit report -i scan.json -f markdown
pqc-audit report -i scan.json -f sarif > findings.sarif
pqc-audit report -i scan.json -f cbom  > cbom.cdx.json
pqc-audit report -i scan.json -f pdf   -o report.pdf
```

### Policy enforcement

```bash
pqc-audit scan tls --host example.it --enforce --policy agid_2026
```

The output JSON includes a `policy_evaluation` block with verdict PASS / PARTIAL / FAIL and per-rule detail.

## Python API

```python
import asyncio
from pqc_audit import Auditor, ScanTarget

auditor = Auditor(policy="agid_2026", data_sensitivity_years=30)
report = asyncio.run(auditor.scan([
    ScanTarget(type="tls", host="www.agid.gov.it", port=443),
    ScanTarget(type="certs", path="/etc/ssl/certs"),
]))

# Re-rendering
from pqc_audit.reporters.markdown_reporter import render as md
print(md(report))

# Policy evaluation
evaluation = auditor.evaluate_against_policy(report)
print(evaluation.overall_verdict)         # PASS / PARTIAL / FAIL
print(evaluation.compliant_assets, "/",
      evaluation.total_assets_evaluated)
for v in evaluation.violations:
    print(v.rule, v.severity, v.remediation)
```

## Roadmap

- [x] Phase 0 — repo skeleton, CI, AGPL-3.0 license
- [x] Phase 1 — core models, TLS / cert / SSH scanners, JSON reporter
- [x] Phase 2 — HNDL, Q-Day, crypto-agility risk scoring
- [x] Phase 3 — classifiers and P1-P5 recommendations (incl. hybrid intermediate)
- [x] Phase 4 — PDF / SARIF / Markdown / CBOM reporters
- [x] Phase 5 — policy engine (4 bundled policies, PASS/PARTIAL/FAIL)
- [ ] Phase 6 — PyPI publish, docs site, full GitHub Actions CI/CD
- [ ] Phase 7 — additional scanners (VPN, code/binary, env secrets)
- [ ] Phase 8 — web UI (optional, separate)

## Development

```bash
pip install -e ".[dev]"
pytest -q              # 189 tests green (~92% coverage)
ruff check .           # linter
mypy --strict pqc_audit/  # type checker (clean)
```

Repository governed by CLA (see `CONTRIBUTING.md`). External PRs go through CI before merge.

## Target use cases

- **Italian PA**: AgID guidelines compliance audit before CONSIP / Sogei tenders.
- **Banks / SIMs**: DORA due-diligence pre-audit by Banca d'Italia.
- **Healthcare (NIS2 essential entities)**: crypto inventory for art. 21 D.Lgs. 138/2024.
- **SMBs supplying PA**: demonstrate crypto-readiness to public-sector customers.
- **Pen-testers / consultants**: Italian-language executive deliverable post-audit.

## Disclaimer

This tool **supports mapping** to NIS2, DORA, and AgID requirements. It does **not** make any organization automatically compliant, nor does it constitute legal advice. Always validate findings with your DPO / CISO and reference original normative sources.

Regulatory references link directly to official sources: [Gazzetta Ufficiale](https://www.gazzettaufficiale.it/), [EUR-Lex](https://eur-lex.europa.eu/), [NIST CSRC](https://csrc.nist.gov/).

## License

AGPL-3.0-only. If you offer this as a Software-as-a-Service, you must release your modifications under the same license. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md) (CLA required for external PRs).

## Author

Aurelio Capriello — independent security researcher (Italy).

Powered by the OMNEX ecosystem.
