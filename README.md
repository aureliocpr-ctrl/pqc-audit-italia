# pqc-audit-italia

> Crypto-discovery and crypto-agility audit toolkit for the Italian market — PA, SMB, financial sector under Banca d'Italia oversight.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)](#roadmap)

**Italiano:** see [README.it.md](README.it.md).

---

## What it is

`pqc-audit-italia` is an open-source scanner that identifies *where* an organization uses cryptography today, *how exposed* it is to **HNDL** (Harvest Now, Decrypt Later) and **Q-Day**, and *how* to plan migration toward NIST PQC standards (FIPS 203 / 204 / 205).

It targets the Italian regulatory landscape (NIS2, DORA, AgID guidelines, Banca d'Italia circulars) with compliance-ready reports in Italian and English.

## What it is NOT

- It does **not** implement post-quantum algorithms — uses `pyca/cryptography` and (optionally) `liboqs-python`.
- It is **not** an offensive tool — only identifies configurations, never exploits.
- It does **not** ship telemetry, analytics, or phone-home. Runs fully air-gapped.

## Key features

- **TLS / SSL scanner** — handshake, certificate chain, cipher suites, deprecated algorithms
- **Certificate inventory** — PEM / DER / PKCS#12 walker with metadata extraction
- **SSH / VPN / config scanners** — IPsec, OpenVPN, Apache, Nginx, Postfix, PostgreSQL
- **Code & binary scanners** — static analysis for hardcoded keys and crypto API usage
- **HNDL & Q-Day risk scoring** — per asset, prioritized by data-confidentiality lifetime
- **Crypto-agility scoring** — measures how easy it is to swap algorithm
- **Compliance mapping** — NIS2 art. 21, DORA art. 9, AgID guidelines, ISO 27001 A.10
- **CBOM CycloneDX 1.6 export** — emerging industry standard
- **Italian-language executive PDF reports** for auditor-ready deliverables

## Quick start

```bash
pip install pqc-audit-italia          # not yet on PyPI; use git for now
pqc-audit scan tls --host example.it --port 443
pqc-audit scan filesystem --path /etc/ssl
pqc-audit report --input results.json --format pdf --policy agid_2026
pqc-audit cbom --input results.json --output cbom.cdx.json
```

## Python API

```python
from pqc_audit import Auditor, ScanTarget

auditor = Auditor(policy="agid_2026")
results = await auditor.scan([
    ScanTarget(type="tls", host="example.it", port=443),
    ScanTarget(type="filesystem", path="/etc/ssl"),
])
report = auditor.generate_report(results, format="pdf")
```

## Roadmap

- [x] Phase 0 — repo skeleton, CI, license
- [ ] Phase 1 — core models, TLS / certificate / SSH scanners, JSON reporter
- [ ] Phase 2 — VPN / filesystem / binary / code / config / token scanners
- [ ] Phase 3 — HNDL / agility / compliance classifiers
- [ ] Phase 4 — PDF / SARIF / Markdown / CBOM reporters
- [ ] Phase 5 — policy engine (NIST baseline, AgID, banking IT, PA critical)
- [ ] Phase 6 — CLI polish, examples, docs site

## Disclaimer

This tool **supports mapping** to NIS2, DORA, and AgID requirements. It does **not** make any organization automatically compliant, nor does it constitute legal advice. Always validate findings with your DPO / CISO and reference original normative sources.

Regulatory references link directly to official sources: [Gazzetta Ufficiale](https://www.gazzettaufficiale.it/), [EUR-Lex](https://eur-lex.europa.eu/), [NIST CSRC](https://csrc.nist.gov/).

## License

AGPL-3.0-only. If you offer this as a Software-as-a-Service, you must release your modifications. See [LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md) (CLA required).

## Author

Aurelio Capriello — independent security researcher (Italy).

Powered by the OMNEX ecosystem.
