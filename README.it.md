# pqc-audit-italia

> Toolkit open-source di crypto-discovery e crypto-agility audit per il mercato italiano — PA, PMI, settore finanziario sotto vigilanza Banca d'Italia.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow)](#roadmap)
[![Tests: 252 verdi](https://img.shields.io/badge/tests-252%20green-success)](#sviluppo)
[![Coverage 90%](https://img.shields.io/badge/coverage-90%25-success)](#sviluppo)
[![Ruff zero](https://img.shields.io/badge/ruff-zero-success)](#sviluppo)
[![Mypy strict](https://img.shields.io/badge/mypy-strict-success)](#sviluppo)
[![Bandit zero](https://img.shields.io/badge/bandit-zero-success)](#sviluppo)

**English:** vedi [README.md](README.md).

---

## Cos'è

`pqc-audit-italia` è uno scanner open-source che identifica *dove* un'organizzazione utilizza crittografia oggi, *quanto* è esposta a **HNDL** (Harvest Now, Decrypt Later) e **Q-Day**, e *come* pianificare la migrazione verso gli standard NIST PQC (FIPS 203 / 204 / 205).

Pensato per il quadro normativo italiano (NIS2 D.Lgs. 138/2024, DORA Reg. (UE) 2022/2554, linee guida AgID, circolari Banca d'Italia) con report compliance-ready in italiano e inglese.

## Cosa NON è

- Non implementa algoritmi post-quantum — usa `pyca/cryptography` per il classico e si appoggia agli standard NIST per la roadmap PQC.
- Non è uno strumento offensivo — identifica configurazioni, non sfrutta vulnerabilità.
- Non invia telemetria, analytics o dati esterni. Funziona anche air-gapped.

## Funzionalità

| Capacità | Stato | Dettaglio |
|---|---|---|
| Scanner TLS / SSL | Pronto | Handshake, catena X.509, cipher suite, signature algorithm, hash, key size |
| Inventario certificati | Pronto | Walker PEM / DER / CRT / CER ricorsivo, simlink-safe, cap 8 MB per file |
| Scanner SSH (KEXINIT) | Pronto | Banner + algoritmi key exchange / cipher / MAC, RFC 4253-safe |
| Risk scoring HNDL e Q-Day | Pronto | Score 0-100 per asset, lifetime confidenzialità configurabile |
| Crypto-agility scoring | Pronto | Misura riusabilità del path crittografico nel software |
| Policy engine | Pronto | 4 policy bundled (vedi sotto), evaluation PASS / PARTIAL / FAIL |
| Reporter JSON | Pronto | Output strutturato per pipeline e dashboard |
| Reporter Markdown | Pronto | Italiano, executive-friendly |
| Reporter SARIF 2.1.0 | Pronto | GitHub code scanning, GitLab SAST |
| Reporter CBOM CycloneDX 1.6 | Pronto | Standard emergente per crypto BOM |
| Reporter PDF | Pronto | WeasyPrint-backed (opzionale) |
| Mapping compliance | Pronto | NIS2 art. 21, DORA art. 9, AgID Linee Guida, ISO 27001 A.10 |

### Policy bundled

| Nome | Per chi | Riferimento |
|---|---|---|
| `nist_baseline` | Default conservativo | NIST FIPS 203/204/205 + SP 800-227 |
| `agid_2026` | PA italiana | AgID Linee Guida + Misure minime di sicurezza ICT |
| `banking_italy` | Banche e SIM | Banca d'Italia + DORA |
| `pa_critical` | Sanità, sicurezza pubblica, infrastrutture | NIS2 D.Lgs. 138/2024, profilo strict |

## Avvio rapido

### Installazione

```bash
git clone https://github.com/<your-org>/pqc-audit-italia.git
cd pqc-audit-italia
pip install -e ".[dev]"
```

### Scan TLS

```bash
pqc-audit scan tls --host www.agid.gov.it --port 443 \
                   --policy agid_2026 \
                   --data-sensitivity-years 30
```

### Scan certificati locali

```bash
pqc-audit scan certs --path /etc/ssl/certs \
                     --policy banking_italy \
                     --data-sensitivity-years 20
```

### Scan SSH

```bash
pqc-audit scan ssh --host server.example.it --port 22 \
                   --policy nist_baseline
```

### Re-render report

Il flusso prevede `scan` → JSON, poi `report` per generare formati derivati:

```bash
pqc-audit scan tls --host example.it > scan.json
pqc-audit report -i scan.json -f markdown
pqc-audit report -i scan.json -f sarif > findings.sarif
pqc-audit report -i scan.json -f cbom   > cbom.cdx.json
pqc-audit report -i scan.json -f pdf    -o report.pdf
```

### Enforcement contro policy

```bash
pqc-audit scan tls --host example.it --enforce --policy agid_2026
```

Il JSON di output include il blocco `policy_evaluation` con verdetto PASS / PARTIAL / FAIL e dettaglio per regola.

## API Python

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

- [x] Fase 0 — scheletro repo, CI, licenza AGPL-3.0
- [x] Fase 1 — modelli core, scanner TLS / certificati / SSH, reporter JSON
- [x] Fase 2 — risk scoring HNDL, Q-Day, crypto-agility
- [x] Fase 3 — classificatori e raccomandazioni P1-P5 (incl. hybrid intermediate)
- [x] Fase 4 — reporter PDF / SARIF / Markdown / CBOM
- [x] Fase 5 — policy engine (4 policy bundled, PASS/PARTIAL/FAIL)
- [ ] Fase 6 — pubblicazione su PyPI, sito docs, CI/CD GitHub Actions complete
- [ ] Fase 7 — scanner aggiuntivi (VPN, codice/binari, secret in env)
- [ ] Fase 8 — UI web (opzionale, separato)

## Sviluppo

```bash
pip install -e ".[dev]"
pytest -q              # 189 test verdi (~92% coverage)
ruff check .           # linter
mypy --strict pqc_audit/  # type checker (clean)
```

Repo regolato da CLA (vedi `CONTRIBUTING.md`). I PR esterni passano CI prima del merge.

## Casi d'uso target

- **PA italiana**: audit conformità AgID Linee Guida prima di gare CONSIP / Sogei.
- **Banche / SIM**: due-diligence DORA pre-audit Banca d'Italia.
- **Sanità (NIS2 essential entities)**: inventario crittografico per art. 21 D.Lgs. 138/2024.
- **PMI fornitrici della PA**: dimostrare crypto-readiness ai propri clienti pubblici.
- **Penetration tester / consulenti**: deliverable executive in italiano post-audit.

## Disclaimer

Questo strumento **supporta il mapping** verso requisiti NIS2, DORA, AgID. Non rende automaticamente conformi alcuna organizzazione, né costituisce consulenza legale. Validare sempre i findings con il proprio DPO / CISO e consultare le fonti normative ufficiali.

I riferimenti normativi rimandano direttamente alle fonti ufficiali: [Gazzetta Ufficiale](https://www.gazzettaufficiale.it/), [EUR-Lex](https://eur-lex.europa.eu/), [NIST CSRC](https://csrc.nist.gov/).

## Licenza

AGPL-3.0-only. Chi offre questo come Software-as-a-Service deve rilasciare le proprie modifiche con la stessa licenza. Vedi [LICENSE](LICENSE) e [CONTRIBUTING.md](CONTRIBUTING.md) (CLA richiesto per PR esterni).

## Autore

Aurelio Capriello — security researcher indipendente (Italia).

Powered by the OMNEX ecosystem.
