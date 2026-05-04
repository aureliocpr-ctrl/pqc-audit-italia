# pqc-audit-italia

> Toolkit open-source di crypto-discovery e crypto-agility audit per il mercato italiano — PA, PMI, settore finanziario sotto vigilanza Banca d'Italia.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)](#roadmap)

**English:** see [README.md](README.md).

---

## Cos'è

`pqc-audit-italia` è uno scanner open-source che identifica *dove* un'organizzazione utilizza crittografia oggi, *quanto* è esposta a **HNDL** (Harvest Now, Decrypt Later) e **Q-Day**, e *come* pianificare la migrazione verso gli standard NIST PQC (FIPS 203 / 204 / 205).

Pensato per il quadro normativo italiano (NIS2 D.Lgs. 138/2024, DORA, linee guida AgID, circolari Banca d'Italia) con report compliance-ready in italiano e inglese.

## Cosa NON è

- Non implementa algoritmi post-quantum — usa `pyca/cryptography` e opzionalmente `liboqs-python`.
- Non è uno strumento offensivo — identifica configurazioni, non sfrutta vulnerabilità.
- Non invia telemetria, analytics o dati esterni. Funziona anche air-gapped.

## Funzionalità principali

- **Scanner TLS / SSL** — handshake, catena certificati, cipher suite, algoritmi deprecati
- **Inventario certificati** — walker PEM / DER / PKCS#12 con estrazione metadata
- **Scanner SSH / VPN / config** — IPsec, OpenVPN, Apache, Nginx, Postfix, PostgreSQL
- **Scanner codice e binari** — analisi statica per chiavi hardcoded e uso API crittografiche
- **Risk scoring HNDL e Q-Day** — per asset, prioritizzato sulla vita utile della confidenzialità del dato
- **Crypto-agility scoring** — misura quanto è facile cambiare algoritmo
- **Mapping compliance** — NIS2 art. 21, DORA art. 9, linee guida AgID, ISO 27001 A.10
- **Export CBOM CycloneDX 1.6** — standard emergente di settore
- **Report PDF executive in italiano** pronti per audit interni o esterni

## Avvio rapido

```bash
pip install pqc-audit-italia          # non ancora su PyPI; usa git per ora
pqc-audit scan tls --host example.it --port 443
pqc-audit scan filesystem --path /etc/ssl
pqc-audit report --input results.json --format pdf --policy agid_2026
pqc-audit cbom --input results.json --output cbom.cdx.json
```

## API Python

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

- [x] Fase 0 — scheletro repo, CI, licenza
- [ ] Fase 1 — modelli core, scanner TLS / certificati / SSH, reporter JSON
- [ ] Fase 2 — scanner VPN / filesystem / binari / codice / config / token
- [ ] Fase 3 — classificatori HNDL / agility / compliance
- [ ] Fase 4 — reporter PDF / SARIF / Markdown / CBOM
- [ ] Fase 5 — policy engine (baseline NIST, AgID, banking IT, PA critica)
- [ ] Fase 6 — rifinitura CLI, esempi, sito docs

## Disclaimer

Questo strumento **supporta il mapping** verso requisiti NIS2, DORA, AgID. Non rende automaticamente conformi alcuna organizzazione, né costituisce consulenza legale. Validare sempre i findings con il proprio DPO / CISO e consultare le fonti normative ufficiali.

I riferimenti normativi rimandano direttamente alle fonti ufficiali: [Gazzetta Ufficiale](https://www.gazzettaufficiale.it/), [EUR-Lex](https://eur-lex.europa.eu/), [NIST CSRC](https://csrc.nist.gov/).

## Licenza

AGPL-3.0-only. Chi offre questo come Software-as-a-Service deve rilasciare le proprie modifiche. Vedi [LICENSE](LICENSE) e [CONTRIBUTING.md](CONTRIBUTING.md) (CLA richiesto).

## Autore

Aurelio Capriello — security researcher indipendente (Italia).

Powered by the OMNEX ecosystem.
