# Annuncio per forum.italia.it (Developer Italia / AgID)

> Post pronto da copia-incollare su https://forum.italia.it
>
> **Categoria suggerita**: `Software Open Source` o `Tecnologie #sicurezza`
> **Tag**: `pqc`, `quantum`, `nis2`, `agid`, `crypto-agility`, `open-source`
>
> **Account**: serve registrazione (SPID-aware). Aurelio fa submit.

---

## Titolo

`pqc-audit-italia v0.2.0 — toolkit open-source per crypto-discovery + quantum-readiness audit (NIS2/DORA/AgID)`

---

## Body del post

Ciao a tutti :wave:

Pubblico **`pqc-audit-italia` v0.2.0** sotto licenza AGPL-3.0:
toolkit open-source di crypto-discovery e crypto-agility audit
pensato per il mercato italiano (PA centrale e territoriale, PMI,
settore finanziario sotto vigilanza Banca d'Italia).

🔗 **Repo**: https://github.com/aureliocpr-ctrl/pqc-audit-italia
📦 **Release**: https://github.com/aureliocpr-ctrl/pqc-audit-italia/releases/tag/v0.2.0
📄 **Licenza**: AGPL-3.0-only

### Cosa fa

Identifica **dove** un'organizzazione usa crittografia oggi,
**quanto** è esposta a HNDL (Harvest Now, Decrypt Later) e Q-Day,
e **come** pianificare la migrazione verso gli standard NIST PQC
(FIPS 203 / 204 / 205).

Specifico per il quadro normativo italiano:

- :it: **AgID** Linee Guida 2026 + Misure minime di sicurezza ICT
- :it: **NIS2** D.Lgs. 138/2024 + Det. ACN 379907/2025
- :eu: **DORA** Reg. (UE) 2022/2554 (banche e istituti finanziari)
- :bank: Circolari Banca d'Italia

Quattro **policy YAML bundled**:
- `agid_2026` — baseline AgID per la PA
- `pa_critical_2027` — profilo PQC-mandatory (sensitivity 50 anni)
- `banking_italy` — Banca d'Italia + DORA
- `nist_baseline` — conservativo NIST FIPS 203/204/205

Sei **reporter** per il deliverable:
- JSON / Markdown / SARIF 2.1.0 (GitHub Code Scanning) /
  CBOM CycloneDX 1.6 (per tender CONSIP / Sogei) / PDF (WeasyPrint) /
  HTML self-contained (e-mail-friendly)

### Quick start

```bash
pip install pqc-audit-italia==0.2.0   # quando arriva su PyPI

# Scan singolo host
pqc-audit scan tls --host www.governo.it --policy agid_2026 --enforce

# Batch portfolio (CSV multi-host)
pqc-audit batch \
    --csv miei_host.csv \
    --policy agid_2026 \
    --enforce \
    --concurrency 8 \
    --fail-on-violations \
    --out artefacts/pqc/

# Snapshot diff temporale (caso d'uso "scan mensile PA")
pqc-audit batch-diff \
    --before snapshot_2026_04.json \
    --after snapshot_2026_05.json \
    --out delta.md
```

### Live evidence (verificabile)

Scansionati 30 host pubblici PA italiana il 2026-05-06 in **9.2 sec**:

| Metrica | Valore |
|---|---:|
| Target totali | 30 |
| OK (algoritmo estratto) | 25 |
| FAIL `agid_2026` | **20 / 25 (80%)** |
| PQC negotiated | 0 / 25 |
| HNDL ≥ 80 | 25 / 25 |

Hosts inclusi: `governo.it`, `agid.gov.it`, `acn.gov.it`, `inps.it`,
`agenziaentrate.gov.it`, 7 regioni, 4 comuni grandi, 3 banche top-10
italiane, telco/utility critiche.

CSV riproducibile: `examples/bench/pa_30hosts.csv` nel repo.

### Use case PA

5 tutorial Q&A in `docs/quickstart-pa-italiana.md`:

1. Scan TLS singolo dominio
2. Audit parco certificati on-prem (file PEM/DER)
3. Generare CBOM CycloneDX per tender CONSIP / Sogei
4. CI/CD gate (GitHub Actions / GitLab CI snippets in `examples/ci_cd/`)
5. Snapshot mensile dell'intero perimetro PA

### Caratteristiche tecniche

- Python 3.11+ (testato 3.11/3.12/3.13 su Linux/macOS/Windows)
- 264 test unit + integration (90% coverage)
- Ruff + Mypy `--strict` + Bandit zero issues
- CI matrix 3 OS × 3 Python su GitHub Actions
- Air-gapped friendly: zero telemetria, zero phone-home

### Cosa NON è

- Non implementa algoritmi PQC (usa `pyca/cryptography` + segue
  standard NIST per la roadmap)
- Non è uno strumento offensivo (identifica configurazioni, non
  sfrutta vulnerabilità)
- Non sostituisce un audit di compliance — è uno strumento di
  triage per identificare dove serve action

### Roadmap

- **0.3.0** (Q3 2026): TestPyPI / PyPI public
- **0.4.0** (Q4 2026): performance benchmark CI gate, IPv6 support
- **1.0.0** (Q1 2027): API contract freeze (semver enforced)
- **2.0.0** (2027+): localizzazione policy BSI tedesco + ANSSI francese

### Feedback

Issue / feature request: https://github.com/aureliocpr-ctrl/pqc-audit-italia/issues

Sviluppo solo + AI pair-programming pattern, contribuzioni esterne
benvenute (vedi `CONTRIBUTING.md`).

— Aurelio Capriello (`aurelio@omnexcyber.com`)

---

## Note operative per submit

1. **Login forum.italia.it** con account dev / SPID
2. **Categoria**: probabilmente `Tecnologie / Sicurezza` o
   `Software / Open Source` (verifica scelta corrente sul forum)
3. **Tag**: `pqc`, `quantum-readiness`, `nis2`, `agid`, `crypto-agility`,
   `open-source`, `agpl`
4. **Allegati**: nessuno (link al repo è sufficiente)
5. **Cross-post**: developers.italia.it ha sezione "News" — chiede
   review prima della pubblicazione, tempo ~3-5 giorni
6. **LinkedIn**: bonus, post separato che linka a forum.italia.it

## Annotazioni Aurelio (NON copiare nel post)

- Segnala personalmente Andrea Tironi / Vincenzo Patruno / mantainer
  Developer Italia se hai contatto diretto
- Crea anche un breve thread su X / Mastodon (#PQC #italia
  #cybersecurity) puntando al forum post
- Considera invio newsletter ACN se hai contatto (dipendentemente
  dal canale che hai)
