# Customer scenarios — pqc-audit-italia

Tre scenari concreti che coprono i tre tier di cliente target.
Ogni scenario è eseguibile copia-incolla. Tempo totale: 5 minuti.

---

## Scenario 1 — PMI italiana (1 dominio + report cliente)

**Situazione**: PMI con un singolo dominio (`example-srl.it`).
Vuole un report da inviare al CISO con la classificazione AgID 2026.

```bash
# Single host scan
python -m pqc_audit.cli scan tls \
    --host www.example-srl.it \
    --policy agid_2026 \
    --enforce \
    --pretty > example-srl_scan.json

# Convert JSON to executive Markdown
python -m pqc_audit.cli report \
    --input example-srl_scan.json \
    --format markdown \
    --output example-srl_report.md
```

**Output**: `example-srl_report.md` con titoli italiani, tabella
asset crittografici, recommendation P5 ML-DSA-65 se RSA-2048.
**Tempo**: 2 secondi.

---

## Scenario 2 — PA italiana (portafoglio multi-host + trend mensile)

**Situazione**: regione italiana con 30+ endpoint pubblici. Vuole
snapshot mensile per CDA con delta vs mese precedente.

```bash
# Build the host CSV (host[,port[,scope]] — header optional)
cat > regione_hosts.csv <<EOF
www.regione.example.it
servizi.regione.example.it
spid.regione.example.it
sanita.regione.example.it
EOF

# Scan portfolio (sweet spot concurrency=8)
python -m pqc_audit.cli batch \
    --csv regione_hosts.csv \
    --policy agid_2026 \
    --enforce \
    --concurrency 8 \
    --out monthly_2026_05/

# Apri il report HTML self-contained nel browser
# (file da inviare al CDA, no Adobe / PowerPoint richiesto)
start monthly_2026_05/batch_report.html
```

**Mese successivo**: stesso comando, output in `monthly_2026_06/`.
Poi diff:

```bash
python -m pqc_audit.cli batch-diff \
    --before monthly_2026_05/batch_report.json \
    --after  monthly_2026_06/batch_report.json \
    --out    delta_05_to_06.md
```

**Output**: `delta_05_to_06.md` italiano con sezioni "Migliorati",
"Peggiorati", "Invariati", "Aggiunti", "Rimossi". Pronto da
allegare a una mail CDA. **Tempo**: 9 secondi per 30 host.

---

## Scenario 3 — Banca italiana (DORA + GitHub Code Scanning)

**Situazione**: banca italiana con CI/CD su GitHub. Vuole
integrare PQC audit nelle PR check + pubblicare su Security tab.

### Setup CI

```yaml
# .github/workflows/pqc-gate.yml
name: PQC compliance gate
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"  # weekly Monday

jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install pqc-audit-italia
      - run: |
          python -m pqc_audit.cli batch \
              --csv infra/pqc/targets.csv \
              --policy banking_italy \
              --enforce \
              --fail-on-violations \
              --out artefacts/pqc/
      - uses: actions/upload-artifact@v4
        with:
          name: pqc-report
          path: artefacts/pqc/
      # Convert batch JSON → SARIF for GitHub Security tab
      - run: |
          python examples/ci_cd/batch_to_sarif.py \
              --input artefacts/pqc/batch_report.json \
              --output artefacts/pqc/batch_report.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: artefacts/pqc/batch_report.sarif
```

**Behaviour**:
- Su ogni PR che tocca `infra/`: il job gira, e se `--fail-on-violations`
  trip (qualunque host FAIL `banking_italy`), la PR viene bloccata
- Settimanale (lunedì 6:00 UTC): scan completo con artifact upload
- SARIF auto-loadato in GitHub Security → visibile in `Security` tab
  + alert su Slack via GitHub Mobile

**Tempo CI**: ~30 sec (Python install + scan + SARIF convert) per
20 endpoint banca.

---

## Estensione: SHIELD CryptoAudit dentro OMNEX

Per cliente che ha già OMNEX deployato on-prem (PA centrale, banca
top-10), il modulo è disponibile via blueprint API:

```bash
# Auth con OMNEX API token
curl -X POST https://omnex.cliente.it/api/cryptoaudit/scan \
    -H "Authorization: Bearer $OMNEX_API_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "host": "internal-portal.cliente.it",
      "port": 443,
      "policy": "banking_italy",
      "enforce": true,
      "scope_authorization": "audit-2026-q2-mandate-CDA-12345"
    }'
```

Il `scope_authorization` è il token di scope guard: lo scan è
rifiutato se l'host non è coperto dal token (prevenzione
auto-pwn / friendly fire interno). Pattern documentato in
`omnex/shield/cryptoaudit/__init__.py`.

---

## Risorse complementari

- [Quickstart PA italiana](../docs/quickstart-pa-italiana.md) —
  caso d'uso 6 "Snapshot mensile dell'intero perimetro PA"
- [`examples/ci_cd/`](ci_cd/) — workflow GitHub Actions e GitLab CI
- [`examples/bench/`](bench/) — performance benchmark reproducibile
