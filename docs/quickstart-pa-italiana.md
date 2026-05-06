# Quickstart per la Pubblica Amministrazione italiana

Audit crypto-agility e PQC readiness per Enti Pubblici, in 15 minuti.

> Questa guida assume di lavorare su uno dei propri sistemi
> (in scope autorizzato) o su un sistema per cui esiste autorizzazione
> esplicita scritta. `pqc-audit-italia` è uno strumento di audit
> *passivo* (handshake TLS, parsing KEXINIT SSH, lettura cert dal
> filesystem) — non sfrutta vulnerabilità, non altera nulla, ma il
> framework normativo italiano richiede comunque autorizzazione
> formale prima di sondare sistemi non propri.

## Caso d'uso 1 — Audit di un singolo dominio istituzionale

Vuoi sapere se il sito principale del tuo Ente è pronto per l'era
post-quantistica? Eseguire questo:

```bash
pqc-audit scan tls \
  --host www.<dominio-ente>.gov.it \
  --port 443 \
  --policy agid_2026 \
  --data-sensitivity-years 30 \
  --enforce
```

Cosa significano gli argomenti:

- `--policy agid_2026` — policy di compliance allineata alle linee
  guida AgID 2026 (TLS minimo, cipher non deprecate, chiave
  minima RSA-2048 / EC P-256, SHA-1 vietato).
- `--data-sensitivity-years 30` — la lifetime di confidenzialità
  attesa per i dati che la PA gestisce (anagrafiche cittadini,
  dati sanitari, atti di governo). 30 anni è un valore prudente
  per la PA centrale; per la sanità si può salire a 50.
- `--enforce` — il report JSON include un blocco
  `policy_evaluation` con verdetto `PASS` / `PARTIAL` / `FAIL`.

Output JSON tipico (estratto):

```json
{
  "scan_results": [...],
  "recommendations": [
    {
      "from_algorithm": "ECDSA-256",
      "to_algorithm": "ML-DSA-65",
      "rationale": "ECDSA-256 is quantum-vulnerable. HNDL 100/100, Q-Day 80/100. Migrate to ML-DSA-65 (NIST FIPS 204) and consider hybrid deployment during transition (RFC 9794).",
      "priority": 5,
      "hybrid_intermediate": "ECDSA-P256+ML-DSA-65",
      "references": ["https://csrc.nist.gov/projects/post-quantum-cryptography",
                     "https://datatracker.ietf.org/doc/rfc9794/"]
    }
  ],
  "policy_evaluation": {
    "policy_name": "agid_2026",
    "overall_verdict": "PASS",
    "compliant_assets": 1,
    "total_assets_evaluated": 1,
    "violations": []
  }
}
```

**Importante**: `policy_evaluation.overall_verdict = PASS` significa
"conforme oggi alle linee guida AgID 2026", **non** "PQC ready".
Il modulo `recommendations` segnala separatamente la priorità di
migrazione PQC. Sono due dimensioni diverse della stessa risposta.

## Caso d'uso 2 — Generare un report executive in italiano

Per il direttore generale o il DPO che NON deve leggere JSON:

```bash
# Salva la scansione
pqc-audit scan tls --host www.<ente>.gov.it --policy agid_2026 \
  --data-sensitivity-years 30 > scan.json

# Genera il PDF in italiano
pqc-audit report --input scan.json --format pdf --output relazione.pdf
```

`relazione.pdf` contiene:

- Header esecutivo (Ente, data, policy applicata, auditor)
- Sintesi: numero asset crypto, % vulnerabili al quantum, score HNDL/Q-Day
- Tabella Top-3 raccomandazioni per priorità
- Allegato tecnico con dettagli per asset

Tempo richiesto: < 1 minuto end-to-end.

## Caso d'uso 3 — Inventario crittografico via CBOM

Le gare CONSIP / Sogei stanno iniziando a chiedere il CBOM
(Cryptography Bill of Materials) come deliverable di gara, sul
modello del SBOM richiesto da CISA. Generare:

```bash
pqc-audit cbom --input scan.json --output cbom.cdx.json
```

Output: CycloneDX 1.6 — formato JSON standardizzato, importabile in
Dependency-Track, FOSSology, e altri inventori OSS / commerciali.

## Caso d'uso 4 — Audit di un parco certificati

Se gestite un PKI interno con certificati X.509 distribuiti su
filesystem (es. `/etc/ssl/certs`, `/var/local/ca/`, share NFS):

```bash
pqc-audit scan certs \
  --path /var/local/ca \
  --policy pa_critical \
  --data-sensitivity-years 30 \
  --enforce
```

`pa_critical` è la policy più restrittiva, pensata per sanità,
sicurezza pubblica e infrastrutture critiche. Walker ricorsivo,
parsing PEM/DER/CRT/CER, cap 8 MB per file (protegge contro
file binari ingannevoli), simlink-safe.

## Caso d'uso 5 — Pipeline CI/CD

Integrare in GitLab CI / GitHub Actions per audit automatici al
deploy:

```yaml
# .gitlab-ci.yml
crypto-audit:
  image: python:3.11
  script:
    - pip install pqc-audit-italia
    - pqc-audit scan tls --host ${PUBLIC_HOST} --policy agid_2026 --enforce > scan.json
    - pqc-audit report -i scan.json -f sarif > findings.sarif
  artifacts:
    reports:
      sast: findings.sarif
```

SARIF 2.1.0 viene importato nativamente dalla pagina "Security &
Compliance" di GitLab, e da GitHub Code Scanning. Le findings
diventano bloccanti se il policy_evaluation è FAIL.

## Caso d'uso 6 — Snapshot mensile dell'intero perimetro PA

Il subcomando `pqc-audit batch` esegue lo scan TLS su una lista
intera di host in un'unica esecuzione e produce un report
aggregato Markdown + JSON. È pensato per due scenari concreti:

1. **Snapshot periodico** del parco TLS di una PA (Regioni,
   ministeri, enti vigilati, fornitori) per tracciare l'adozione
   PQC nel tempo.
2. **Pre-gara CONSIP/Sogei**: il fornitore consegna in 2 minuti
   uno snapshot crittografico di TUTTO il perimetro digitale
   del cliente, già scritto in italiano e firmato.

```bash
# Lista CSV: host[,port[,scope]] — header opzionale, BOM Excel ok
$ cat parco_PA.csv
www.agid.gov.it,443,agid.gov.it
www.governo.it,443,governo.it
www.inps.it,443,inps.it
www.regione.lombardia.it,443,lombardia.it
www.consip.it,443,consip.it

# Scan parallelo (8 host alla volta) con enforcement della policy
$ pqc-audit batch \
    --csv parco_PA.csv \
    --policy agid_2026 \
    --data-sensitivity-years 30 \
    --concurrency 8 \
    --enforce \
    --out artefatti/snapshot_2026_05/

wrote artefatti/snapshot_2026_05/batch_report.md
wrote artefatti/snapshot_2026_05/batch_report.json
```

Il file `batch_report.md` è già pronto per essere consegnato al
cliente: header esecutivo italiano, tabella per host con
algoritmo TLS, HNDL, Q-Day, verdict policy e top
raccomandazione, nota di chiusura "P5 uniforme" se nessun host
negozia PQC.

Per usarlo come **gate di compliance in CI/CD** aggiungere
`--fail-on-violations`: il comando esce con codice 3 se almeno
un host fallisce la policy, bloccando il MR / PR finché la
crittografia non è AgID-compliant.

```bash
$ pqc-audit batch --csv parco_PA.csv \
                  --policy pa_critical \
                  --enforce --fail-on-violations \
                  --out artefatti/
# exit 0 → green / exit 3 → block PR / artefatti scritti comunque
```

I template pronti per GitHub Actions e GitLab CI sono in
`examples/ci_cd/` del repository — basta copia-incolla del file
nel proprio `.github/workflows/` o `.gitlab-ci.yml`.

## Tre cose da sapere subito

### 1. Il default è prudente

L'audit non altera nulla, non sfrutta nulla, non scarica payload
esotici. Si limita a osservare la risposta del server. **Sicuro
da eseguire anche su sistemi in produzione**, sempre nel rispetto
del proprio framework di autorizzazione.

### 2. Il `--enforce` non è obbligatorio

Senza `--enforce` il report contiene comunque le `recommendations`
(roadmap PQC). Il `--enforce` aggiunge la valutazione contro la
policy specifica. Per la PA, conviene *sempre* eseguirlo:
serve a documentare che oggi siete a norma, anche se la roadmap
PQC va attivata.

### 3. La policy `agid_2026` è viva

Le linee guida AgID si aggiornano. Il file YAML della policy è
modificabile (`policies/agid_2026.yaml`) ed è incluso nel
pacchetto Python come `package_data`, quindi sopravvive alle
installazioni. Se una nuova determina ACN aggiunge un requisito
(es. "TLS 1.3 obbligatorio entro 2027"), aggiornare la policy
YAML è una modifica a singolo file e non richiede re-build.

## Cosa NON fa lo strumento

- **NON** indica come migrare effettivamente i sistemi (è un
  problema architetturale, non solo crittografico).
- **NON** sostituisce un audit DORA / NIS2 completo — produce un
  pezzo della documentazione che un audit complessivo richiede,
  specificamente la parte crittografica.
- **NON** è un consulente legale — i suoi messaggi vanno sempre
  validati con DPO / CISO / consulente di compliance.
- **NON** monitora in continuo — è uno strumento puntuale. Per
  monitoraggio continuo va integrato in CI/CD o eseguito con
  cron periodico.

## Letture consigliate (fonti ufficiali)

- AgID Linee Guida — <https://www.agid.gov.it/it/sicurezza/cert-agid>
- D.Lgs. 138/2024 (NIS2) — <https://www.gazzettaufficiale.it/eli/id/2024/10/01/24G00154/sg>
- Reg. (UE) 2022/2554 (DORA) — <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>
- NIST FIPS 203/204/205 — <https://csrc.nist.gov/projects/post-quantum-cryptography>
- RFC 9794 (PQC migrazione hybrid) — <https://datatracker.ietf.org/doc/rfc9794/>

## Contatti

Strumento mantenuto da Aurelio Capriello, security researcher
indipendente (Italia). License: AGPL-3.0-only. Per richieste
commerciali / consulenza specifica, vedere il file
`CONTRIBUTING.md` per il CLA.
