# pqc-audit-italia — Migration guide

> Guida ai breaking change tra versioni. Manualmente curata, non
> auto-generata.

## 0.1 → 0.2 (2026-05-06)

### No breaking changes per public API

L'API stabile (`pqc_audit.Auditor`, `pqc_audit.ScanTarget`,
`pqc_audit.AuditReport`) è **invariata** tra 0.1 e 0.2.

Tutti i CLI flag esistenti (`scan tls --host`, `scan certs --path`,
`scan ssh --host`, `report --input`, `report --format`) sono
**backward compatible**.

### Nuove feature additive

- **`pqc-audit batch`** — nuovo subcomando per scan multi-host
  (CSV o inline) con concurrency + CI gate. Vedi
  [README "Batch scan"](../README.md#batch-portfolio-scan) +
  [`examples/customer_scenarios.md`](../examples/customer_scenarios.md).

- **`pqc-audit batch-diff`** — confronto temporale fra due
  `batch_report.json` snapshot. Caso d'uso "snapshot mensile PA".

- **HTML batch reporter** — `batch_report.html` self-contained
  (CSS+JS inline, host filter, CSV export) generato di default
  insieme a `.md` e `.json` quando esegui `pqc-audit batch`.

### Bug fix che potrebbero impattare assertioni custom

Se un cliente ha logica downstream sui `batch_report.json`:

#### 1. Expired certificate detection (CWE-298)

**Prima** (0.1.0): un cert con `not_valid_after < now()` veniva
scansionato senza vulnerability di expiry — solo quantum-vulnerability.

**Adesso** (0.2.0): il cert genera una nuova vulnerability con:
- `severity: HIGH`
- `cwe: "CWE-298"`
- `title: "Certificate expired (N days ago)"`

**Impatto**: clienti che contano `len(scan_results[0].vulnerabilities)`
vedranno un +1 sui cert scaduti. Aggiorna le tue dashboard se contano.

#### 2. False-green fix in `batch.summarize_one`

**Prima** (0.1.0): `summarize_one` produceva `status="ok" /
verdict="PASS"` per host con scan errors interni e 0 asset.

**Adesso** (0.2.0): produce `status="error" / error="..."` con il
messaggio di errore originale. Niente più PASS misleading per
host irraggiungibili.

**Impatto**: script downstream che filtravano `status="ok"` ora
vedono questi host come `error`. Se assumevi tutti gli host
"ok=PASS+irraggiungibili", aggiorna la logica.

#### 3. Bandit policy formalizzata

`pyproject.toml [tool.bandit]` ora ha skips intenzionali
documentati (vedi `.bandit` per il rationale). Eseguire
`bandit -r pqc_audit/ -ll` con o senza `-c pyproject.toml` da
risultati identici (HIGH = 0).

**Impatto**: nessuno — il binary build di pqc-audit-italia è
invariato.

### Nuovi requisiti dipendenze

Nessun nuovo requisito core.

Optional `[dev]` dependency aggiunte (solo per chi sviluppa il
package, non per consumer):
- `bandit[toml]>=1.7`

Optional `[pdf]` dependency invariate (`weasyprint>=62.0`).

## Roadmap 0.3+

Vedi `docs/PUBLIC_ROADMAP.md` (in repo OMNEX, sezione "T1 2026") +
`CHANGELOG.md`. Prossime feature pianificate:

- **0.3.0** — TestPyPI publish + first PyPI release
- **0.4.0** — performance benchmark suite + CI gate
- **0.5.0** — IPv6 + mTLS scenari edge case
- **1.0.0** — API contract freeze, semver enforced
