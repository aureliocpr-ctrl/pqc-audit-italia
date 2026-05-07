# pqc-audit-italia — Audit report 2026-05-06

> Audit live post-release v0.2.0 + bug hunt + fix.
> Scope: pqc-audit-italia HEAD `03b0e40`.

## Bug found & fixed

### 1. CLI `--version` flag standard mancante

**Severity**: UX (LOW), ma molesto per utenti.

**Reproduce**:
```bash
$ pqc-audit --version
Error: No such option: --version
$ pqc-audit -V
Error: No such option: -V
$ pqc-audit version    # solo questo funzionava
0.2.0
```

**Root cause**: il subcomando `version` esisteva ma non c'era
callback typer per `--version` / `-V` flag eager.

**Fix**: commit `03b0e40` — aggiunta `_version_callback` con
`is_eager=True` come root callback. Long form `--version`, short
form `-V`, subcommand legacy `pqc-audit version` tutti supportati.

**Lock-in**: 3 nuovi test in `test_cli_signature_lock_in.py`.

### 2. Ruff lint cleanup `examples/bench/bench_run.py`

**Severity**: lint (informational), CI lint.yml era rosso.

**Fix**:
- `S603` subprocess + untrusted → `# noqa: S603` con razionale
  (cmd è hardcoded `sys.executable`)
- `PLW1510` subprocess senza check → `check=False` esplicito
- `F541` f-string senza placeholder → tolto prefix `f`

## Verifiche superate (audit live)

### CSV edge cases
- ✅ BOM UTF-8 + CRLF + quoted fields gestiti
- ✅ Header-only CSV → exit 2 con error message
- ✅ CSV malformato → error chiaro, no crash

### Network edge cases
- ✅ DNS fail (`fakehostnotexists.invalid`) → `status=error`
  con `gaierror` esplicito (false-green fix funziona live)
- ✅ TLS handshake reset → catturato come error
- ✅ Concurrency=32 (max) → 9.98 sec per 30 host (plateau)
- ✅ Concurrency=0/100 (fuori range 1..32) → exit 2 con error

### Cert detection
- ✅ Cert scaduto (`not_valid_after - 30 days`) → HIGH severity
  "Certificate expired (30 days ago)" (CWE-298 fix funziona live)
- ✅ ECDSA-256 self-signed → 2 vuln (quantum + self-signed)
- ✅ Multi-file cert directory (RSA + ECDSA-256 + ECDSA-384)
  → 3 asset, 6 vuln, 0 errori

### Output formats
- ✅ JSON valid + parseable
- ✅ Markdown UTF-8 corretto (regione.lombardia.it ecc.)
- ✅ HTML self-contained: `<!doctype html>` + viewport meta +
  inline `<style>` + inline `<script>` + filter input + CSV
  download button + verdict-fail/hndl-high CSS class
- ✅ SARIF 2.1.0: schema valid, tool.driver.name corretto, runs[0]
- ✅ CBOM CycloneDX 1.6: bomFormat + specVersion + components +
  metadata.tools

### Wrapper OmnexCryptoAudit (in OMNEX vendor)
- ✅ Scope guard: out-of-scope → `PermissionError` esplicito
- ✅ In-scope: scan eseguito + report popolato

### IDN
- ✅ UTF-8 host (`café.example.it`) gestito senza crash, errore
  DNS riportato chiaramente

### Concurrency stress
- ✅ 30 host @ c=8 in 9.2 sec (sweet spot)
- ✅ 30 host @ c=32 in 9.98 sec (no degradation)

### Quality gates (post-fix)
- ✅ Ruff check: All checks passed!
- ✅ Ruff format check: All passed
- ✅ Mypy --strict: 24 file zero issues
- ✅ Bandit: 0 HIGH, 0 MEDIUM
- ✅ Pytest: 264+3 = 267 verdi (era 264, +3 per --version flag)

## Non-bug findings

### `weasyprint` non installato

PDF reporter è opt-in, va bene così. Marker `pytest.skip` nel test
funziona correttamente.

### `pip-audit` raggiunge i pacchetti vendored

Non testato in questa sessione perché twine/pip-audit non sono nei
requisiti minimi. Raccomando run periodico via CI.

### `metadata.tools` shape in CBOM

Il reporter CBOM produce `metadata.tools` come lista di string
(nome tool diretto). CycloneDX 1.6 spec accetta sia oggetti che
stringhe. **Non è un bug**, ma CycloneDX 1.6 raccomanda l'oggetto
con `name + version + vendor`. Considerare migrazione in 0.3.0
per maggiore conformance.

## Suggerimenti per 0.3.0 (non fatti oggi)

- Migrare `metadata.tools` CBOM al format object-based (non blocking)
- Aggiungere check `validity_period_remaining_days` come property
  in CBOM components
- Estendere mypy strict scope a `pqc_audit/scanners/` (oggi solo
  pqc_audit/ root + core/)
- Add type-only export `pqc_audit.types` per consumer Python
  che vogliono importare senza side effect

## Stato finale

- HEAD: `03b0e40`
- Pre-commit gate: 397/397 verde (OMNEX-side)
- pqc-audit standalone: 267 test verdi
- Bandit + Mypy + Ruff: zero issues
- Bug fix runtime: 1 (`--version` flag)
- Lint cleanup: 3 (bench_run.py)

**Verdict**: Production-ready. Pronto per PyPI publish.
