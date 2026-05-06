# pqc-audit-italia — release checklist

> Procedura per chiudere e pubblicare una release su PyPI.
> Usare questa checklist quando Aurelio darà l'OK al push pubblico.

## Pre-flight (eseguibile in autonomia)

- [ ] `make gates` → tutti verdi (ruff + format + mypy + bandit + pytest)
- [ ] `make build` → wheel + sdist in `dist/`
- [ ] `python -m twine check dist/*` → "Passed" su entrambi i file
- [ ] `pip install dist/pqc_audit_italia-X.Y.Z-py3-none-any.whl` →
      verifica install pulita in venv fresco
- [ ] `pqc-audit version` → ritorna `X.Y.Z`
- [ ] `pqc-audit batch --help` → mostra opzioni stabili (`--targets`,
      `--csv`, `--policy`, `--enforce`, `--concurrency`, `--fail-on-violations`,
      `--out`)

## Versioning + git (richiede OK Aurelio)

- [ ] Bump `version` in `pyproject.toml` se non già aggiornato
- [ ] Bump `__version__` in `pqc_audit/__init__.py`
- [ ] CHANGELOG: muovere [Unreleased] → [X.Y.Z] - YYYY-MM-DD
- [ ] Commit chore: ``release: bump 0.X.Y → 0.X.Z``
- [ ] Tag annotato: ``git tag -a vX.Y.Z -m "release vX.Y.Z"``
- [ ] Push branch + tag: ``git push origin main vX.Y.Z``

## TestPyPI (smoke pre-prod)

- [ ] `make publish-test` (o `twine upload --repository testpypi dist/*`)
- [ ] In venv pulito: `pip install -i https://test.pypi.org/simple/ pqc-audit-italia`
- [ ] Smoke verifica: `pqc-audit version` + `pqc-audit batch --targets google.com --policy nist_baseline --out /tmp/o`

## PyPI (production)

- [ ] `make publish` (o `twine upload dist/*`)
- [ ] Verifica install pubblica: `pip install pqc-audit-italia==X.Y.Z`
- [ ] Aggiorna README.md badge se necessario
- [ ] Pubblica annuncio su:
  - [ ] GitHub Discussions
  - [ ] LinkedIn (account Aurelio)
  - [ ] Forum AgID/PA italiana se presente

## Post-release

- [ ] Verifica github.com/aureliocpr/pqc-audit-italia release page
- [ ] Crea entry CITATION.cff con versione e data
- [ ] Update `docs/INVESTOR_LIVE_EVIDENCE.md` con timestamp ultimo scan
- [ ] Lancia un live scan PA aggiornato (`make live-evidence`) per
      catturare eventuali cambi di policy lato target

## Rollback (se serve)

- [ ] PyPI: NON SI PUO' UNPUBLISH una versione una volta caricata
      (PyPI policy). Si può solo `yank` (mark deprecated) e pubblicare
      una X.Y.Z+1 fix.
- [ ] git: `git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`
- [ ] CHANGELOG: aggiungere `### Yanked` per documentare la
      versione ritirata + ragione

## Note

- **Twine API token**: ottenere da `https://pypi.org/manage/account/token/`,
  scope: "Project: pqc-audit-italia". Credenziali NEVER committed —
  configura `~/.pypirc` o env var `TWINE_PASSWORD`.
- **Trusted Publishers**: alternativa raccomandata a token scoped.
  Configurare il workflow GitHub Actions con OIDC per evitare il
  passaggio di credenziali in clear.
- **Bus factor**: la chiave Twine è sotto controllo Aurelio. Se
  serve continuità, considerare GitHub OIDC trusted publisher.

## Ultimo run di build (verificato 2026-05-06)

```
$ make build
Successfully built pqc_audit_italia-0.2.0-py3-none-any.whl and pqc_audit_italia-0.2.0.tar.gz

$ ls -la dist/
-rw-r--r-- pqc_audit_italia-0.2.0-py3-none-any.whl  86 KB
-rw-r--r-- pqc_audit_italia-0.2.0.tar.gz           145 KB

$ pip install --dry-run dist/pqc_audit_italia-0.2.0-py3-none-any.whl
Would install pqc-audit-italia-0.2.0
```

Le 0.2.0 wheel sono già pronte. Mancano solo gli step "git tag + push +
twine upload" che richiedono l'OK di Aurelio (regola CLAUDE.md no
autonomous push).
