# Contributing to pqc-audit-italia

Thank you for considering a contribution. This project welcomes bug reports, feature requests, code, documentation, and translations.

## Contributor License Agreement (CLA)

This project requires a CLA for all non-trivial contributions. By submitting a pull request you agree that:

1. You wrote the contribution yourself, or have the right to submit it.
2. You grant the project maintainer (Aurelio Capriello) a perpetual, worldwide, royalty-free license to use, modify, and **relicense** the contribution, including under licenses different from AGPL-3.0 in the future.
3. The contribution does not contain proprietary code from third parties without their explicit permission.

Sign the CLA by adding `Signed-off-by: Your Name <you@example.com>` to commit messages, and replying `I agree to the CLA terms` on your first PR.

A formal CLA-bot will be enabled before the first stable release.

## Reporting bugs

Open an [issue](https://github.com/aureliocpr/pqc-audit-italia/issues) using the bug template. Include:

- `pqc-audit --version`
- Python version, OS
- Minimal reproducer
- Expected vs actual behavior

For security-sensitive bugs see [SECURITY.md](SECURITY.md) instead.

## Suggesting features

Open an issue using the feature template. Explain:

- The problem you are solving
- The use case (sector, normative driver if any)
- Acceptance criteria

## Development setup

```bash
git clone https://github.com/aureliocpr/pqc-audit-italia.git
cd pqc-audit-italia
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev,pdf,binary,docs]"
pre-commit install            # if pre-commit is configured
```

Run the test suite:

```bash
pytest                                  # all tests with coverage
pytest tests/unit                       # unit only
pytest -m "not integration"             # skip slow tests
```

Lint and type-check:

```bash
ruff check .
ruff format --check .
mypy pqc_audit
bandit -r pqc_audit
pip-audit
```

## Code style

- Code, comments, docstrings: **English**.
- User-facing strings (CLI help, report templates): English by default, Italian translations under `pqc_audit/locales/it/`.
- Type hints mandatory, `mypy --strict` clean.
- Follow `ruff` defaults plus the rules in `pyproject.toml`.
- Async-first for I/O paths; pure sync for parsing and pure functions.
- Pydantic v2 for all data models.
- No `print` — use `structlog`.

## Pull request checklist

- [ ] Tests added or updated, coverage does not drop below 80%
- [ ] `ruff check .` and `mypy pqc_audit` clean
- [ ] CHANGELOG.md updated under "Unreleased"
- [ ] Docstrings updated for public API changes
- [ ] CLA acknowledgement on first PR

## Areas where help is most welcome

1. **Italian compliance mapping** — NIS2 D.Lgs. 138/2024, AgID, Banca d'Italia, DORA
2. **Additional scanners** — vendor-specific configs (Cisco, Fortinet, F5, Aruba)
3. **CBOM / SARIF schema validation**
4. **Documentation translations** (Italian primary, French / German welcome)
5. **Real-world test fixtures** (anonymized cert chains, configs)

## License of contributions

By contributing you agree that your code will be released under AGPL-3.0-only, and that you grant the project owner the right to relicense future versions as required to sustain the project (CLA above).
