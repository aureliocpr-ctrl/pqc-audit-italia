# pqc-audit-italia — make targets
#
#   make help        list available targets
#   make test        unit + integration suite
#   make gates       ruff + ruff format + mypy + bandit + tests (CI parity)
#   make build       wheel + sdist into dist/
#   make publish-test    upload to TestPyPI (twine, requires creds)
#   make publish     upload to PyPI (twine, requires creds)

.PHONY: help test gates build publish-test publish clean

help:
	@echo "pqc-audit-italia — make targets"
	@echo "  make test            unit + integration suite"
	@echo "  make gates           ruff + format + mypy + bandit + tests"
	@echo "  make build           wheel + sdist → dist/"
	@echo "  make publish-test    twine upload to TestPyPI"
	@echo "  make publish         twine upload to PyPI"
	@echo "  make clean           rm dist/ build/ *.egg-info coverage.xml"

test:
	python -m pytest --tb=short

gates:
	@echo "→ ruff check"
	python -m ruff check .
	@echo "→ ruff format check"
	python -m ruff format --check .
	@echo "→ mypy strict"
	python -m mypy pqc_audit/ --strict
	@echo "→ bandit"
	python -m bandit -r pqc_audit/ -ll
	@echo "→ pytest"
	python -m pytest -q --tb=line
	@echo "All gates green."

build:
	python -m build --wheel --sdist
	@echo ""
	@echo "Built artefacts in dist/:"
	@ls -la dist/

publish-test:
	@echo "Uploading to TestPyPI..."
	python -m twine upload --repository testpypi dist/pqc_audit_italia-*.whl dist/pqc_audit_italia-*.tar.gz

publish:
	@echo "Uploading to PyPI..."
	python -m twine upload dist/pqc_audit_italia-*.whl dist/pqc_audit_italia-*.tar.gz

clean:
	rm -rf dist/ build/ *.egg-info coverage.xml .pytest_cache .mypy_cache .ruff_cache
	@echo "Clean."
