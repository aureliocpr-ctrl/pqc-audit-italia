"""Allow ``python -m pqc_audit ...`` as an alternative to the ``pqc-audit`` entry point.

Useful when the package is importable but the ``pqc-audit`` console
script has not been installed (e.g. ``pip install --target`` layouts,
zip apps, or a clean checkout without ``pip install -e .``).
"""

from __future__ import annotations

from pqc_audit.cli import app

if __name__ == "__main__":
    app()
