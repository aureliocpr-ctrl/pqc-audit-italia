"""Smoke tests — package importable, version present, CLI registers."""

from __future__ import annotations


def test_package_imports() -> None:
    import pqc_audit

    assert hasattr(pqc_audit, "__version__")
    assert isinstance(pqc_audit.__version__, str)
    assert pqc_audit.__version__.count(".") >= 2


def test_subpackages_import() -> None:
    import importlib

    for name in (
        "pqc_audit.core",
        "pqc_audit.scanners",
        "pqc_audit.classifiers",
        "pqc_audit.reporters",
        "pqc_audit.policies",
        "pqc_audit.cli",
    ):
        importlib.import_module(name)


def test_cli_app_exists() -> None:
    from pqc_audit.cli import app

    assert app is not None
    # typer.Typer instance has registered commands
    assert hasattr(app, "registered_commands")
