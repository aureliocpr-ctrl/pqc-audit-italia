"""Tests for pqc_audit.cli — typer entry point.

Uses typer.testing.CliRunner to exercise the registered commands
end-to-end, including help text, version, and stub exit codes.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from pqc_audit import __version__
from pqc_audit.cli import app

runner = CliRunner()


def test_help_shows_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    out = result.stdout
    for keyword in ("scan", "report", "cbom", "version"):
        assert keyword in out


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_help() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for keyword in ("tls", "certs", "ssh"):
        assert keyword in result.stdout


def test_scan_certs_stub_exits_2() -> None:
    """certs stub explicitly returns exit code 2 (not yet implemented)."""
    result = runner.invoke(app, ["scan", "certs"])
    assert result.exit_code == 2


def test_scan_ssh_stub_exits_2() -> None:
    result = runner.invoke(app, ["scan", "ssh"])
    assert result.exit_code == 2


def test_scan_tls_against_unreachable_host_returns_valid_json() -> None:
    """`scan tls` always emits a JSON report — even on connection error.
    The report records the per-target error in scan_results[].errors."""
    result = runner.invoke(
        app,
        ["scan", "tls", "--host", "127.0.0.1", "--port", "1", "--compact"],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["report_id"]
    assert parsed["scan_results"]
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "tls"
    # Either 0 assets + non-empty errors (refused/timeout)
    assert sr["assets"] == [] or sr["errors"]


def test_report_stub_exits_2() -> None:
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 2


def test_cbom_stub_exits_2() -> None:
    result = runner.invoke(app, ["cbom"])
    assert result.exit_code == 2
