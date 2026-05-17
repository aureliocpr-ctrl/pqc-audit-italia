"""CLI tests for the ``pqc-audit hash`` subcommand (Sprint 8 step B).

Closes the verification loop opened by Sprint 8 step A: an external
auditor / regulator reads the published digest, parses the report,
runs ``pqc-audit hash --input report.json`` and hash-compares.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pqc_audit.cli import app

# JSON-producing invocations use the plain runner; --help / error
# panels use a runner with NO_COLOR so ANSI escapes don't fragment
# expected substrings on Linux/macOS CI.
runner = CliRunner()
help_runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"})


def test_cli_hash_prints_64_hex_digest_for_valid_report(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"report_id": "abc", "policy_name": "x"}), encoding="utf-8")
    result = runner.invoke(app, ["hash", "--input", str(report_file)])
    assert result.exit_code == 0, result.stdout
    digest = result.stdout.strip()
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_cli_hash_is_stable_across_runs(tmp_path: Path) -> None:
    report_file = tmp_path / "stable.json"
    report_file.write_text(json.dumps({"x": 1, "y": [2, 3]}), encoding="utf-8")
    first = runner.invoke(app, ["hash", "--input", str(report_file)]).stdout.strip()
    second = runner.invoke(app, ["hash", "--input", str(report_file)]).stdout.strip()
    assert first == second


def test_cli_hash_differs_when_payload_differs(tmp_path: Path) -> None:
    a_file = tmp_path / "a.json"
    b_file = tmp_path / "b.json"
    a_file.write_text(json.dumps({"policy": "agid_2026"}), encoding="utf-8")
    b_file.write_text(json.dumps({"policy": "agid_2027"}), encoding="utf-8")
    a = runner.invoke(app, ["hash", "--input", str(a_file)]).stdout.strip()
    b = runner.invoke(app, ["hash", "--input", str(b_file)]).stdout.strip()
    assert a != b


def test_cli_hash_missing_file_exits_nonzero(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.json"
    result = runner.invoke(app, ["hash", "--input", str(missing)])
    assert result.exit_code != 0
    combined = (result.stdout or "") + (result.stderr or "")
    assert "cannot read" in combined or "error" in combined.lower()


def test_cli_hash_invalid_json_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("this is not json", encoding="utf-8")
    result = runner.invoke(app, ["hash", "--input", str(bad)])
    assert result.exit_code != 0


def test_cli_hash_reads_stdin_with_dash() -> None:
    runner_stdin = CliRunner()
    result = runner_stdin.invoke(app, ["hash", "--input", "-"], input='{"k":1}')
    assert result.exit_code == 0, result.stdout
    digest = result.stdout.strip()
    assert len(digest) == 64


def test_cli_hash_is_listed_in_top_help() -> None:
    """The new subcommand must appear in `pqc-audit --help`."""
    result = help_runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "hash" in result.stdout
