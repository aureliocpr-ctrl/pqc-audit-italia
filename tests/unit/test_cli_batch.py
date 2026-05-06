"""Tests for the `pqc-audit batch` subcommand and its helpers.

Exercises the CLI surface (argparse-style options, CSV vs inline
targets, output artefacts, error handling). Heavy network logic is
indirectly covered by the underlying scanners; here we point at
``127.0.0.1:1`` to force a fast connection-refused path that still
produces a well-formed Markdown + JSON report.

The pure helpers in :mod:`pqc_audit.batch` are tested directly so
parsing/summarising/rendering can be validated without spinning up
the typer runner or hitting the network.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from pqc_audit import batch as batch_mod
from pqc_audit.cli import app

runner = CliRunner()


# ── Pure helpers ─────────────────────────────────────────────────


def test_parse_inline_targets_default_port() -> None:
    targets = batch_mod.parse_inline_targets("a.example, b.example:8443")
    assert len(targets) == 2
    assert targets[0].host == "a.example" and targets[0].port == 443
    assert targets[1].host == "b.example" and targets[1].port == 8443


def test_parse_inline_targets_skip_empty_chunks() -> None:
    targets = batch_mod.parse_inline_targets("a.example, , , b.example")
    assert [t.host for t in targets] == ["a.example", "b.example"]


def test_parse_csv_minimal_one_column(tmp_path: Path) -> None:
    p = tmp_path / "t.csv"
    p.write_text("host\nx.example\ny.example\n", encoding="utf-8")
    targets = batch_mod.parse_csv(p)
    assert [t.host for t in targets] == ["x.example", "y.example"]
    # Header row "host" must be skipped
    assert all(t.host != "host" for t in targets)


def test_parse_csv_three_columns(tmp_path: Path) -> None:
    p = tmp_path / "t.csv"
    p.write_text(
        "a.example,8443,example.com\nb.example,,b.example\n",
        encoding="utf-8",
    )
    targets = batch_mod.parse_csv(p)
    assert targets[0].host == "a.example"
    assert targets[0].port == 8443
    assert targets[0].scope == "example.com"
    assert targets[1].port == 443  # blank port → default


def test_parse_csv_handles_utf8_bom(tmp_path: Path) -> None:
    """Excel writes a UTF-8 BOM at the start of the file."""
    p = tmp_path / "bom.csv"
    p.write_bytes(b"\xef\xbb\xbfhost\nwww.example.it\n")
    targets = batch_mod.parse_csv(p)
    assert len(targets) == 1, f"BOM swallowed; got {targets!r}"
    assert targets[0].host == "www.example.it"


def test_target_resolved_scope_etld_plus_one() -> None:
    t = batch_mod.Target(host="www.regione.lombardia.it")
    assert t.resolved_scope() == "lombardia.it"


def test_target_resolved_scope_explicit_wins() -> None:
    t = batch_mod.Target(host="api.example.com", scope="example.com")
    assert t.resolved_scope() == "example.com"


def test_summarize_ok_path() -> None:
    fake_report = {
        "scan_results": [
            {
                "assets": [{"algorithm": {"name": "ECDSA", "key_size_bits": 256}}],
                "vulnerabilities": [{"title": "x"}],
            }
        ],
        "metadata": {"risk_summary": {"hndl_max": 100, "qday_max": 80}},
        "recommendations": [{"to_algorithm": "ML-DSA-65", "priority": 5}],
        "policy_evaluation": {"overall_verdict": "PASS", "violations": []},
    }
    row = batch_mod.summarize_one("www.example.it", fake_report)
    assert row["status"] == "ok"
    assert row["algorithm"] == "ECDSA-256"
    assert row["hndl"] == 100
    assert row["policy_verdict"] == "PASS"
    assert row["top_reco"] == "ML-DSA-65"


def test_summarize_error_path() -> None:
    err_report = {"error": "TimeoutError: ..."}
    row = batch_mod.summarize_one("unreachable.example", err_report)
    assert row["status"] == "error"
    assert "TimeoutError" in row["error"]


def test_render_markdown_includes_header_and_table() -> None:
    rows = [
        {
            "host": "ok.example",
            "status": "ok",
            "algorithm": "ECDSA-256",
            "vulns": 1,
            "hndl": 100,
            "qday": 80,
            "policy_verdict": "PASS",
            "violations": 0,
            "top_reco": "ML-DSA-65",
        },
        {"host": "err.example", "status": "error", "error": "Boom"},
    ]
    md = batch_mod.render_markdown(
        rows, policy="agid_2026", sensitivity=15, enforce=False
    )
    assert md.startswith("# Batch PQC audit")
    assert "| Host |" in md
    assert "ok.example" in md and "ECDSA-256" in md
    assert "err.example" in md and "Boom" in md


def test_render_markdown_pqc_zero_emits_p5_warning() -> None:
    rows = [
        {
            "host": "a.example",
            "status": "ok",
            "algorithm": "RSA-2048",
            "vulns": 1,
            "hndl": 100,
            "qday": 80,
            "policy_verdict": "PASS",
            "violations": 0,
            "top_reco": "ML-DSA-65",
        }
    ]
    md = batch_mod.render_markdown(
        rows, policy="agid_2026", sensitivity=15, enforce=False
    )
    assert "P5" in md


# ── End-to-end (typer CliRunner) ─────────────────────────────────


def test_help_shows_batch_subcommand() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "batch" in result.stdout


def test_batch_help_lists_required_options() -> None:
    result = runner.invoke(app, ["batch", "--help"])
    assert result.exit_code == 0
    out = result.stdout
    for opt in ("--csv", "--targets", "--policy", "--out"):
        assert opt in out


def test_batch_inline_targets_writes_md_and_json(tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "batch",
            "--targets", "127.0.0.1:1",
            "--policy", "nist_baseline",
            "--out", str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    md = (out / "batch_report.md").read_text(encoding="utf-8")
    assert "Batch PQC audit" in md
    assert "127.0.0.1" in md
    payload = json.loads((out / "batch_report.json").read_text(encoding="utf-8"))
    assert isinstance(payload, list) and len(payload) == 1
    # The raw payload is either an AuditReport dict (success) or a
    # ``{host, port, error}`` minimal stub (transport failure).
    entry = payload[0]
    assert "scan_results" in entry or "error" in entry


def test_batch_csv_input(tmp_path: Path) -> None:
    csv_path = tmp_path / "t.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "scope"])
        w.writerow(["127.0.0.1", "1", "127.0.0.1"])
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "batch",
            "--csv", str(csv_path),
            "--policy", "nist_baseline",
            "--out", str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert (out / "batch_report.md").exists()
    assert (out / "batch_report.json").exists()


def test_batch_requires_at_least_one_source(tmp_path: Path) -> None:
    """Calling batch with neither --targets nor --csv must fail."""
    result = runner.invoke(app, ["batch", "--out", str(tmp_path / "out")])
    assert result.exit_code != 0
    # Typer surfaces validation as text in stdout (Typer/Click convention).
    haystack = (result.stdout + result.stderr).lower()
    assert "required" in haystack or "must" in haystack or "either" in haystack


def test_batch_csv_handles_utf8_bom(tmp_path: Path) -> None:
    """Excel writes a UTF-8 BOM at the start of the file. Must not be
    treated as part of the first column header."""
    p = tmp_path / "bom.csv"
    p.write_bytes(b"\xef\xbb\xbfhost\n127.0.0.1\n")
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "batch",
            "--csv", str(p),
            "--out", str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads((out / "batch_report.json").read_text(encoding="utf-8"))
    assert isinstance(payload, list) and len(payload) == 1
    # The BOM must NOT have leaked into the Markdown header row.
    md = (out / "batch_report.md").read_text(encoding="utf-8")
    assert "﻿host" not in md
    assert "127.0.0.1" in md
