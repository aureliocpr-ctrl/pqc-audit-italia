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


def test_run_batch_concurrency_caps_in_flight(monkeypatch) -> None:
    """With ``concurrency=2``, no more than 2 ``run_one`` coroutines
    should be in flight at once. With the default ``concurrency=1``
    the in-flight counter must never exceed 1."""

    import asyncio

    in_flight = {"now": 0, "peak": 0}

    async def _fake_run_one(target, **_kw):
        in_flight["now"] += 1
        in_flight["peak"] = max(in_flight["peak"], in_flight["now"])
        await asyncio.sleep(0.05)
        in_flight["now"] -= 1
        return {"host": target.host, "scan_results": [{"assets": []}]}

    monkeypatch.setattr(batch_mod, "run_one", _fake_run_one)

    targets = [batch_mod.Target(host=f"h{i}.example") for i in range(6)]

    pairs_seq = asyncio.run(
        batch_mod.run_batch(
            targets, policy="agid_2026", sensitivity=15, enforce=False,
            concurrency=1,
        )
    )
    assert len(pairs_seq) == 6
    assert in_flight["peak"] == 1, (
        f"sequential should keep peak in-flight at 1, got {in_flight['peak']}"
    )

    in_flight["peak"] = 0
    pairs_par = asyncio.run(
        batch_mod.run_batch(
            targets, policy="agid_2026", sensitivity=15, enforce=False,
            concurrency=3,
        )
    )
    assert len(pairs_par) == 6
    # The semaphore must cap parallelism, but it must allow >1.
    assert 1 < in_flight["peak"] <= 3, (
        f"concurrency=3 should cap at 3 (and exceed 1), "
        f"got peak={in_flight['peak']}"
    )

    # Pairing is preserved in both modes.
    assert [t.host for t, _ in pairs_seq] == [t.host for t in targets]
    assert sorted(t.host for t, _ in pairs_par) == sorted(t.host for t in targets)


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


def test_batch_emits_html_report(tmp_path: Path) -> None:
    """The HTML reporter must run alongside Markdown + JSON.

    The CSS / JS goes inline into the same file so the deliverable is
    one self-contained ``.html`` attachment. The unit test for the
    pure renderer covers shape and security; here we just verify
    that the CLI actually wires it in.
    """
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
    assert (out / "batch_report.html").exists()
    html = (out / "batch_report.html").read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "Batch PQC audit" in html
    # The host appears in the rendered table.
    assert "127.0.0.1" in html
    # The CLI tells the user about the new file.
    assert "batch_report.html" in result.stdout


def test_batch_requires_at_least_one_source(tmp_path: Path) -> None:
    """Calling batch with neither --targets nor --csv must fail."""
    result = runner.invoke(app, ["batch", "--out", str(tmp_path / "out")])
    assert result.exit_code != 0
    # Typer surfaces validation as text in stdout (Typer/Click convention).
    haystack = (result.stdout + result.stderr).lower()
    assert "required" in haystack or "must" in haystack or "either" in haystack


def test_batch_fail_on_violations_returns_nonzero_when_fail(tmp_path: Path) -> None:
    """``--fail-on-violations`` is a CI gate: if ANY host has a
    policy_evaluation FAIL, the CLI must exit with code 3 so a
    pipeline can block the build. Uses a stub run_one to inject
    a deterministic FAIL verdict without touching the network."""
    fail_payload = {
        "scan_results": [{
            "assets": [{"algorithm": {"name": "RSA", "key_size_bits": 2048}}],
            "vulnerabilities": [],
        }],
        "metadata": {"risk_summary": {"hndl_max": 100, "qday_max": 80}},
        "recommendations": [{"to_algorithm": "ML-DSA-65", "priority": 5}],
        "policy_evaluation": {
            "overall_verdict": "FAIL",
            "violations": [{"rule": "rsa_forbidden", "asset": "RSA-2048"}],
        },
    }

    async def _fake_run_one(target, **_kw):
        return dict(fail_payload, host=target.host)

    out = tmp_path / "out"
    from unittest.mock import patch
    with patch.object(batch_mod, "run_one", _fake_run_one):
        result = runner.invoke(
            app,
            [
                "batch",
                "--targets", "bad.example",
                "--policy", "agid_2026",
                "--enforce",
                "--fail-on-violations",
                "--out", str(out),
            ],
        )

    # Reports must still be written even when we exit non-zero.
    assert (out / "batch_report.md").exists()
    assert (out / "batch_report.json").exists()
    # Exit code 3 reserved for "policy gate tripped".
    assert result.exit_code == 3, (
        f"expected exit 3 with --fail-on-violations on a FAIL host; "
        f"got {result.exit_code}\n{result.stdout}"
    )


def test_batch_fail_on_violations_zero_when_clean() -> None:
    """When every host passes (no FAIL / no error), the gate
    must exit 0. Uses a stub run_one to avoid network."""
    import json

    pass_payload = {
        "scan_results": [{"assets": [], "vulnerabilities": []}],
        "metadata": {"risk_summary": {"hndl_max": 50, "qday_max": 30}},
        "recommendations": [],
        "policy_evaluation": {"overall_verdict": "PASS", "violations": []},
    }

    async def _fake_run_one(target, **_kw):
        return dict(pass_payload, host=target.host)

    from pqc_audit import batch as _batch_mod

    import tempfile
    import os

    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "out")
        # We can't monkeypatch via CliRunner cleanly, so go straight
        # at the helper layer.
        from unittest.mock import patch
        with patch.object(_batch_mod, "run_one", _fake_run_one):
            result = runner.invoke(
                app,
                [
                    "batch",
                    "--targets", "ok1.example,ok2.example",
                    "--policy", "agid_2026",
                    "--enforce",
                    "--fail-on-violations",
                    "--out", out,
                ],
            )
        assert result.exit_code == 0, (
            f"expected exit 0 when all hosts PASS; got {result.exit_code}\n"
            f"{result.stdout}"
        )
        payload = json.loads(open(os.path.join(out, "batch_report.json"), encoding="utf-8").read())
        assert all(p.get("policy_evaluation", {}).get("overall_verdict") == "PASS"
                   for p in payload), payload


def test_batch_empty_csv_exits_nonzero(tmp_path: Path) -> None:
    """An empty CSV (header-only or zero rows) must NOT silently
    produce an empty report — the CLI must reject the input with
    a clear error message and a non-zero exit code so a CI pipeline
    notices the misconfiguration."""
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("host,port,scope\n", encoding="utf-8")
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "batch",
            "--csv", str(csv_path),
            "--out", str(out),
        ],
    )
    assert result.exit_code != 0, (
        "expected non-zero exit on empty CSV; "
        f"got {result.exit_code}\n{result.stdout}"
    )
    haystack = (result.stdout + (result.stderr or "")).lower()
    assert "no targets" in haystack or "empty" in haystack, (
        f"expected error message about empty input; got: {result.stdout!r}"
    )


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
