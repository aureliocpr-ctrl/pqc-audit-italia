"""Tests for ``pqc-audit scan tls --enforce`` — Phase 5.C CLI integration."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from pqc_audit.cli import app

runner = CliRunner()


def test_scan_tls_enforce_flag_emits_policy_evaluation() -> None:
    """When --enforce is passed, the JSON output carries policy_evaluation."""
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "--host",
            "127.0.0.1",
            "--port",
            "1",
            "--policy",
            "nist_baseline",
            "--enforce",
            "--compact",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert "policy_evaluation" in payload
    pe = payload["policy_evaluation"]
    assert pe["policy_name"] == "nist_baseline"
    assert "overall_verdict" in pe
    assert "violations" in pe
    # Empty scan (port 1 refuses) → zero assets, PASS.
    assert pe["total_assets_evaluated"] == 0
    assert pe["overall_verdict"] == "PASS"


def test_scan_tls_without_enforce_omits_policy_evaluation() -> None:
    """Default behavior unchanged: no --enforce ⇒ no policy_evaluation key."""
    result = runner.invoke(
        app,
        [
            "scan",
            "tls",
            "--host",
            "127.0.0.1",
            "--port",
            "1",
            "--compact",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert "policy_evaluation" not in payload
