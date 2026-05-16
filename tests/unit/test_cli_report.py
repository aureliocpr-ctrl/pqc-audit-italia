"""Tests for the ``pqc-audit report`` CLI subcommand."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from pqc_audit.cli import app

runner = CliRunner()


def _audit_report_json() -> str:
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        RiskLevel,
        ScanCategory,
        ScanResult,
        Vulnerability,
    )
    from pqc_audit.reporters.json_reporter import render as render_json

    asset = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    vuln = Vulnerability(
        title="Quantum-vulnerable algorithm in use",
        description="RSA-2048 broken by Shor.",
        severity=RiskLevel.HIGH,
        affected_asset_ids=("tls://example.it:443",),
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=[vuln],
        started_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 4, 12, 0, 5, tzinfo=UTC),
    )
    report = AuditReport(
        report_id="audit-cli-001",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=[],
        generated_at=datetime(2026, 5, 4, 12, 0, 10, tzinfo=UTC),
    )
    return render_json(report, pretty=False)


def test_report_help_lists_formats() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    out = result.stdout
    for fmt in ("json", "markdown", "sarif", "cbom", "pdf"):
        assert fmt in out


def test_report_json_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "scan.json"
    src.write_text(_audit_report_json(), encoding="utf-8")
    dst = tmp_path / "out.json"
    result = runner.invoke(
        app,
        ["report", "--input", str(src), "--format", "json", "--output", str(dst)],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(dst.read_text(encoding="utf-8"))
    assert parsed["report_id"] == "audit-cli-001"


def test_report_markdown_to_stdout(tmp_path: Path) -> None:
    src = tmp_path / "scan.json"
    src.write_text(_audit_report_json(), encoding="utf-8")
    result = runner.invoke(
        app,
        ["report", "--input", str(src), "--format", "markdown"],
    )
    assert result.exit_code == 0, result.stdout
    assert "pqc-audit-italia" in result.stdout
    assert "audit-cli-001" in result.stdout


def test_report_sarif_emits_valid_json(tmp_path: Path) -> None:
    src = tmp_path / "scan.json"
    src.write_text(_audit_report_json(), encoding="utf-8")
    result = runner.invoke(
        app,
        ["report", "--input", str(src), "--format", "sarif"],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["version"] == "2.1.0"


def test_report_cbom_emits_cyclonedx(tmp_path: Path) -> None:
    src = tmp_path / "scan.json"
    src.write_text(_audit_report_json(), encoding="utf-8")
    result = runner.invoke(
        app,
        ["report", "--input", str(src), "--format", "cbom"],
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"


def test_report_invalid_input_returns_exit_2(tmp_path: Path) -> None:
    src = tmp_path / "broken.json"
    src.write_text("{ this is not valid json", encoding="utf-8")
    result = runner.invoke(app, ["report", "--input", str(src), "--format", "json"])
    assert result.exit_code == 2


def test_report_pdf_to_stdout_errors(tmp_path: Path) -> None:
    """PDF output requires --output (binary content not safe on stdout)."""
    src = tmp_path / "scan.json"
    src.write_text(_audit_report_json(), encoding="utf-8")
    result = runner.invoke(app, ["report", "--input", str(src), "--format", "pdf"])
    assert result.exit_code == 2


def test_report_markdown_preserves_top_level_policy_evaluation(tmp_path: Path) -> None:
    """Regression guard for the 06/05 MAJOR finding: a JSON report with
    a top-level ``policy_evaluation`` (the convention used by ``scan
    tls --enforce``) MUST re-render with the ``## Compliance`` section.

    Before fix 0.2.1 ``_load_audit_report`` dropped the top-level
    ``policy_evaluation`` and the Markdown reporter (which reads
    ``metadata['policy_evaluation']``) silently emitted no compliance
    block — the central ``--enforce → report --format markdown``
    promise was broken with no test catching it.
    """
    src = tmp_path / "scan.json"
    payload = json.loads(_audit_report_json())
    payload["policy_evaluation"] = {
        "overall_verdict": "FAIL",
        "policy_name": "agid_2026",
        "total_assets_evaluated": 1,
        "compliant_assets": 0,
        "non_compliant_assets": 1,
        "violations": [
            {
                "asset_identifier": "tls://example.it:443",
                "rule": "forbidden_algorithms",
                "expected": "none of [RSA-2048]",
                "actual": "RSA-2048",
                "severity": "HIGH",
                "remediation": "Migrate to ML-DSA-65",
            }
        ],
    }
    src.write_text(json.dumps(payload), encoding="utf-8")
    result = runner.invoke(
        app,
        ["report", "--input", str(src), "--format", "markdown"],
    )
    assert result.exit_code == 0, result.stdout
    assert "## Compliance" in result.stdout
    assert "FAIL" in result.stdout
    assert "forbidden_algorithms" in result.stdout
