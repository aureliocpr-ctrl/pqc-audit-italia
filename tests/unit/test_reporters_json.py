"""Tests for pqc_audit.reporters.json_reporter — JSON serialization."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest


def _build_audit_report():
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        MigrationRecommendation,
        RiskLevel,
        ScanCategory,
        ScanResult,
        Vulnerability,
    )

    asset = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc),
    )
    vuln = Vulnerability(
        title="Quantum-vulnerable algorithm in use",
        description="RSA-2048 broken by Shor on a CRQC.",
        severity=RiskLevel.HIGH,
        cwe="CWE-327",
        affected_asset_ids=("tls://example.it:443",),
    )
    rec = MigrationRecommendation(
        from_algorithm="RSA-2048",
        to_algorithm="ML-DSA-65",
        rationale="NIST FIPS 204 replacement",
        priority=4,
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=[vuln],
        started_at=datetime(2026, 5, 4, 12, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 4, 12, 0, 5, tzinfo=timezone.utc),
    )
    return AuditReport(
        report_id="audit-2026-001",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=[rec],
        generated_at=datetime(2026, 5, 4, 12, 0, 10, tzinfo=timezone.utc),
    )


def test_json_reporter_returns_str() -> None:
    from pqc_audit.reporters.json_reporter import render

    out = render(_build_audit_report())
    assert isinstance(out, str)


def test_json_reporter_valid_json() -> None:
    from pqc_audit.reporters.json_reporter import render

    out = render(_build_audit_report())
    parsed = json.loads(out)
    assert isinstance(parsed, dict)


def test_json_reporter_top_level_keys() -> None:
    from pqc_audit.reporters.json_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    for k in ("report_id", "policy_name", "scan_results", "recommendations", "generated_at", "summary"):
        assert k in parsed


def test_json_reporter_summary_counts() -> None:
    from pqc_audit.reporters.json_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    summary = parsed["summary"]
    assert summary["total_assets"] == 1
    assert summary["total_vulnerabilities"] == 1
    assert summary["highest_severity"] == "HIGH"


def test_json_reporter_pretty_default_true() -> None:
    from pqc_audit.reporters.json_reporter import render

    out = render(_build_audit_report())
    # Pretty default contains a newline + indentation
    assert "\n  " in out


def test_json_reporter_compact_when_pretty_false() -> None:
    from pqc_audit.reporters.json_reporter import render

    out = render(_build_audit_report(), pretty=False)
    assert "\n" not in out


def test_json_reporter_severity_serialized_as_name() -> None:
    from pqc_audit.reporters.json_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    sev = parsed["scan_results"][0]["vulnerabilities"][0]["severity"]
    assert sev == "HIGH"


def test_json_reporter_datetime_iso_format() -> None:
    from pqc_audit.reporters.json_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    ts = parsed["generated_at"]
    # ISO 8601 with timezone
    assert "T" in ts
    assert ts.endswith("+00:00") or ts.endswith("Z")


def test_json_reporter_round_trips_to_dict() -> None:
    from pqc_audit.reporters.json_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    # No bytes / sets / non-JSON types leaked through
    assert json.dumps(parsed)
