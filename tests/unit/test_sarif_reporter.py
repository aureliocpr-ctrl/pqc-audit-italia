"""Tests for pqc_audit.reporters.sarif_reporter — SARIF 2.1.0 output."""

from __future__ import annotations

import json
from datetime import UTC, datetime


def _build_audit_report(*, dup_vuln: bool = False):
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
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
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    vulns = [
        Vulnerability(
            title="Quantum-vulnerable algorithm in use",
            description="RSA-2048 broken by Shor on a CRQC.",
            severity=RiskLevel.HIGH,
            cwe="CWE-327",
            references=("https://csrc.nist.gov/pubs/fips/204",),
            affected_asset_ids=("tls://example.it:443",),
        ),
        Vulnerability(
            title="Weak hash advisory",
            description="SHA-1 in TLS chain.",
            severity=RiskLevel.LOW,
            affected_asset_ids=("tls://example.it:443",),
        ),
        Vulnerability(
            title="Missing OCSP",
            description="Operational concern.",
            severity=RiskLevel.MEDIUM,
            affected_asset_ids=("tls://example.it:443",),
        ),
        Vulnerability(
            title="Critical broken cipher",
            description="Total break.",
            severity=RiskLevel.CRITICAL,
            affected_asset_ids=("tls://example.it:443",),
        ),
    ]
    if dup_vuln:
        # Same algorithm + category should reuse the same ruleId
        vulns.append(
            Vulnerability(
                title="Quantum-vulnerable algorithm (dup)",
                description="RSA-2048 instance #2.",
                severity=RiskLevel.HIGH,
                cwe="CWE-327",
                affected_asset_ids=("tls://example.it:443",),
            )
        )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=vulns,
        started_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 4, 12, 0, 5, tzinfo=UTC),
    )
    return AuditReport(
        report_id="audit-2026-001",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=[],
        generated_at=datetime(2026, 5, 4, 12, 0, 10, tzinfo=UTC),
    )


def test_sarif_reporter_returns_str_valid_json() -> None:
    from pqc_audit.reporters.sarif_reporter import render

    out = render(_build_audit_report())
    assert isinstance(out, str)
    parsed = json.loads(out)
    assert isinstance(parsed, dict)


def test_sarif_reporter_top_level_schema_fields() -> None:
    from pqc_audit.reporters.sarif_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    assert parsed["version"] == "2.1.0"
    assert "$schema" in parsed
    assert "runs" in parsed
    assert isinstance(parsed["runs"], list)
    assert len(parsed["runs"]) == 1


def test_sarif_reporter_tool_driver_metadata() -> None:
    from pqc_audit.reporters.sarif_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "pqc-audit-italia"
    # Some version string is set
    assert "version" in driver and isinstance(driver["version"], str)


def test_sarif_reporter_one_result_per_vulnerability() -> None:
    from pqc_audit.reporters.sarif_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    results = parsed["runs"][0]["results"]
    assert len(results) == 4
    for r in results:
        assert "ruleId" in r
        assert "message" in r and "text" in r["message"]
        assert "level" in r
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_reporter_level_mapping() -> None:
    from pqc_audit.reporters.sarif_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    levels_by_title = {r["properties"]["title"]: r["level"] for r in parsed["runs"][0]["results"]}
    assert levels_by_title["Critical broken cipher"] == "error"
    assert levels_by_title["Quantum-vulnerable algorithm in use"] == "error"
    assert levels_by_title["Missing OCSP"] == "warning"
    assert levels_by_title["Weak hash advisory"] == "note"


def test_sarif_reporter_rules_are_deduplicated() -> None:
    from pqc_audit.reporters.sarif_reporter import render

    parsed = json.loads(render(_build_audit_report(dup_vuln=True)))
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    # Unique ids in the rules array
    assert len(rule_ids) == len(set(rule_ids))
    # The duplicated vulnerability shares ruleId with the original
    results = parsed["runs"][0]["results"]
    rsa_results = [r for r in results if "Quantum-vulnerable" in r["properties"]["title"]]
    assert len({r["ruleId"] for r in rsa_results}) == 1
