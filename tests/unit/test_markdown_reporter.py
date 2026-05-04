"""Tests for pqc_audit.reporters.markdown_reporter — executive Markdown."""

from __future__ import annotations

from datetime import UTC, datetime


def _build_audit_report(*, with_policy_eval: bool = False, with_recs: bool = True):
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

    asset_rsa = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    asset_pqc = CryptoAsset(
        asset_id="tls://pqc.example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="ML-DSA-65"),
        location="pqc.example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    vuln_high = Vulnerability(
        title="Quantum-vulnerable algorithm in use",
        description="RSA-2048 broken by Shor on a CRQC.",
        severity=RiskLevel.HIGH,
        cwe="CWE-327",
        affected_asset_ids=("tls://example.it:443",),
    )
    vuln_low = Vulnerability(
        title="Weak hash advisory",
        description="SHA-1 in TLS chain.",
        severity=RiskLevel.LOW,
        affected_asset_ids=("tls://example.it:443",),
    )
    recs: list[MigrationRecommendation] = []
    if with_recs:
        recs = [
            MigrationRecommendation(
                from_algorithm="RSA-2048",
                to_algorithm="ML-DSA-65",
                rationale="NIST FIPS 204 replacement",
                priority=4,
                hybrid_intermediate="ECDSA-P256+ML-DSA-65",
            )
        ]
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset_rsa, asset_pqc],
        vulnerabilities=[vuln_high, vuln_low],
        started_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 4, 12, 0, 5, tzinfo=UTC),
    )
    metadata: dict = {}
    if with_policy_eval:
        metadata["policy_evaluation"] = {
            "overall_verdict": "FAIL",
            "policy_name": "agid_2026",
            "total_assets_evaluated": 2,
            "compliant_assets": 1,
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
    return AuditReport(
        report_id="audit-2026-001",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=recs,
        generated_at=datetime(2026, 5, 4, 12, 0, 10, tzinfo=UTC),
        metadata=metadata,
    )


def test_markdown_reporter_returns_str() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report())
    assert isinstance(out, str)
    assert len(out) > 0


def test_markdown_reporter_contains_header_and_tool_name() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report())
    assert "pqc-audit-italia" in out
    assert "audit-2026-001" in out


def test_markdown_reporter_lists_assets_in_table() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report())
    # asset identifier and algorithms appear
    assert "tls://example.it:443" in out
    assert "RSA" in out
    assert "ML-DSA-65" in out
    # at least one Markdown table separator
    assert "|" in out
    assert "---" in out


def test_markdown_reporter_groups_vulnerabilities_by_severity() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report())
    assert "HIGH" in out
    assert "LOW" in out
    assert "Quantum-vulnerable algorithm in use" in out
    assert "Weak hash advisory" in out


def test_markdown_reporter_renders_recommendations_with_priority() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report())
    assert "P4" in out
    assert "RSA-2048" in out
    assert "ML-DSA-65" in out
    assert "ECDSA-P256+ML-DSA-65" in out


def test_markdown_reporter_compliance_section_when_policy_evaluation_present() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report(with_policy_eval=True))
    assert "Compliance" in out
    assert "FAIL" in out
    assert "forbidden_algorithms" in out


def test_markdown_reporter_no_compliance_section_when_evaluation_missing() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report(with_policy_eval=False))
    # Section heading shouldn't appear at all
    assert "## Compliance" not in out


def test_markdown_reporter_handles_empty_recommendations() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report(with_recs=False))
    # Section still rendered with a friendly fallback line
    assert "Raccomandazioni migrazione PQC" in out
