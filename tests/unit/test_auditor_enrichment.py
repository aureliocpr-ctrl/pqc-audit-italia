"""Tests for Auditor risk enrichment + auto-generated recommendations.

Phase 1 hardening: the brief acceptance test requires that an audit
report ship with HNDL / Q-Day classification and concrete migration
recommendations, not only raw scan results.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


def _make_asset(algorithm_name: str, key_size: int | None = None):
    from pqc_audit.core.models import Algorithm, CryptoAsset, ScanCategory

    return CryptoAsset(
        asset_id=f"tls://{algorithm_name}",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name=algorithm_name, key_size_bits=key_size),
        location="example.it:443",
        discovered_at=datetime.now(UTC),
    )


def _make_scan_result(*assets):
    from pqc_audit.core.models import ScanResult

    now = datetime.now(UTC)
    return ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=list(assets),
        vulnerabilities=[],
        started_at=now,
        finished_at=now,
    )


def test_enrich_report_adds_risk_summary() -> None:
    from pqc_audit.auditor import enrich_report
    from pqc_audit.core.models import AuditReport

    asset_vuln = _make_asset("RSA", 2048)
    asset_safe = _make_asset("ML-DSA-65")
    sr = _make_scan_result(asset_vuln, asset_safe)
    report = AuditReport(
        report_id="t1",
        scan_results=[sr],
        policy_name="default",
        generated_at=datetime.now(UTC),
    )

    enriched = enrich_report(report, data_sensitivity_years=10)
    risk = enriched.metadata["risk_summary"]
    assert risk["asset_count"] == 2
    assert risk["vulnerable_count"] == 1
    assert risk["resistant_count"] == 1
    assert risk["hndl_max"] >= 70
    assert risk["qday_max"] >= 70


def test_enrich_report_generates_recommendations_for_vulnerable() -> None:
    from pqc_audit.auditor import enrich_report
    from pqc_audit.core.models import AuditReport

    sr = _make_scan_result(_make_asset("RSA", 2048))
    report = AuditReport(
        report_id="t2",
        scan_results=[sr],
        policy_name="default",
        generated_at=datetime.now(UTC),
    )

    enriched = enrich_report(report, data_sensitivity_years=10)
    assert len(enriched.recommendations) == 1
    rec = enriched.recommendations[0]
    assert rec.from_algorithm == "RSA-2048"
    assert rec.to_algorithm.startswith("ML-")
    assert rec.priority >= 4  # high urgency for quantum-vulnerable + long lifetime
    assert rec.hybrid_intermediate is not None  # transition guidance


def test_enrich_no_recommendation_for_resistant() -> None:
    from pqc_audit.auditor import enrich_report
    from pqc_audit.core.models import AuditReport

    sr = _make_scan_result(_make_asset("ML-KEM-768"))
    report = AuditReport(
        report_id="t3",
        scan_results=[sr],
        policy_name="default",
        generated_at=datetime.now(UTC),
    )

    enriched = enrich_report(report, data_sensitivity_years=10)
    assert enriched.recommendations == []


def test_enrich_dedupes_recommendations_per_algorithm() -> None:
    """Multiple RSA-2048 assets produce ONE recommendation, not N."""
    from pqc_audit.auditor import enrich_report
    from pqc_audit.core.models import AuditReport

    sr = _make_scan_result(
        _make_asset("RSA", 2048),
        _make_asset("RSA", 2048),
        _make_asset("RSA", 2048),
    )
    report = AuditReport(
        report_id="t4",
        scan_results=[sr],
        policy_name="default",
        generated_at=datetime.now(UTC),
    )
    enriched = enrich_report(report, data_sensitivity_years=10)
    assert len(enriched.recommendations) == 1


@pytest.mark.parametrize(
    "alg_name,expected_hybrid",
    [
        ("RSA", "RSA-3072+ML-DSA-65"),
        ("ECDSA", "ECDSA-P256+ML-DSA-65"),
        ("EdDSA", "ECDSA-P256+ML-DSA-65"),
        ("Ed25519", "ECDSA-P256+ML-DSA-65"),
        ("Ed448", "ECDSA-P256+ML-DSA-65"),
    ],
)
def test_hybrid_for_signature_primitives_returns_signature_hybrid(
    alg_name: str, expected_hybrid: str
) -> None:
    """EdDSA / Ed25519 / Ed448 are signature primitives — their hybrid
    intermediate MUST be a signature scheme (ML-DSA), not a KEM
    (ML-KEM). Before fix 0.2.1, EdDSA fell into the generic ``next()``
    fallback and was mapped to ``X25519+ML-KEM-768`` — a KEM,
    semantically wrong for a signing migration plan.
    """
    from pqc_audit.auditor import _hybrid_for

    assert _hybrid_for(alg_name) == expected_hybrid


@pytest.mark.asyncio
async def test_auditor_scan_returns_enriched_report() -> None:
    """End-to-end: Auditor.scan() output already contains risk summary
    and recommendations, no manual enrich step needed."""
    from pqc_audit import Auditor, ScanTarget

    a = Auditor(data_sensitivity_years=15)
    target = ScanTarget(type="tls", host="127.0.0.1", port=1)  # unreachable, fast
    report = await a.scan([target])
    # Even with zero assets discovered, metadata must contain the summary.
    assert "risk_summary" in report.metadata
    assert "data_sensitivity_years" in report.metadata
    assert report.metadata["data_sensitivity_years"] == 15
