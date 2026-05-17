"""Tests for pqc_audit.core.models — pydantic v2 data models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


def test_risk_level_ordered() -> None:
    from pqc_audit.core.models import RiskLevel

    assert RiskLevel.INFO < RiskLevel.LOW
    assert RiskLevel.LOW < RiskLevel.MEDIUM
    assert RiskLevel.MEDIUM < RiskLevel.HIGH
    assert RiskLevel.HIGH < RiskLevel.CRITICAL


def test_risk_level_from_string() -> None:
    from pqc_audit.core.models import RiskLevel

    assert RiskLevel.parse("critical") is RiskLevel.CRITICAL
    assert RiskLevel.parse("HIGH") is RiskLevel.HIGH
    assert RiskLevel.parse("Medium") is RiskLevel.MEDIUM
    assert RiskLevel.parse("unknown") is RiskLevel.INFO  # safe default


def test_scan_category_enum() -> None:
    from pqc_audit.core.models import ScanCategory

    # Sprint 9j.3 added DATABASE for PostgreSQL/MySQL SSL probes.
    expected = {"NETWORK", "FILESYSTEM", "BINARY", "CODE", "CONFIG", "DATABASE"}
    assert {c.name for c in ScanCategory} == expected


def test_algorithm_minimal_construction() -> None:
    from pqc_audit.core.models import Algorithm

    alg = Algorithm(name="RSA", key_size_bits=2048)
    assert alg.name == "RSA"
    assert alg.key_size_bits == 2048
    assert alg.canonical_name == "RSA-2048"


def test_algorithm_canonical_name_no_keysize() -> None:
    from pqc_audit.core.models import Algorithm

    alg = Algorithm(name="ML-KEM-768")
    assert alg.canonical_name == "ML-KEM-768"


def test_key_material_fingerprint_required() -> None:
    from pqc_audit.core.models import KeyMaterial

    km = KeyMaterial(
        algorithm="RSA",
        key_size_bits=2048,
        public_key_fingerprint_sha256="a" * 64,
    )
    assert km.algorithm == "RSA"
    assert km.public_key_fingerprint_sha256.startswith("a")


def test_key_material_rejects_short_fingerprint() -> None:
    from pydantic import ValidationError

    from pqc_audit.core.models import KeyMaterial

    with pytest.raises(ValidationError):
        KeyMaterial(
            algorithm="RSA",
            key_size_bits=2048,
            public_key_fingerprint_sha256="short",
        )


def test_crypto_asset_basic() -> None:
    from pqc_audit.core.models import (
        Algorithm,
        CryptoAsset,
        ScanCategory,
    )

    asset = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=datetime.now(UTC),
    )
    assert asset.asset_id == "tls://example.it:443"
    assert asset.category is ScanCategory.NETWORK
    assert asset.algorithm.name == "RSA"


def test_vulnerability_default_severity_info() -> None:
    from pqc_audit.core.models import RiskLevel, Vulnerability

    vuln = Vulnerability(
        title="MD5 in cert chain",
        description="Intermediate CA signed with MD5.",
    )
    assert vuln.severity is RiskLevel.INFO


def test_migration_recommendation_priority_range() -> None:
    from pydantic import ValidationError

    from pqc_audit.core.models import MigrationRecommendation

    rec = MigrationRecommendation(
        from_algorithm="RSA-2048",
        to_algorithm="ML-KEM-768",
        rationale="quantum-vulnerable, NIST FIPS 203 replacement",
        priority=3,
    )
    assert rec.priority == 3

    with pytest.raises(ValidationError):
        MigrationRecommendation(
            from_algorithm="x",
            to_algorithm="y",
            rationale="z",
            priority=99,  # out of 1-5
        )


def test_scan_result_aggregates_assets() -> None:
    from pqc_audit.core.models import (
        Algorithm,
        CryptoAsset,
        ScanCategory,
        ScanResult,
    )

    a = CryptoAsset(
        asset_id="x",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="x",
        discovered_at=datetime.now(UTC),
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[a],
        vulnerabilities=[],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    assert sr.scanner_name == "tls"
    assert len(sr.assets) == 1


def test_audit_report_aggregate() -> None:
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        ScanCategory,
        ScanResult,
    )

    a = CryptoAsset(
        asset_id="x",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="x",
        discovered_at=datetime.now(UTC),
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[a],
        vulnerabilities=[],
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    ar = AuditReport(
        report_id="audit-001",
        scan_results=[sr],
        policy_name="agid_2026",
        generated_at=datetime.now(UTC),
    )
    assert ar.report_id == "audit-001"
    assert ar.total_assets == 1
    assert ar.total_vulnerabilities == 0
