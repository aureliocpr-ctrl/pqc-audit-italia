"""Tests for pqc_audit.reporters.cbom_reporter — CycloneDX 1.6 CBOM."""

from __future__ import annotations

import json
from datetime import UTC, datetime


def _build_audit_report():
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        KeyMaterial,
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
        key_material=KeyMaterial(
            algorithm="RSA",
            key_size_bits=2048,
            public_key_fingerprint_sha256="a" * 64,
        ),
    )
    asset_pqc_sig = CryptoAsset(
        asset_id="tls://pqc-sig.example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="ML-DSA-87"),
        location="pqc-sig.example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    asset_pqc_kem = CryptoAsset(
        asset_id="tls://pqc-kem.example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="ML-KEM-768"),
        location="pqc-kem.example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    vuln = Vulnerability(
        title="Quantum-vulnerable algorithm in use",
        description="RSA-2048 broken by Shor.",
        severity=RiskLevel.HIGH,
        cwe="CWE-327",
        affected_asset_ids=("tls://example.it:443",),
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset_rsa, asset_pqc_sig, asset_pqc_kem],
        vulnerabilities=[vuln],
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


def test_cbom_reporter_returns_str_valid_json() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    out = render(_build_audit_report())
    assert isinstance(out, str)
    parsed = json.loads(out)
    assert isinstance(parsed, dict)


def test_cbom_reporter_top_level_specversion_1_6() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert parsed["serialNumber"].startswith("urn:uuid:")
    assert parsed["version"] == 1


def test_cbom_reporter_metadata_tool_and_timestamp() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    md = parsed["metadata"]
    assert "timestamp" in md
    tools = md.get("tools")
    # CycloneDX 1.6 supports tools.components[] OR tools[]; we accept either
    if isinstance(tools, dict):
        assert any(t.get("name") == "pqc-audit-italia" for t in tools.get("components", []))
    else:
        assert any(t.get("name") == "pqc-audit-italia" for t in tools)


def test_cbom_reporter_components_count_matches_assets() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    assets = parsed["components"]
    assert len(assets) == 3
    for c in assets:
        assert c["type"] == "cryptographic-asset"
        assert "cryptoProperties" in c
        algo = c["cryptoProperties"].get("algorithmProperties")
        assert algo is not None


def test_cbom_reporter_rsa_marked_quantum_vulnerable() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    rsa = next(c for c in parsed["components"] if "RSA" in c["name"])
    algo = rsa["cryptoProperties"]["algorithmProperties"]
    assert algo["nistQuantumSecurityLevel"] == 0
    assert algo["primitive"] == "signature"


def test_cbom_reporter_ml_dsa_87_nist_category_5() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    ml_dsa = next(c for c in parsed["components"] if c["name"] == "ML-DSA-87")
    algo = ml_dsa["cryptoProperties"]["algorithmProperties"]
    assert algo["nistQuantumSecurityLevel"] == 5
    assert algo["primitive"] == "signature"


def test_cbom_reporter_ml_kem_768_primitive_kex() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    kem = next(c for c in parsed["components"] if c["name"] == "ML-KEM-768")
    algo = kem["cryptoProperties"]["algorithmProperties"]
    assert algo["primitive"] in {"kex", "key-encapsulation"}
    assert algo["nistQuantumSecurityLevel"] == 3


def test_cbom_reporter_vulnerabilities_vex_entry_per_finding() -> None:
    from pqc_audit.reporters.cbom_reporter import render

    parsed = json.loads(render(_build_audit_report()))
    vex = parsed.get("vulnerabilities", [])
    assert len(vex) == 1
    entry = vex[0]
    assert "id" in entry
    affects = entry.get("affects", [])
    assert len(affects) >= 1
    assert "ref" in affects[0]
