"""Tests for the composable rule_packs module.

Rule packs are *regulation-anchored*, *parametric*, *versioned*
modules that cross-cut profiles. They are distinct from
``pqc_audit.policies`` (legacy end-to-end profiles).

These tests pin the contract before the implementation lands.
"""

from __future__ import annotations

from datetime import date

import pytest


def test_list_bundled_rule_packs_returns_sorted_names() -> None:
    from pqc_audit.rule_packs import list_bundled_rule_packs

    names = list_bundled_rule_packs()
    assert isinstance(names, list)
    assert names == sorted(names)
    assert "nist-core-2026" in names


def test_load_rule_pack_nist_core_2026_has_expected_metadata() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("nist-core-2026")
    assert pack.name == "nist-core-2026"
    assert pack.title
    assert pack.version
    # Verified standard publication dates — these are stable historical
    # facts we anchor the pack to. If the YAML drifts away from them
    # the rule pack is no longer regulation-anchored and this test
    # MUST fail loudly.
    assert pack.effective_dates["fips_203_final"] == date(2024, 8, 13)
    assert pack.effective_dates["fips_204_final"] == date(2024, 8, 13)
    assert pack.effective_dates["fips_205_final"] == date(2024, 8, 13)
    assert pack.provenance.source == "NIST"
    assert pack.provenance.url.startswith("https://csrc.nist.gov/")


def test_load_rule_pack_nist_core_2026_has_pqc_allow_list() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("nist-core-2026")
    allowed = {c.algorithm for c in pack.controls if c.rule_type == "allow"}
    # FIPS 203 KEM
    assert "ML-KEM-768" in allowed
    assert "ML-KEM-1024" in allowed
    # FIPS 204 signatures
    assert "ML-DSA-65" in allowed
    assert "ML-DSA-87" in allowed
    # FIPS 205 hash-based signatures
    assert any(a.startswith("SLH-DSA") for a in allowed)


def test_load_rule_pack_nist_core_2026_deprecates_classical_after_2030() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("nist-core-2026")
    deprecations = [c for c in pack.controls if c.rule_type == "deprecate_after"]
    # NIST IR 8547: classical RSA/ECDSA deprecated 2030, disallowed 2035.
    rsa_2048 = [c for c in deprecations if c.algorithm == "RSA-2048"]
    assert rsa_2048, "expected RSA-2048 in deprecate_after controls"
    assert rsa_2048[0].effective == date(2030, 1, 1)


def test_load_rule_pack_rejects_traversal_names() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    malicious = [
        "../../etc/passwd",
        "..",
        "/etc/shadow",
        "rule\x00pack",
        "rule with space",
        "",
        "rule/pack",
        "rule\\pack",
    ]
    for name in malicious:
        with pytest.raises((ValueError, FileNotFoundError)):
            load_rule_pack(name)


def test_load_rule_pack_unknown_raises_filenotfound() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    with pytest.raises(FileNotFoundError):
        load_rule_pack("does-not-exist-2099")


def test_compile_rule_packs_merges_allow_lists() -> None:
    from pqc_audit.rule_packs import compile_rule_packs

    compiled = compile_rule_packs(["nist-core-2026"])
    # A compiled rule set exposes a stable, deduplicated view of allow
    # / forbid / deprecate sets across all packs.
    assert "ML-KEM-768" in compiled.allowed_algorithms
    assert "ML-DSA-65" in compiled.allowed_algorithms
    # Empty input is allowed (caller may want a noop compile).
    empty = compile_rule_packs([])
    assert empty.allowed_algorithms == set()
    assert empty.forbidden_algorithms == set()


def test_compile_rule_packs_rejects_duplicates() -> None:
    from pqc_audit.rule_packs import compile_rule_packs

    # Idempotent: passing the same pack twice MUST not double-count
    # controls, but it also MUST not crash. We compile the same pack
    # twice and assert the result is identical to a single compile.
    a = compile_rule_packs(["nist-core-2026"])
    b = compile_rule_packs(["nist-core-2026", "nist-core-2026"])
    assert a.allowed_algorithms == b.allowed_algorithms
    assert a.forbidden_algorithms == b.forbidden_algorithms


def test_rule_pack_schema_rejects_missing_provenance() -> None:
    """A rule pack without provenance is not regulation-anchored — reject."""
    from pydantic import ValidationError

    from pqc_audit.rule_packs.schema import RulePack

    with pytest.raises(ValidationError):
        RulePack.model_validate(
            {
                "name": "broken",
                "version": "1.0.0",
                "title": "x",
                "description": "x",
                "effective_dates": {},
                "applies_to": {"asset_categories": ["tls"]},
                "controls": [],
            }
        )


def test_rule_pack_control_severity_must_be_valid() -> None:
    from pydantic import ValidationError

    from pqc_audit.rule_packs.schema import Control

    with pytest.raises(ValidationError):
        Control.model_validate(
            {
                "id": "X-001",
                "description": "x",
                "rule_type": "allow",
                "algorithm": "ML-KEM-768",
                "severity": "BANANA",
            }
        )


def test_load_rule_pack_audit_evidence_emit_2026_has_required_artifacts() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("audit-evidence-emit-2026")
    assert pack.name == "audit-evidence-emit-2026"
    # Evidence requirements drive WHICH artifacts an auditor must emit
    # alongside the report (CBOM, SARIF, SLSA, in-toto).
    artifact_types = {ev.artifact_type for ev in pack.evidence_requirements}
    assert "cbom" in artifact_types
    assert "sarif" in artifact_types
    assert "slsa-provenance" in artifact_types
    assert "in-toto-attestation" in artifact_types


def test_load_rule_pack_audit_evidence_emit_2026_has_format_specs() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("audit-evidence-emit-2026")
    cbom = next(ev for ev in pack.evidence_requirements if ev.artifact_type == "cbom")
    assert cbom.format == "cyclonedx-1.6"
    sarif = next(ev for ev in pack.evidence_requirements if ev.artifact_type == "sarif")
    assert sarif.format == "sarif-2.1.0"


def test_compile_rule_packs_aggregates_evidence_requirements() -> None:
    from pqc_audit.rule_packs import compile_rule_packs

    compiled = compile_rule_packs(["audit-evidence-emit-2026"])
    assert "cbom" in compiled.required_evidence_artifacts
    assert "sarif" in compiled.required_evidence_artifacts


def test_evidence_requirement_rejects_unknown_artifact_type() -> None:
    from pydantic import ValidationError

    from pqc_audit.rule_packs.schema import EvidenceRequirement

    with pytest.raises(ValidationError):
        EvidenceRequirement.model_validate(
            {
                "id": "EV-X",
                "description": "x",
                "artifact_type": "unicorn-attestation",
                "format": "x",
                "severity": "HIGH",
            }
        )
