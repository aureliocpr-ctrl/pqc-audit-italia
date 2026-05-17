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


# --- Sprint 4 #2 — four additional regulation-anchored packs ----------


def test_load_rule_pack_eu_crypto_regulatory_2026_anchors_cra_dora_eidas2() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("eu-crypto-regulatory-2026")
    assert pack.name == "eu-crypto-regulatory-2026"
    # CRA Regulation (EU) 2024/2847 entered into force 2024-12-10 and
    # becomes fully applicable to products 2027-12-11 — both anchored.
    assert pack.effective_dates["cra_in_force"] == date(2024, 12, 10)
    assert pack.effective_dates["cra_full_application"] == date(2027, 12, 11)
    # DORA Regulation (EU) 2022/2554 applied 2025-01-17.
    assert pack.effective_dates["dora_applied"] == date(2025, 1, 17)
    # eIDAS2 Regulation (EU) 2024/1183 entered into force 2024-05-20.
    assert pack.effective_dates["eidas2_in_force"] == date(2024, 5, 20)
    # Provenance must reference an EUR-Lex URL so the regulatory
    # anchor is non-repudiable.
    assert "eur-lex.europa.eu" in pack.provenance.url


def test_eu_crypto_regulatory_2026_discourages_classical_before_2030() -> None:
    """ENISA hybrid-first path discourages RSA/ECDSA earlier than NIST IR 8547."""
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("eu-crypto-regulatory-2026")
    discouraged = {c.algorithm for c in pack.controls if c.rule_type == "discourage"}
    assert "RSA-2048" in discouraged
    assert "ECDSA-P-256" in discouraged


def test_load_rule_pack_it_recepimento_nis2_2026_anchors_dlgs_138() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("it-recepimento-nis2-2026")
    assert pack.name == "it-recepimento-nis2-2026"
    # D.Lgs. 138/2024 published in GU on 2024-10-01.
    assert pack.effective_dates["dlgs_138_2024_gu"] == date(2024, 10, 1)
    # ACN established by DL 82/2021 — 2021-08-04.
    assert pack.effective_dates["acn_competent_authority"] == date(2021, 8, 4)
    # Banca d'Italia Circolare 285 first edition.
    assert pack.effective_dates["bdi_circ_285_first"] == date(2013, 12, 17)
    # Provenance includes normattiva.it canonical link.
    assert "normattiva.it" in pack.provenance.url


def test_it_recepimento_nis2_forbids_md5_sha1_rsa1024_3des_rc4() -> None:
    """NIS2 essential entities cannot keep legacy primitives in scope."""
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("it-recepimento-nis2-2026")
    forbidden = {c.algorithm for c in pack.controls if c.rule_type == "forbid"}
    assert {"MD5", "SHA-1", "RSA-1024", "3DES", "RC4"}.issubset(forbidden)


def test_load_rule_pack_agid_absc_2026_anchors_ict_baseline() -> None:
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("agid-absc-2026")
    assert pack.name == "agid-absc-2026"
    # AGID Circolare 2/2017 (Misure minime ICT) — 2017-04-18.
    assert pack.effective_dates["agid_circ_2_2017"] == date(2017, 4, 18)
    assert pack.provenance.source.startswith("AGID")


def test_agid_absc_2026_allows_pqc_baseline_for_pa_procurement() -> None:
    """PA capitolato 2026+ defaults to ML-KEM-768 + ML-DSA-65."""
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("agid-absc-2026")
    allowed = {c.algorithm for c in pack.controls if c.rule_type == "allow"}
    assert "ML-KEM-768" in allowed
    assert "ML-DSA-65" in allowed


def test_load_rule_pack_fips_strict_2026_forbids_classical_no_transition() -> None:
    """STRICT variant forbids RSA/ECC outright (no 2030 transition window)."""
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("fips-203-204-205-strict-2026")
    assert pack.name == "fips-203-204-205-strict-2026"
    forbidden = {c.algorithm for c in pack.controls if c.rule_type == "forbid"}
    # Classical RSA / ECC must be in FORBID (not in deprecate_after) —
    # the whole point of STRICT mode.
    assert "RSA-2048" in forbidden
    assert "RSA-3072" in forbidden
    assert "ECDSA-P-256" in forbidden
    assert "ECDSA-P-384" in forbidden
    assert "ECDH-P-256" in forbidden
    # And RSA-2048 must NOT be in deprecate_after under STRICT mode.
    deprecate = {c.algorithm for c in pack.controls if c.rule_type == "deprecate_after"}
    assert "RSA-2048" not in deprecate


def test_fips_strict_2026_references_cnsa_2_0() -> None:
    """STRICT pack is rationalised by the NSA CNSA 2.0 timeline."""
    from pqc_audit.rule_packs import load_rule_pack

    pack = load_rule_pack("fips-203-204-205-strict-2026")
    assert "CNSA 2.0" in pack.provenance.source or "media.defense.gov" in pack.provenance.url
    assert pack.effective_dates["cnsa_2_0_published"] == date(2022, 9, 7)


def test_list_bundled_rule_packs_includes_all_six() -> None:
    """After Sprint 4 #2 the bundled set is exactly six packs."""
    from pqc_audit.rule_packs import list_bundled_rule_packs

    names = set(list_bundled_rule_packs())
    expected = {
        "nist-core-2026",
        "audit-evidence-emit-2026",
        "eu-crypto-regulatory-2026",
        "it-recepimento-nis2-2026",
        "agid-absc-2026",
        "fips-203-204-205-strict-2026",
    }
    assert expected.issubset(names), f"missing packs: {expected - names}"


def test_compile_rule_packs_strict_overlays_classical_forbid() -> None:
    """STRICT + nist-core merged: RSA-2048 is added to the forbidden set.

    Documented behaviour of CompiledRuleSet: ``forbid`` and
    ``deprecate_after`` are independent buckets and the merge is
    additive — STRICT does NOT erase the lenient deprecate_after entry,
    it adds RSA-2048 to ``forbidden_algorithms`` as well. Callers
    enforcing STRICT must read ``forbidden_algorithms`` first; the
    presence of an algorithm there is a hard fail regardless of any
    deprecate_after window.
    """
    from pqc_audit.rule_packs import compile_rule_packs

    compiled = compile_rule_packs(
        ["nist-core-2026", "fips-203-204-205-strict-2026"]
    )
    assert "RSA-2048" in compiled.forbidden_algorithms
    # The lenient-only compile keeps RSA-2048 out of forbidden.
    lenient = compile_rule_packs(["nist-core-2026"])
    assert "RSA-2048" not in lenient.forbidden_algorithms
    assert "RSA-2048" in lenient.deprecate_after


def test_compile_rule_packs_eu_plus_italian_layered_compliance() -> None:
    """Italian PA tender: EU + IT + AGID layered into a single compiled set."""
    from pqc_audit.rule_packs import compile_rule_packs

    compiled = compile_rule_packs(
        [
            "eu-crypto-regulatory-2026",
            "it-recepimento-nis2-2026",
            "agid-absc-2026",
        ]
    )
    # Italian PA NIS2 + EU CRA + AGID procurement = the three legacy
    # primitives must all surface in the forbidden set.
    assert {"MD5", "SHA-1", "RSA-1024", "3DES", "RC4"}.issubset(
        compiled.forbidden_algorithms
    )
    # ML-KEM-768 must remain explicitly allowed.
    assert "ML-KEM-768" in compiled.allowed_algorithms
