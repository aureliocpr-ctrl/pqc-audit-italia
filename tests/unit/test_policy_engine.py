"""Tests for pqc_audit.policy_engine — Phase 5 enforcement layer.

The engine takes an :class:`AuditReport` (or a list of
:class:`CryptoAsset`) and a loaded policy dict, and produces a
:class:`PolicyEvaluation` with per-asset violations.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


def _ts() -> datetime:
    return datetime(2026, 5, 4, 12, 0, 0, tzinfo=UTC)


def _make_asset(
    *,
    asset_id: str = "tls://example.it:443",
    name: str = "RSA",
    key_size: int | None = 2048,
    curve: str | None = None,
    tls_version: str | None = "TLSv1.2",
    sig_hash: str | None = "SHA-256",
):
    """Factory: minimal CryptoAsset with metadata fields used by the engine."""
    from pqc_audit.core.models import Algorithm, CryptoAsset, ScanCategory

    md: dict[str, object] = {}
    if tls_version is not None:
        md["tls_version"] = tls_version
    if sig_hash is not None:
        md["signature_hash"] = sig_hash
    return CryptoAsset(
        asset_id=asset_id,
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name=name, key_size_bits=key_size, curve=curve),
        location=asset_id.replace("tls://", ""),
        discovered_at=_ts(),
        metadata=md,
    )


# ---------------------------------------------------------------------------
# Forbidden algorithms
# ---------------------------------------------------------------------------


def test_forbidden_md5_against_agid_2026_yields_violation() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("agid_2026")
    asset = _make_asset(name="MD5", key_size=128)
    eval_ = evaluate_assets([asset], policy)
    rules = [v.rule for v in eval_.violations]
    assert "forbidden_algorithms" in rules
    # MD5 is also a deprecated hash, but the FIRST class hit is forbidden.
    md5_v = next(v for v in eval_.violations if v.rule == "forbidden_algorithms")
    assert "MD5" in md5_v.actual.upper()
    assert eval_.overall_verdict == "FAIL"


def test_rsa_2048_against_pa_critical_is_forbidden() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("pa_critical")
    asset = _make_asset(name="RSA", key_size=2048, tls_version="TLSv1.3")
    eval_ = evaluate_assets([asset], policy)
    forbidden = [v for v in eval_.violations if v.rule == "forbidden_algorithms"]
    assert forbidden, eval_.violations
    assert "RSA-2048" in forbidden[0].actual


# ---------------------------------------------------------------------------
# Minimum key sizes
# ---------------------------------------------------------------------------


def test_rsa_2048_against_nist_baseline_passes_min_size() -> None:
    """nist_baseline forbids RSA-1024 but accepts RSA-2048."""
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    asset = _make_asset(name="RSA", key_size=2048, tls_version="TLSv1.2")
    eval_ = evaluate_assets([asset], policy)
    # RSA-2048 IS NOT in nist_baseline forbidden list.
    forbidden_rules = [v for v in eval_.violations if v.rule == "forbidden_algorithms"]
    assert not forbidden_rules, eval_.violations


def test_rsa_1024_against_nist_baseline_violates_forbidden() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    asset = _make_asset(name="RSA", key_size=1024, tls_version="TLSv1.2")
    eval_ = evaluate_assets([asset], policy)
    assert any(v.rule == "forbidden_algorithms" for v in eval_.violations)


def test_required_minimum_key_size_explicit_rule() -> None:
    """Explicit ``required_minimum_key_size`` triggers undersized violation."""
    from pqc_audit.policy_engine import PolicyViolation, evaluate_assets

    policy = {
        "name": "custom",
        "description": "custom",
        "required_minimum_key_size": {"RSA": 4096},
    }
    asset = _make_asset(name="RSA", key_size=2048)
    eval_ = evaluate_assets([asset], policy)
    matches = [v for v in eval_.violations if v.rule == "required_minimum_key_size"]
    assert matches and isinstance(matches[0], PolicyViolation)
    assert "4096" in matches[0].expected
    assert "2048" in matches[0].actual


# ---------------------------------------------------------------------------
# Minimum TLS version
# ---------------------------------------------------------------------------


def test_tls10_against_pa_critical_violates_min_tls() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("pa_critical")
    # ECDSA-P-384 is not forbidden in pa_critical; TLS 1.0 IS.
    asset = _make_asset(
        name="ECDSA",
        key_size=384,
        curve="secp384r1",
        tls_version="TLSv1.0",
    )
    eval_ = evaluate_assets([asset], policy)
    tls_v = [v for v in eval_.violations if v.rule == "minimum_tls_version"]
    assert tls_v, eval_.violations
    assert "TLSv1.3" in tls_v[0].expected
    assert "1.0" in tls_v[0].actual


def test_tls13_against_pa_critical_passes_tls() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("pa_critical")
    asset = _make_asset(
        name="ECDSA",
        key_size=384,
        curve="secp384r1",
        tls_version="TLSv1.3",
    )
    eval_ = evaluate_assets([asset], policy)
    assert not [v for v in eval_.violations if v.rule == "minimum_tls_version"]


# ---------------------------------------------------------------------------
# Required signature hash minimum
# ---------------------------------------------------------------------------


def test_signature_sha1_against_banking_italy_violates() -> None:
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "banking_italy_test",
        "description": "test",
        "required_signature_hash_minimum": "SHA-256",
        "forbidden_algorithms": ["SHA-1"],
    }
    asset = _make_asset(name="ECDSA", key_size=256, sig_hash="SHA-1")
    eval_ = evaluate_assets([asset], policy)
    sig_v = [v for v in eval_.violations if v.rule == "required_signature_hash_minimum"]
    assert sig_v, eval_.violations
    assert "SHA-256" in sig_v[0].expected
    assert "SHA-1" in sig_v[0].actual


def test_signature_sha256_meets_sha256_minimum() -> None:
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "test",
        "description": "test",
        "required_signature_hash_minimum": "SHA-256",
    }
    asset = _make_asset(name="ECDSA", key_size=256, sig_hash="SHA-256")
    eval_ = evaluate_assets([asset], policy)
    assert not [v for v in eval_.violations if v.rule == "required_signature_hash_minimum"]


# ---------------------------------------------------------------------------
# Hybrid acceptable
# ---------------------------------------------------------------------------


def test_hybrid_acceptable_default_allows_hybrid_scheme() -> None:
    from pqc_audit.policy_engine import evaluate_assets

    policy = {"name": "t", "description": "t"}
    asset = _make_asset(name="X25519+ML-KEM-768", key_size=None, sig_hash=None)
    eval_ = evaluate_assets([asset], policy)
    # Default hybrid_acceptable=True → no violation specific to hybrid.
    assert not [v for v in eval_.violations if v.rule == "hybrid_acceptable"]


def test_hybrid_not_acceptable_emits_violation() -> None:
    from pqc_audit.policy_engine import evaluate_assets

    policy = {"name": "t", "description": "t", "hybrid_acceptable": False}
    asset = _make_asset(name="X25519+ML-KEM-768", key_size=None, sig_hash=None)
    eval_ = evaluate_assets([asset], policy)
    assert any(v.rule == "hybrid_acceptable" for v in eval_.violations)


# ---------------------------------------------------------------------------
# Verdicts: PASS / FAIL / PARTIAL
# ---------------------------------------------------------------------------


def test_pass_verdict_when_zero_violations() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    asset = _make_asset(
        name="ML-KEM-768",
        key_size=None,
        tls_version="TLSv1.3",
        sig_hash="SHA-256",
    )
    eval_ = evaluate_assets([asset], policy)
    assert eval_.violations == []
    assert eval_.overall_verdict == "PASS"
    assert eval_.compliant_assets == 1
    assert eval_.non_compliant_assets == 0


def test_partial_verdict_when_some_assets_compliant() -> None:
    """Mix: 1 OK + 1 broken → PARTIAL."""
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    ok = _make_asset(
        asset_id="tls://good:443",
        name="ML-DSA-65",
        key_size=None,
        tls_version="TLSv1.3",
        sig_hash="SHA-384",
    )
    broken = _make_asset(
        asset_id="tls://bad:443",
        name="MD5",
        key_size=128,
        tls_version="TLSv1.2",
        sig_hash="MD5",
    )
    eval_ = evaluate_assets([ok, broken], policy)
    assert eval_.compliant_assets == 1
    assert eval_.non_compliant_assets == 1
    assert eval_.overall_verdict == "PARTIAL"


def test_fail_verdict_when_majority_non_compliant() -> None:
    """3 of 3 broken → FAIL."""
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    bad = [_make_asset(asset_id=f"tls://bad{i}:443", name="MD5", key_size=128) for i in range(3)]
    eval_ = evaluate_assets(bad, policy)
    assert eval_.non_compliant_assets == 3
    assert eval_.overall_verdict == "FAIL"


# ---------------------------------------------------------------------------
# Inheritance chain (pa_critical -> agid_2026 -> nist_baseline)
# ---------------------------------------------------------------------------


def test_inheritance_chain_resolved_for_evaluation() -> None:
    """pa_critical inherits forbid list from agid_2026 + adds RSA-3072."""
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("pa_critical")
    # RSA-3072 is forbidden ONLY in pa_critical (added on top of inheritance).
    rsa_3072 = _make_asset(name="RSA", key_size=3072, tls_version="TLSv1.3")
    eval_ = evaluate_assets([rsa_3072], policy)
    forbidden = [v for v in eval_.violations if v.rule == "forbidden_algorithms"]
    assert forbidden, eval_.violations
    assert "3072" in forbidden[0].actual


# ---------------------------------------------------------------------------
# evaluate_report (top-level over AuditReport)
# ---------------------------------------------------------------------------


def test_evaluate_report_aggregates_across_scan_results() -> None:
    from pqc_audit.core.models import AuditReport, ScanResult
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_report

    asset = _make_asset(name="MD5", key_size=128)
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=[],
        started_at=_ts(),
        finished_at=_ts(),
    )
    report = AuditReport(
        report_id="test-1",
        scan_results=[sr],
        policy_name="agid_2026",
        generated_at=_ts(),
    )
    eval_ = evaluate_report(report, load_policy("agid_2026"))
    assert eval_.total_assets_evaluated == 1
    assert eval_.non_compliant_assets == 1
    assert eval_.policy_name == "agid_2026"


def test_evaluate_empty_report_yields_pass() -> None:
    from pqc_audit.core.models import AuditReport
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_report

    report = AuditReport(
        report_id="empty",
        scan_results=[],
        policy_name="nist_baseline",
        generated_at=_ts(),
    )
    eval_ = evaluate_report(report, load_policy("nist_baseline"))
    assert eval_.total_assets_evaluated == 0
    assert eval_.violations == []
    assert eval_.overall_verdict == "PASS"


# ---------------------------------------------------------------------------
# Unknown / extra fields: ignored silently
# ---------------------------------------------------------------------------


def test_unknown_policy_keys_are_ignored_silently() -> None:
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "weird",
        "description": "extra fields",
        "future_field_we_dont_handle": "yolo",
        "extra_controls": {"hsm_required_for_signing_keys": True},
    }
    asset = _make_asset(name="ML-DSA-65", key_size=None)
    eval_ = evaluate_assets([asset], policy)
    # No crash, no violation tied to the unknown key.
    assert all(v.rule != "future_field_we_dont_handle" for v in eval_.violations)


# ---------------------------------------------------------------------------
# Pydantic model contract
# ---------------------------------------------------------------------------


def test_policy_evaluation_model_is_serializable() -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    asset = _make_asset(name="MD5", key_size=128)
    eval_ = evaluate_assets([asset], policy)
    payload = eval_.model_dump()
    assert payload["policy_name"] == "nist_baseline"
    assert isinstance(payload["violations"], list)
    assert payload["violations"][0]["asset_identifier"]


def test_violation_severity_is_risklevel() -> None:
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("nist_baseline")
    asset = _make_asset(name="MD5", key_size=128)
    eval_ = evaluate_assets([asset], policy)
    assert eval_.violations
    assert isinstance(eval_.violations[0].severity, RiskLevel)


# ---------------------------------------------------------------------------
# Discouraged algorithms (MEDIUM, sibling of forbidden_algorithms)
# ---------------------------------------------------------------------------


def test_discouraged_algorithm_emits_medium_violation() -> None:
    """``discouraged_algorithms`` MUST surface as a MEDIUM violation
    (not blocking, but visible)."""
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "t",
        "description": "t",
        "discouraged_algorithms": ["RSA-2048"],
    }
    asset = _make_asset(name="RSA", key_size=2048, tls_version=None, sig_hash=None)
    eval_ = evaluate_assets([asset], policy)
    matches = [v for v in eval_.violations if v.rule == "discouraged_algorithms"]
    assert matches, eval_.violations
    assert matches[0].severity == RiskLevel.MEDIUM
    assert "RSA-2048" in matches[0].actual


def test_discouraged_algorithm_signature_hash_match() -> None:
    """Discouraged signature hashes (like SHA-256 on a long-term PA
    policy that prefers SHA-384) match via the asset metadata hash field."""
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "t",
        "description": "t",
        "discouraged_algorithms": ["SHA-256"],
    }
    asset = _make_asset(name="ECDSA", key_size=384, curve="secp384r1", sig_hash="SHA-256")
    eval_ = evaluate_assets([asset], policy)
    matches = [v for v in eval_.violations if v.rule == "discouraged_algorithms"]
    assert matches, eval_.violations
    assert matches[0].severity == RiskLevel.MEDIUM


def test_discouraged_does_not_overlap_with_forbidden_severity() -> None:
    """An algorithm in BOTH forbidden + discouraged surfaces both
    rules but the higher-severity forbidden one wins for the verdict."""
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "t",
        "description": "t",
        "forbidden_algorithms": ["MD5"],
        "discouraged_algorithms": ["MD5"],
    }
    asset = _make_asset(name="MD5", key_size=128, sig_hash=None)
    eval_ = evaluate_assets([asset], policy)
    severities = {v.severity for v in eval_.violations}
    assert RiskLevel.HIGH in severities
    assert RiskLevel.MEDIUM in severities


# ---------------------------------------------------------------------------
# Thresholds (hndl_max_score / qday_max_score / min_agility_score)
# ---------------------------------------------------------------------------


def test_thresholds_hndl_max_score_triggers_violation_on_rsa_2048() -> None:
    """An RSA-2048 asset against a tight HNDL ceiling (10) must trip
    the ``thresholds.hndl_max_score`` rule."""
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "tight",
        "description": "tight",
        "data_sensitivity_years": 30,
        "thresholds": {"hndl_max_score": 10},
    }
    asset = _make_asset(name="RSA", key_size=2048, sig_hash=None)
    eval_ = evaluate_assets([asset], policy)
    hndl = [v for v in eval_.violations if v.rule == "thresholds.hndl_max_score"]
    assert hndl, eval_.violations
    assert "<= 10" in hndl[0].expected


def test_thresholds_hndl_max_score_passes_when_quantum_resistant() -> None:
    """ML-KEM-768 has tiny HNDL exposure → no threshold violation."""
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "tight",
        "description": "tight",
        "data_sensitivity_years": 30,
        "thresholds": {"hndl_max_score": 10},
    }
    asset = _make_asset(name="ML-KEM-768", key_size=None, sig_hash=None)
    eval_ = evaluate_assets([asset], policy)
    assert not [v for v in eval_.violations if v.rule == "thresholds.hndl_max_score"]


def test_thresholds_min_agility_score_triggers_on_hardcoded_keys() -> None:
    """A hardcoded primitive (low crypto-agility) trips
    ``thresholds.min_agility_score``."""
    from pqc_audit.core.models import Algorithm, CryptoAsset, ScanCategory
    from pqc_audit.policy_engine import evaluate_assets

    asset = CryptoAsset(
        asset_id="tls://stuck:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="ML-KEM-768"),
        location="stuck:443",
        discovered_at=_ts(),
        metadata={"hardcoded": True, "cert_pinned": True},
    )
    policy = {
        "name": "tight",
        "description": "tight",
        "thresholds": {"min_agility_score": 50},
    }
    eval_ = evaluate_assets([asset], policy)
    agility = [v for v in eval_.violations if v.rule == "thresholds.min_agility_score"]
    assert agility, eval_.violations


def test_pa_critical_yaml_thresholds_actually_enforced() -> None:
    """End-to-end: loading ``pa_critical`` and evaluating RSA-2048
    must trip BOTH forbidden_algorithms AND thresholds.hndl_max_score.

    Before fix 0.2.1 the engine silently ignored every ``thresholds.*``
    key in every bundled YAML.
    """
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    policy = load_policy("pa_critical")
    asset = _make_asset(name="RSA", key_size=2048, tls_version="TLSv1.3")
    eval_ = evaluate_assets([asset], policy)
    rules = {v.rule for v in eval_.violations}
    assert "forbidden_algorithms" in rules
    assert "thresholds.hndl_max_score" in rules


# ---------------------------------------------------------------------------
# Empty-asset guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_name", ["nist_baseline", "agid_2026", "banking_italy", "pa_critical"]
)
def test_evaluate_assets_handles_empty_input(policy_name: str) -> None:
    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets

    eval_ = evaluate_assets([], load_policy(policy_name))
    assert eval_.total_assets_evaluated == 0
    assert eval_.overall_verdict == "PASS"


# ---------------------------------------------------------------------------
# Sprint 6 — rule_packs integration into policy_engine
# ---------------------------------------------------------------------------


def test_policy_with_rule_packs_merges_forbidden_set() -> None:
    """A policy referencing rule_packs must inherit their forbidden_algorithms.

    Before Sprint 6 the rule-pack YAMLs were decorative — policies
    didn't consume them. This test pins the merge contract: ``{"rule_packs":
    ["nist-core-2026"]}`` adds RSA-1024 / MD5 / SHA-1 / 3DES / RC4 to
    the effective forbidden set the engine enforces.
    """
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "rp_test",
        "description": "rule-pack integration probe",
        "data_sensitivity_years": 10,
        "rule_packs": ["nist-core-2026"],
    }
    asset = _make_asset(name="MD5", key_size=128, tls_version="TLSv1.3")
    eval_ = evaluate_assets([asset], policy)
    forbidden = [v for v in eval_.violations if v.rule == "forbidden_algorithms"]
    assert forbidden, eval_.violations
    assert "MD5" in forbidden[0].actual


def test_policy_with_rule_packs_unions_with_explicit_forbidden_list() -> None:
    """Explicit ``forbidden_algorithms`` and rule-pack-derived ones MUST union, not overwrite."""
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "rp_test_union",
        "description": "union semantics",
        "data_sensitivity_years": 10,
        "forbidden_algorithms": ["AES-128"],  # contrived, just to prove union
        "rule_packs": ["nist-core-2026"],
    }
    # AES-128 — only from explicit list
    aes = _make_asset(name="AES", key_size=128, tls_version="TLSv1.3")
    md5 = _make_asset(name="MD5", key_size=128, tls_version="TLSv1.3")
    eval_ = evaluate_assets([aes, md5], policy)
    rules = [v.actual for v in eval_.violations if v.rule == "forbidden_algorithms"]
    joined = " || ".join(rules)
    assert "AES" in joined  # from explicit list
    assert "MD5" in joined  # from rule pack


def test_policy_with_rule_packs_emits_deprecate_after_violation_post_date() -> None:
    """deprecate_after with effective <= today must surface as a HIGH violation."""
    from pqc_audit.policy_engine import evaluate_assets

    # nist-core-2026 deprecates RSA-2048 effective 2030-01-01.
    # Test date is 2026-05-04 (see _ts()), so RSA-2048 is NOT yet
    # past the deprecation. We use a per-test policy with an explicit
    # _deprecate_after override in the past to force the rule.
    policy = {
        "name": "rp_deprecate_now",
        "description": "post-date deprecation",
        "data_sensitivity_years": 10,
        "rule_packs": ["nist-core-2026"],
        # The engine reads the compiled deprecate_after dict; for the
        # post-date case we emulate by referencing a policy with
        # current_date past 2030 in _evaluation_clock. Simpler: ship
        # a synthetic pack via the public API would be heavier. We
        # instead let the merge populate deprecate_after and inject
        # a custom evaluation clock via the optional 'evaluation_date'
        # policy field (also added in Sprint 6).
        "evaluation_date": "2031-01-01",
    }
    rsa = _make_asset(name="RSA", key_size=2048, tls_version="TLSv1.3")
    eval_ = evaluate_assets([rsa], policy)
    deprecate = [v for v in eval_.violations if v.rule == "deprecate_after"]
    assert deprecate, eval_.violations
    assert "RSA-2048" in deprecate[0].actual
    assert "2030" in deprecate[0].expected  # the effective date is mentioned


def test_policy_with_rule_packs_does_not_emit_deprecate_after_before_date() -> None:
    """deprecate_after with effective > today must NOT surface a violation."""
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "rp_deprecate_future",
        "description": "pre-date deprecation",
        "data_sensitivity_years": 10,
        "rule_packs": ["nist-core-2026"],
        "evaluation_date": "2026-05-04",  # before the 2030-01-01 line
    }
    rsa = _make_asset(name="RSA", key_size=2048, tls_version="TLSv1.3")
    eval_ = evaluate_assets([rsa], policy)
    deprecate = [v for v in eval_.violations if v.rule == "deprecate_after"]
    assert not deprecate, "deprecate_after fired before its effective date"


def test_policy_with_rule_packs_invalid_pack_name_raises() -> None:
    """An unknown rule-pack name in a policy must fail loudly at evaluation."""
    from pqc_audit.policy_engine import evaluate_assets

    policy = {
        "name": "rp_bad",
        "description": "broken",
        "data_sensitivity_years": 10,
        "rule_packs": ["nope-2999"],
    }
    asset = _make_asset(name="RSA", key_size=2048, tls_version="TLSv1.3")
    with pytest.raises(FileNotFoundError):
        evaluate_assets([asset], policy)
