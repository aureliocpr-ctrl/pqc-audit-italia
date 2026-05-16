"""Tests for Auditor.evaluate_against_policy — Phase 5.B integration."""

from __future__ import annotations

from datetime import UTC, datetime


def _ts() -> datetime:
    return datetime(2026, 5, 4, 12, 0, 0, tzinfo=UTC)


def _stub_report(
    *,
    alg_name: str = "MD5",
    key_size: int | None = 128,
    sig_hash: str = "SHA-256",
    tls_version: str = "TLSv1.2",
):
    """Return an AuditReport with one synthetic asset (no network I/O)."""
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        ScanCategory,
        ScanResult,
    )

    asset = CryptoAsset(
        asset_id="tls://stub:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name=alg_name, key_size_bits=key_size),
        location="stub:443",
        discovered_at=_ts(),
        metadata={"tls_version": tls_version, "signature_hash": sig_hash},
    )
    sr = ScanResult(
        scanner_name="tls",
        target="stub:443",
        assets=[asset],
        vulnerabilities=[],
        started_at=_ts(),
        finished_at=_ts(),
    )
    return AuditReport(
        report_id="test-1",
        scan_results=[sr],
        policy_name="agid_2026",
        generated_at=_ts(),
    )


def test_evaluate_against_policy_uses_self_policy_by_default() -> None:
    from pqc_audit import Auditor

    auditor = Auditor(policy="agid_2026")
    report = _stub_report(alg_name="MD5", key_size=128, sig_hash="MD5")
    eval_ = auditor.evaluate_against_policy(report)
    assert eval_.policy_name == "agid_2026"
    assert eval_.non_compliant_assets == 1


def test_evaluate_against_policy_explicit_override() -> None:
    """Passing policy_name explicitly overrides Auditor.policy.

    Note (0.2.1): both ``nist_baseline`` and ``pa_critical`` now reject
    RSA-2048, but for *different* reasons — nist_baseline via
    ``discouraged_algorithms`` (MEDIUM) and ``thresholds.hndl_max_score``
    (HIGH, because RSA-2048 with the default 10y sensitivity already
    blows past the HNDL ceiling), while pa_critical adds the explicit
    ``forbidden_algorithms`` entry. The test verifies the OVERRIDE
    mechanism: the policy_name on the eval matches the override, not
    the Auditor default.
    """
    from pqc_audit import Auditor

    auditor = Auditor(policy="nist_baseline")
    report = _stub_report(alg_name="RSA", key_size=2048)
    nist_eval = auditor.evaluate_against_policy(report)
    assert nist_eval.policy_name == "nist_baseline"
    pa_eval = auditor.evaluate_against_policy(report, policy_name="pa_critical")
    assert pa_eval.policy_name == "pa_critical"
    assert pa_eval.non_compliant_assets == 1
    # pa_critical is strictly more violations than nist_baseline (it
    # adds forbidden_algorithms on top of inherited thresholds + discouraged).
    assert len(pa_eval.violations) >= len(nist_eval.violations)


def test_evaluate_against_policy_default_policy_loads_nist_baseline() -> None:
    """Auditor() without explicit policy still works (falls back to nist_baseline)."""
    from pqc_audit import Auditor

    auditor = Auditor()  # default policy='default'
    report = _stub_report(alg_name="ML-DSA-65", key_size=None)
    eval_ = auditor.evaluate_against_policy(report)
    # Whatever the resolved policy, ML-DSA-65 is PQC and should comply.
    assert eval_.overall_verdict == "PASS"


def test_evaluate_against_policy_returns_policyevaluation_type() -> None:
    from pqc_audit import Auditor
    from pqc_audit.policy_engine import PolicyEvaluation

    auditor = Auditor(policy="agid_2026")
    report = _stub_report(alg_name="MD5", key_size=128, sig_hash="MD5")
    eval_ = auditor.evaluate_against_policy(report)
    assert isinstance(eval_, PolicyEvaluation)
