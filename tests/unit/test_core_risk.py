"""Tests for pqc_audit.core.risk — HNDL / Q-Day / agility scoring."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


def _make_asset(algorithm_name: str, key_size: int | None = None):
    from pqc_audit.core.models import Algorithm, CryptoAsset, ScanCategory

    return CryptoAsset(
        asset_id=f"test://{algorithm_name}",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name=algorithm_name, key_size_bits=key_size),
        location="example.it",
        discovered_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# HNDL (Harvest Now, Decrypt Later)
# ---------------------------------------------------------------------------


def test_hndl_high_for_quantum_vulnerable_long_lifetime() -> None:
    from pqc_audit.core.risk import calculate_hndl_risk

    asset = _make_asset("RSA", 2048)
    score = calculate_hndl_risk(asset, data_sensitivity_years=15)
    assert 70 <= score <= 100


def test_hndl_low_for_pqc_resistant() -> None:
    from pqc_audit.core.risk import calculate_hndl_risk

    asset = _make_asset("ML-KEM-768")
    score = calculate_hndl_risk(asset, data_sensitivity_years=20)
    assert score <= 20


def test_hndl_zero_for_short_lived_data() -> None:
    from pqc_audit.core.risk import calculate_hndl_risk

    asset = _make_asset("RSA", 2048)
    # Data lifetime = 1 year; harvested traffic loses value before Q-Day.
    score = calculate_hndl_risk(asset, data_sensitivity_years=1)
    assert score <= 30


def test_hndl_clamped_0_100() -> None:
    from pqc_audit.core.risk import calculate_hndl_risk

    asset = _make_asset("RSA", 2048)
    extreme = calculate_hndl_risk(asset, data_sensitivity_years=1000)
    assert 0 <= extreme <= 100


# ---------------------------------------------------------------------------
# Q-Day
# ---------------------------------------------------------------------------


def test_qday_high_for_quantum_vulnerable() -> None:
    from pqc_audit.core.risk import calculate_qday_risk

    asset = _make_asset("RSA", 2048)
    score = calculate_qday_risk(asset, qday_estimate_year=2032)
    assert score >= 70


def test_qday_low_for_quantum_resistant() -> None:
    from pqc_audit.core.risk import calculate_qday_risk

    asset = _make_asset("ML-DSA-65")
    score = calculate_qday_risk(asset)
    assert score <= 10


def test_qday_medium_for_quantum_weakened() -> None:
    from pqc_audit.core.risk import calculate_qday_risk

    asset = _make_asset("AES-128")
    score = calculate_qday_risk(asset)
    assert 30 <= score <= 70


# ---------------------------------------------------------------------------
# Agility
# ---------------------------------------------------------------------------


def test_agility_default_medium() -> None:
    from pqc_audit.core.risk import calculate_agility_score

    asset = _make_asset("RSA", 2048)
    score = calculate_agility_score(asset)
    assert 0 <= score <= 100


def test_agility_lower_when_hardcoded_in_metadata() -> None:
    from pqc_audit.core.models import Algorithm, CryptoAsset, ScanCategory
    from pqc_audit.core.risk import calculate_agility_score

    pinned = CryptoAsset(
        asset_id="x",
        category=ScanCategory.CODE,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="src/auth.py:42",
        discovered_at=datetime.now(UTC),
        metadata={"hardcoded": True, "cert_pinned": True},
    )
    free = CryptoAsset(
        asset_id="y",
        category=ScanCategory.CONFIG,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="/etc/nginx/nginx.conf",
        discovered_at=datetime.now(UTC),
        metadata={"hardcoded": False, "cert_pinned": False},
    )
    assert calculate_agility_score(pinned) < calculate_agility_score(free)


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


def test_aggregate_risk_picks_max_hndl() -> None:
    from pqc_audit.core.risk import aggregate_risk

    a1 = _make_asset("RSA", 2048)
    a2 = _make_asset("ML-KEM-768")
    agg = aggregate_risk([a1, a2], data_sensitivity_years=10)
    assert agg["hndl_max"] >= 70
    assert agg["qday_max"] >= 70
    assert agg["asset_count"] == 2
    assert agg["vulnerable_count"] == 1
    assert agg["resistant_count"] == 1


def test_aggregate_empty_list() -> None:
    from pqc_audit.core.risk import aggregate_risk

    agg = aggregate_risk([], data_sensitivity_years=10)
    assert agg["asset_count"] == 0
    assert agg["hndl_max"] == 0
    assert agg["qday_max"] == 0


@pytest.mark.parametrize(
    "alg,expected_class",
    [
        ("RSA", "QUANTUM_VULNERABLE"),
        ("ML-DSA-65", "QUANTUM_RESISTANT"),
        ("SHA-1", "QUANTUM_WEAKENED"),
    ],
)
def test_classify_via_aggregate_buckets(alg: str, expected_class: str) -> None:
    from pqc_audit.core.risk import aggregate_risk

    agg = aggregate_risk([_make_asset(alg)], data_sensitivity_years=10)
    if expected_class == "QUANTUM_VULNERABLE":
        assert agg["vulnerable_count"] == 1
    elif expected_class == "QUANTUM_RESISTANT":
        assert agg["resistant_count"] == 1
    else:
        assert agg["weakened_count"] == 1
