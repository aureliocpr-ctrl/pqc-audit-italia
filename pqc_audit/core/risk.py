"""Risk scoring: HNDL, Q-Day, crypto-agility, aggregate.

All public functions return integer scores in the range 0-100 (clamped),
with higher = worse. Default Q-Day estimate is 2032 — a midpoint of the
2030-2035 window commonly cited by industry analysts.

The math is intentionally simple and inspectable: this is an *audit*
tool, not a probabilistic forecasting engine. Reviewers must be able
to defend each number in front of an auditor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm
from pqc_audit.core.models import CryptoAsset

# Default assumed year a Cryptographically Relevant Quantum Computer arrives.
DEFAULT_QDAY_YEAR = 2032

# Score bands (centralized for tunability + tests visibility)
_SCORE_VULNERABLE_BASE = 80
_SCORE_WEAKENED_BASE = 50
_SCORE_RESISTANT_BASE = 5
_SCORE_HYBRID_BASE = 20
_SCORE_UNKNOWN_BASE = 40


def _clamp(value: float) -> int:
    """Clamp to [0, 100] integer."""
    return max(0, min(100, int(round(value))))


def _baseline_for(asset: CryptoAsset) -> int:
    """Static baseline score derived only from algorithm classification."""
    cls = classify_algorithm(asset.algorithm.name)
    if cls is AlgorithmClass.QUANTUM_VULNERABLE:
        return _SCORE_VULNERABLE_BASE
    if cls is AlgorithmClass.QUANTUM_WEAKENED:
        return _SCORE_WEAKENED_BASE
    if cls is AlgorithmClass.QUANTUM_RESISTANT:
        return _SCORE_RESISTANT_BASE
    if cls is AlgorithmClass.HYBRID:
        return _SCORE_HYBRID_BASE
    return _SCORE_UNKNOWN_BASE


def calculate_hndl_risk(
    asset: CryptoAsset,
    data_sensitivity_years: int,
    *,
    qday_year: int = DEFAULT_QDAY_YEAR,
    today: datetime | None = None,
) -> int:
    """HNDL exposure score (0-100).

    Intuition: an attacker captures ciphertext today and decrypts it
    after Q-Day. If the data still matters at Q-Day, exposure is high.

    Formula:
        baseline_for(algorithm)               # 0-80 depending on bucket
        + lifetime_factor                     # +20 if data outlives Q-Day
        - 0 / + small adjustments

    Where ``lifetime_factor`` is +20 if (today + sensitivity_years) >= qday,
    +10 if it falls within ±2 years, 0 otherwise.

    Quantum-resistant algorithms get a near-zero score regardless of
    sensitivity — they were not vulnerable in the first place.
    """
    today = today or datetime.now(timezone.utc)
    cls = classify_algorithm(asset.algorithm.name)
    if cls is AlgorithmClass.QUANTUM_RESISTANT:
        return _clamp(_SCORE_RESISTANT_BASE)

    end_of_sensitivity_year = today.year + max(0, int(data_sensitivity_years))
    if end_of_sensitivity_year >= qday_year + 2:
        lifetime_factor = 20
    elif end_of_sensitivity_year >= qday_year - 2:
        lifetime_factor = 10
    else:
        # Data dies well before Q-Day — HNDL pressure is much lower.
        lifetime_factor = -50

    return _clamp(_baseline_for(asset) + lifetime_factor)


def calculate_qday_risk(
    asset: CryptoAsset,
    *,
    qday_estimate_year: int = DEFAULT_QDAY_YEAR,
    today: datetime | None = None,
) -> int:
    """Q-Day risk: how exposed is the asset *at* Q-Day (0-100).

    Quantum-vulnerable -> baseline (~80).
    Quantum-weakened   -> middle band (~50).
    Quantum-resistant  -> low (~5).
    Unknown            -> conservative middle.

    The ``qday_estimate_year`` parameter is currently informational
    (forward-looking estimates do not change the static class verdict),
    but kept in the API to allow future weighting (e.g. proximity to
    Q-Day amplifying urgency).
    """
    _ = today, qday_estimate_year  # reserved for future heuristics
    return _clamp(_baseline_for(asset))


def calculate_agility_score(asset: CryptoAsset) -> int:
    """Crypto-agility: HIGHER = easier to migrate (0-100).

    Heuristics on metadata:
    - hardcoded=True              -25
    - cert_pinned=True            -20
    - hsm_backed=True             -10  (more secure but harder to rotate)
    - configurable=True           +20
    - abstraction_layer=True      +15

    Default baseline 50.
    """
    score = 50
    md = asset.metadata or {}
    if md.get("hardcoded"):
        score -= 25
    if md.get("cert_pinned"):
        score -= 20
    if md.get("hsm_backed"):
        score -= 10
    if md.get("configurable"):
        score += 20
    if md.get("abstraction_layer"):
        score += 15
    return _clamp(score)


def aggregate_risk(
    assets: list[CryptoAsset],
    data_sensitivity_years: int,
    *,
    qday_year: int = DEFAULT_QDAY_YEAR,
) -> dict[str, Any]:
    """Aggregate risk across a portfolio of assets.

    Returns a flat dict with counts per bucket plus the maximum HNDL /
    Q-Day score observed. Suitable for executive-summary headers.
    """
    if not assets:
        return {
            "asset_count": 0,
            "vulnerable_count": 0,
            "weakened_count": 0,
            "resistant_count": 0,
            "hybrid_count": 0,
            "unknown_count": 0,
            "hndl_max": 0,
            "qday_max": 0,
            "agility_min": 0,
        }

    vuln = weak = res = hyb = unk = 0
    hndl_max = qday_max = 0
    agility_min = 100

    for a in assets:
        cls = classify_algorithm(a.algorithm.name)
        if cls is AlgorithmClass.QUANTUM_VULNERABLE:
            vuln += 1
        elif cls is AlgorithmClass.QUANTUM_WEAKENED:
            weak += 1
        elif cls is AlgorithmClass.QUANTUM_RESISTANT:
            res += 1
        elif cls is AlgorithmClass.HYBRID:
            hyb += 1
        else:
            unk += 1
        hndl_max = max(
            hndl_max,
            calculate_hndl_risk(a, data_sensitivity_years, qday_year=qday_year),
        )
        qday_max = max(qday_max, calculate_qday_risk(a, qday_estimate_year=qday_year))
        agility_min = min(agility_min, calculate_agility_score(a))

    return {
        "asset_count": len(assets),
        "vulnerable_count": vuln,
        "weakened_count": weak,
        "resistant_count": res,
        "hybrid_count": hyb,
        "unknown_count": unk,
        "hndl_max": hndl_max,
        "qday_max": qday_max,
        "agility_min": agility_min,
    }
