"""Policy enforcement engine — Phase 5.

Evaluates an :class:`AuditReport` (or a flat list of
:class:`CryptoAsset`) against a loaded policy dict and produces a
structured :class:`PolicyEvaluation` with per-asset violations.

The engine is a pure function: it does not perform I/O, does not
mutate the inputs, and never raises on unknown policy fields (they
are logged at DEBUG and ignored). This keeps it forward-compatible
with new policy schema additions.

Public API::

    from pqc_audit.policies import load_policy
    from pqc_audit.policy_engine import evaluate_assets, evaluate_report

    policy = load_policy("agid_2026")
    eval_ = evaluate_report(report, policy)
    if eval_.overall_verdict != "PASS":
        for v in eval_.violations:
            print(v.asset_identifier, v.rule, v.expected, "vs", v.actual)
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from pqc_audit.core.algorithms import (
    HYBRID_SCHEMES,
    AlgorithmClass,
    classify_algorithm,
)
from pqc_audit.core.models import (
    AuditReport,
    CryptoAsset,
    RiskLevel,
)

log = logging.getLogger(__name__)

# Policy keys the engine understands. Anything else is intentionally
# ignored (logged at DEBUG) so YAML files can grow without breaking
# older code paths.
_KNOWN_POLICY_KEYS: frozenset[str] = frozenset(
    {
        "name",
        "description",
        "inherits",
        "data_sensitivity_years",
        "minimum_tls_version",
        "forbidden_algorithms",
        "discouraged_algorithms",
        "required_replacements",
        "required_minimum_key_size",
        "required_signature_hash_minimum",
        "pqc_required_by_year",
        "hsm_required",
        "hybrid_acceptable",
        "thresholds",
        "extra_controls",
        "references",
    }
)

# TLS version comparator. The bundled policies use the canonical
# ``TLSv1.X`` form, but scanner metadata may also expose plain
# ``TLSv1.3``, ``TLS 1.3`` or ``1.3``. Normalize before comparing.
_TLS_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?")
_TLS_RANK: dict[tuple[int, int], int] = {
    (1, 0): 10,
    (1, 1): 11,
    (1, 2): 12,
    (1, 3): 13,
}

# Hash-strength ordering used by ``required_signature_hash_minimum``.
# Higher value == stronger. SHA-1 / MD5 sit below SHA-256 by design.
_HASH_RANK: dict[str, int] = {
    "MD5": 0,
    "SHA-1": 10,
    "SHA1": 10,
    "SHA-224": 22,
    "SHA-256": 25,
    "SHA-384": 38,
    "SHA-512": 51,
    "SHA3-256": 32,
    "SHA3-384": 38,
    "SHA3-512": 51,
}


class PolicyViolation(BaseModel):
    """A single rule failure tied to a specific asset."""

    model_config = ConfigDict(frozen=True)

    asset_identifier: str
    rule: str
    expected: str
    actual: str
    severity: RiskLevel
    remediation: str


class PolicyEvaluation(BaseModel):
    """Aggregate result of evaluating a set of assets against a policy."""

    model_config = ConfigDict(frozen=True)

    policy_name: str
    policy_description: str
    total_assets_evaluated: int
    compliant_assets: int
    non_compliant_assets: int
    violations: list[PolicyViolation] = Field(default_factory=list)
    overall_verdict: str = "PASS"
    evaluated_at: datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _warn_unknown_keys(policy: dict[str, Any]) -> None:
    for key in policy:
        if key not in _KNOWN_POLICY_KEYS:
            log.debug("policy_engine: ignoring unknown policy key %r", key)


def _tls_version_rank(raw: str | None) -> int | None:
    """Map a TLS version string to an integer rank (higher == newer).

    Returns ``None`` for inputs that don't look like a TLS version,
    so the caller can skip the rule cleanly.
    """
    if not raw:
        return None
    match = _TLS_VERSION_RE.search(raw)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or "0")
    return _TLS_RANK.get((major, minor), major * 10 + minor)


def _normalize_hash(name: str | None) -> str:
    if not name:
        return ""
    return name.strip().upper().replace("_", "-")


def _hash_rank(name: str | None) -> int | None:
    norm = _normalize_hash(name)
    return _HASH_RANK.get(norm)


def _asset_canonical(asset: CryptoAsset) -> str:
    """Canonical algorithm name, including key size where relevant."""
    return asset.algorithm.canonical_name


def _is_hybrid(asset: CryptoAsset) -> bool:
    return classify_algorithm(asset.algorithm.name) is AlgorithmClass.HYBRID or (
        asset.algorithm.name.upper() in {k.upper() for k in HYBRID_SCHEMES}
    )


def _build_violation(
    *,
    asset: CryptoAsset,
    rule: str,
    expected: str,
    actual: str,
    severity: RiskLevel,
    remediation: str,
) -> PolicyViolation:
    return PolicyViolation(
        asset_identifier=asset.asset_id,
        rule=rule,
        expected=expected,
        actual=actual,
        severity=severity,
        remediation=remediation,
    )


# ---------------------------------------------------------------------------
# Per-rule checkers
# ---------------------------------------------------------------------------


def _check_forbidden_algos(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    forbidden = policy.get("forbidden_algorithms") or []
    if not forbidden:
        return []
    forbidden_upper = {str(x).strip().upper() for x in forbidden}
    candidates = {
        asset.algorithm.name.upper(),
        _asset_canonical(asset).upper(),
    }
    # Also scrutinize the signature hash, since hashes like MD5/SHA-1
    # commonly appear in ``forbidden_algorithms`` lists.
    sig_hash = _normalize_hash(asset.metadata.get("signature_hash"))
    if sig_hash:
        candidates.add(sig_hash)
    hits = candidates & forbidden_upper
    if not hits:
        return []
    hit_str = ", ".join(sorted(hits))
    return [
        _build_violation(
            asset=asset,
            rule="forbidden_algorithms",
            expected=f"none of {sorted(forbidden_upper)!r}",
            actual=hit_str,
            severity=RiskLevel.HIGH,
            remediation=(
                f"Replace forbidden primitive(s) {hit_str} with a NIST-approved "
                "alternative (FIPS 203/204/205 for asymmetric, SHA-256+ for hashes)."
            ),
        )
    ]


def _check_min_tls(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    expected_raw = policy.get("minimum_tls_version")
    if not expected_raw:
        return []
    actual_raw = asset.metadata.get("tls_version")
    if not actual_raw:
        return []
    expected_rank = _tls_version_rank(str(expected_raw))
    actual_rank = _tls_version_rank(str(actual_raw))
    if expected_rank is None or actual_rank is None:
        return []
    if actual_rank >= expected_rank:
        return []
    return [
        _build_violation(
            asset=asset,
            rule="minimum_tls_version",
            expected=str(expected_raw),
            actual=str(actual_raw),
            severity=RiskLevel.HIGH,
            remediation=(
                f"Disable TLS versions below {expected_raw}. Reconfigure the "
                "endpoint to negotiate the policy minimum or higher."
            ),
        )
    ]


def _check_min_key_size(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    sizes = policy.get("required_minimum_key_size") or {}
    if not isinstance(sizes, dict) or not sizes:
        return []
    name = asset.algorithm.name.upper()
    keysize = asset.algorithm.key_size_bits or 0
    minimum = None
    for k, v in sizes.items():
        if str(k).strip().upper() == name:
            try:
                minimum = int(v)
            except (TypeError, ValueError):
                continue
            break
    if minimum is None or keysize >= minimum:
        return []
    return [
        _build_violation(
            asset=asset,
            rule="required_minimum_key_size",
            expected=f"{name} >= {minimum} bits",
            actual=f"{name} = {keysize} bits",
            severity=RiskLevel.HIGH,
            remediation=(
                f"Re-issue this asset with at least {minimum} bits, or migrate "
                "to a NIST PQC algorithm (FIPS 203/204/205)."
            ),
        )
    ]


def _check_signature_hash(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    expected_raw = policy.get("required_signature_hash_minimum")
    if not expected_raw:
        return []
    expected_rank = _hash_rank(str(expected_raw))
    sig_hash = asset.metadata.get("signature_hash")
    if not sig_hash:
        return []
    actual_rank = _hash_rank(str(sig_hash))
    if expected_rank is None or actual_rank is None:
        return []
    if actual_rank >= expected_rank:
        return []
    return [
        _build_violation(
            asset=asset,
            rule="required_signature_hash_minimum",
            expected=str(expected_raw),
            actual=str(sig_hash),
            severity=RiskLevel.HIGH,
            remediation=(
                f"Re-sign this asset with {expected_raw} or stronger. "
                "Avoid SHA-1 / MD5 in any fresh signature."
            ),
        )
    ]


def _check_hybrid(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    if "hybrid_acceptable" not in policy:
        return []
    if policy["hybrid_acceptable"]:
        return []
    if not _is_hybrid(asset):
        return []
    return [
        _build_violation(
            asset=asset,
            rule="hybrid_acceptable",
            expected="pure PQC (hybrid not allowed by policy)",
            actual=asset.algorithm.name,
            severity=RiskLevel.MEDIUM,
            remediation=(
                "Switch from a hybrid scheme to a pure NIST PQC algorithm "
                "(e.g. ML-KEM-768 / ML-DSA-65)."
            ),
        )
    ]


_CHECKERS = (
    _check_forbidden_algos,
    _check_min_tls,
    _check_min_key_size,
    _check_signature_hash,
    _check_hybrid,
)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def _verdict(total: int, non_compliant: int) -> str:
    if total == 0 or non_compliant == 0:
        return "PASS"
    if non_compliant == total:
        return "FAIL"
    # >50% broken counts as FAIL, otherwise PARTIAL.
    if non_compliant * 2 > total:
        return "FAIL"
    return "PARTIAL"


def evaluate_assets(
    assets: Iterable[CryptoAsset],
    policy: dict[str, Any],
) -> PolicyEvaluation:
    """Evaluate ``assets`` against ``policy`` and return a
    :class:`PolicyEvaluation`.

    The policy dict is expected to be the merged output of
    :func:`pqc_audit.policies.load_policy`, but a hand-built dict
    works too.
    """
    _warn_unknown_keys(policy)
    asset_list = list(assets)

    violations: list[PolicyViolation] = []
    non_compliant_ids: set[str] = set()
    for asset in asset_list:
        per_asset: list[PolicyViolation] = []
        for checker in _CHECKERS:
            per_asset.extend(checker(asset, policy))
        if per_asset:
            non_compliant_ids.add(asset.asset_id)
            violations.extend(per_asset)

    total = len(asset_list)
    non_compliant = len(non_compliant_ids)
    compliant = total - non_compliant

    return PolicyEvaluation(
        policy_name=str(policy.get("name") or "unknown"),
        policy_description=str(policy.get("description") or ""),
        total_assets_evaluated=total,
        compliant_assets=compliant,
        non_compliant_assets=non_compliant,
        violations=violations,
        overall_verdict=_verdict(total, non_compliant),
        evaluated_at=datetime.now(UTC),
    )


def evaluate_report(
    report: AuditReport,
    policy: dict[str, Any],
) -> PolicyEvaluation:
    """Evaluate every asset in ``report.scan_results`` against ``policy``."""
    assets: list[CryptoAsset] = []
    for sr in report.scan_results:
        assets.extend(sr.assets)
    return evaluate_assets(assets, policy)


__all__ = [
    "PolicyEvaluation",
    "PolicyViolation",
    "evaluate_assets",
    "evaluate_report",
]
