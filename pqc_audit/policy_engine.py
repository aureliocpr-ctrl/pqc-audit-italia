"""Policy enforcement engine — Phase 5.

Evaluates an :class:`AuditReport` (or a flat list of
:class:`CryptoAsset`) against a loaded policy dict and produces a
structured :class:`PolicyEvaluation` with per-asset violations.

The engine is a pure function with two exceptions:

* It will *read* (never write) rule-pack YAML files when the policy
  contains a ``rule_packs`` key — see :func:`_compile_pack_overlay`.
  An unknown pack name fails loudly (``FileNotFoundError``); an
  empty list is a noop.
* It will perform ``datetime.now`` for ``deprecate_after`` checks
  *unless* the policy supplies an ``evaluation_date`` (used by tests
  and by point-in-time audits).

Unknown policy keys are logged at DEBUG and ignored so YAML files can
grow without breaking older code paths.

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
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from pqc_audit.core.algorithms import (
    HYBRID_SCHEMES,
    AlgorithmClass,
    classify_algorithm,
)
from pqc_audit.core.clock import frozen_now
from pqc_audit.core.models import (
    AuditReport,
    CryptoAsset,
    RiskLevel,
)
from pqc_audit.core.risk import (
    calculate_agility_score,
    calculate_hndl_risk,
    calculate_qday_risk,
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
        # pa_critical_2027 introduces a structured "required PQC families".
        # The engine doesn't enforce it yet (the schema is still being
        # finalized at AgID/ACN level), but we accept the key so the
        # forward-compat warning stays quiet.
        "required_pqc_algorithms",
        # Sprint 6: list of pack short-names (e.g. ``nist-core-2026``)
        # whose compiled allow/forbid/discourage/deprecate_after sets
        # are merged into the policy at evaluation time. See
        # :func:`_compile_pack_overlay`.
        "rule_packs",
        # Sprint 6: optional ISO-8601 date overriding ``datetime.now``
        # for ``deprecate_after`` checks. Useful for point-in-time
        # audits and for tests that pin a synthetic clock.
        "evaluation_date",
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


class RulePackProvenance(BaseModel):
    """Legal-value provenance record for a rule pack that drove the verdict.

    Sprint 7: a regulator or procurement reviewer must be able to
    re-derive the audit's verdict weeks later. That requires pinning
    not just the pack's short-name but also its declared ``version``,
    the regulatory anchor URL it claims, and a SHA-256 of the YAML
    file *as shipped* (so any silent edit between audits surfaces).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    source: str
    url: str
    retrieved: date
    file_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


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
    # Sprint 7: per-pack provenance (name, version, source, URL, file
    # hash) recorded at evaluation time. Empty for legacy policies
    # that do not opt into ``rule_packs``. Loaded from the YAML on
    # disk — drift between runs == regression test failure.
    rule_pack_provenance: list[RulePackProvenance] = Field(default_factory=list)


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


def _check_discouraged_algorithms(
    asset: CryptoAsset, policy: dict[str, Any]
) -> list[PolicyViolation]:
    """MEDIUM-severity warning sibling of ``forbidden_algorithms``.

    ``discouraged_algorithms`` are primitives that are *acceptable for
    now* (no HARD-FAIL) but should not appear in new deployments. The
    YAML files have always carried this key — the engine just never
    evaluated it. Surface every hit as a non-blocking violation so
    operators see the migration debt explicitly.
    """
    discouraged = policy.get("discouraged_algorithms") or []
    if not discouraged:
        return []
    discouraged_upper = {str(x).strip().upper() for x in discouraged}
    candidates = {
        asset.algorithm.name.upper(),
        _asset_canonical(asset).upper(),
    }
    sig_hash = _normalize_hash(asset.metadata.get("signature_hash"))
    if sig_hash:
        candidates.add(sig_hash)
    hits = candidates & discouraged_upper
    if not hits:
        return []
    hit_str = ", ".join(sorted(hits))
    return [
        _build_violation(
            asset=asset,
            rule="discouraged_algorithms",
            expected=f"prefer alternatives to {sorted(discouraged_upper)!r}",
            actual=hit_str,
            severity=RiskLevel.MEDIUM,
            remediation=(
                f"{hit_str} is discouraged by this policy. Plan migration to a "
                "stronger primitive before the next renewal cycle."
            ),
        )
    ]


def _check_thresholds(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    """Per-asset enforcement of ``thresholds.{hndl_max_score, qday_max_score,
    min_agility_score}``.

    Recomputes the score on the fly using
    :mod:`pqc_audit.core.risk` so the check is self-contained and does
    not require a pre-enriched report. The ``data_sensitivity_years``
    used to drive HNDL is read from the policy (every bundled YAML
    sets it).
    """
    thresholds = policy.get("thresholds")
    if not isinstance(thresholds, dict):
        return []
    sensitivity_raw = policy.get("data_sensitivity_years", 10)
    try:
        sensitivity = int(sensitivity_raw)
    except (TypeError, ValueError):
        sensitivity = 10
    out: list[PolicyViolation] = []

    hndl_max = thresholds.get("hndl_max_score")
    if isinstance(hndl_max, int):
        score = calculate_hndl_risk(asset, sensitivity)
        if score > hndl_max:
            out.append(
                _build_violation(
                    asset=asset,
                    rule="thresholds.hndl_max_score",
                    expected=f"HNDL <= {hndl_max}",
                    actual=f"HNDL = {score}",
                    severity=RiskLevel.HIGH,
                    remediation=(
                        "Reduce HNDL exposure: shorten the confidentiality "
                        "lifetime of data protected by this asset, or migrate "
                        "to a quantum-resistant primitive (FIPS 203/204/205)."
                    ),
                )
            )

    qday_max = thresholds.get("qday_max_score")
    if isinstance(qday_max, int):
        score = calculate_qday_risk(asset)
        if score > qday_max:
            out.append(
                _build_violation(
                    asset=asset,
                    rule="thresholds.qday_max_score",
                    expected=f"Q-Day risk <= {qday_max}",
                    actual=f"Q-Day risk = {score}",
                    severity=RiskLevel.HIGH,
                    remediation=(
                        "Migrate this asset off classical primitives. The "
                        "current Q-Day exposure exceeds the policy ceiling."
                    ),
                )
            )

    min_agility = thresholds.get("min_agility_score")
    if isinstance(min_agility, int):
        score = calculate_agility_score(asset)
        if score < min_agility:
            out.append(
                _build_violation(
                    asset=asset,
                    rule="thresholds.min_agility_score",
                    expected=f"agility >= {min_agility}",
                    actual=f"agility = {score}",
                    severity=RiskLevel.MEDIUM,
                    remediation=(
                        "Increase crypto-agility: remove hardcoded keys / "
                        "cert pinning, introduce a configuration abstraction "
                        "so the primitive can be swapped without redeploy."
                    ),
                )
            )
    return out


def _compile_pack_overlay(policy: dict[str, Any]) -> dict[str, Any]:
    """Merge the policy ``rule_packs`` overlay into a fresh dict.

    Returns a new dict (the caller's policy is never mutated). The
    overlay extends ``forbidden_algorithms`` / ``discouraged_algorithms``
    with the union of the named packs' compiled sets, and stores the
    compiled ``deprecate_after`` dict under the private key
    ``_compiled_deprecate_after`` for :func:`_check_deprecate_after`
    to consume.

    Unknown pack names propagate the :class:`FileNotFoundError` from
    :mod:`pqc_audit.rule_packs` so callers fail loudly at evaluation
    instead of silently producing an over-permissive verdict.
    """
    pack_names = policy.get("rule_packs")
    if not pack_names:
        return policy
    if not isinstance(pack_names, list):
        log.debug("policy_engine: 'rule_packs' is not a list, ignoring")
        return policy
    # Local import keeps policy_engine importable when rule_packs is
    # not vendored (e.g. minimal install). Suppressed PLC0415 for that
    # reason — the indirection is intentional, not laziness.
    import hashlib  # noqa: PLC0415

    from pqc_audit.rule_packs import (  # noqa: PLC0415
        compile_rule_packs,
        load_rule_pack,
        rule_pack_file_path,
    )

    name_list = [str(name) for name in pack_names]
    compiled = compile_rule_packs(name_list)
    merged = dict(policy)
    existing_forbid = {str(x) for x in merged.get("forbidden_algorithms") or []}
    existing_discourage = {str(x) for x in merged.get("discouraged_algorithms") or []}
    merged["forbidden_algorithms"] = sorted(existing_forbid | compiled.forbidden_algorithms)
    merged["discouraged_algorithms"] = sorted(existing_discourage | compiled.discouraged_algorithms)
    merged["_compiled_deprecate_after"] = dict(compiled.deprecate_after)

    # Sprint 7: legal-value provenance — pin each pack's declared
    # version + the SHA-256 of the YAML file as shipped. A regulator
    # can re-fetch the same file from the same commit and hash-compare;
    # any silent edit between audits will surface as a hash mismatch.
    provenance_records: list[RulePackProvenance] = []
    for pack_name in name_list:
        pack = load_rule_pack(pack_name)
        pack_path = rule_pack_file_path(pack_name)
        file_bytes = pack_path.read_bytes()
        sha = hashlib.sha256(file_bytes).hexdigest()
        provenance_records.append(
            RulePackProvenance(
                name=pack.name,
                version=pack.version,
                source=pack.provenance.source,
                url=pack.provenance.url,
                retrieved=pack.provenance.retrieved,
                file_sha256=sha,
            )
        )
    merged["_rule_pack_provenance"] = provenance_records
    return merged


def _evaluation_date(policy: dict[str, Any]) -> date:
    """Today, or the ``evaluation_date`` override from the policy."""
    raw = policy.get("evaluation_date")
    if isinstance(raw, str):
        try:
            return date.fromisoformat(raw)
        except ValueError:
            log.debug("policy_engine: invalid evaluation_date %r, using today", raw)
    if isinstance(raw, date):
        return raw
    return frozen_now().date()


def _check_deprecate_after(asset: CryptoAsset, policy: dict[str, Any]) -> list[PolicyViolation]:
    """Emit a HIGH violation for an asset whose algorithm has reached its NIST IR
    8547-style deprecation date.

    The compiled deprecate map lives under ``_compiled_deprecate_after``
    (populated by :func:`_compile_pack_overlay`). The check is a no-op
    when no rule pack contributed a deprecation, or when the asset
    algorithm does not match any deprecated key. Matching is on
    :attr:`Algorithm.canonical_name` so RSA-2048 in the rule pack
    matches an asset whose Algorithm(name='RSA', key_size_bits=2048).
    """
    deprecate_map = policy.get("_compiled_deprecate_after")
    if not isinstance(deprecate_map, dict) or not deprecate_map:
        return []
    canonical = asset.algorithm.canonical_name
    effective = deprecate_map.get(canonical)
    if effective is None:
        return []
    if not isinstance(effective, date):
        return []
    today = _evaluation_date(policy)
    if today < effective:
        return []
    return [
        _build_violation(
            asset=asset,
            rule="deprecate_after",
            expected=(
                f"{canonical} deprecated by rule pack effective "
                f"{effective.isoformat()} — migrate to a PQC primitive"
            ),
            actual=f"{canonical} still in use on {today.isoformat()}",
            severity=RiskLevel.HIGH,
            remediation=(
                "An ingested rule pack flags this algorithm as deprecated for "
                "new use after the effective date. Plan migration to a "
                "FIPS-203/204/205 primitive (ML-KEM-768, ML-DSA-65, "
                "SLH-DSA-SHA2-192s) or a hybrid scheme during the transition "
                "window."
            ),
        )
    ]


_CHECKERS = (
    _check_forbidden_algos,
    _check_min_tls,
    _check_min_key_size,
    _check_signature_hash,
    _check_hybrid,
    _check_discouraged_algorithms,
    _check_thresholds,
    _check_deprecate_after,
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
    works too. If the policy contains a ``rule_packs`` list, the
    named packs are compiled and their forbid / discourage /
    deprecate_after sets are unioned into the effective policy
    *for this evaluation only* (the caller's dict is never mutated).
    """
    _warn_unknown_keys(policy)
    policy = _compile_pack_overlay(policy)
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

    provenance_raw = policy.get("_rule_pack_provenance") or []
    provenance: list[RulePackProvenance] = [
        p for p in provenance_raw if isinstance(p, RulePackProvenance)
    ]

    return PolicyEvaluation(
        policy_name=str(policy.get("name") or "unknown"),
        policy_description=str(policy.get("description") or ""),
        total_assets_evaluated=total,
        compliant_assets=compliant,
        non_compliant_assets=non_compliant,
        violations=violations,
        overall_verdict=_verdict(total, non_compliant),
        evaluated_at=frozen_now(),
        rule_pack_provenance=provenance,
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
