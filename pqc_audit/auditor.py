"""High-level orchestrator: pick scanners by target type, run them,
aggregate into a single :class:`AuditReport`, and enrich the report
with risk summary + auto-generated migration recommendations.

Usage::

    from pqc_audit import Auditor, ScanTarget

    auditor = Auditor(policy="agid_2026", data_sensitivity_years=15)
    report = await auditor.scan([
        ScanTarget(type="tls", host="example.it", port=443),
    ])

The Auditor never raises on per-target errors — failures are captured
in ``ScanResult.errors`` so a single broken target does not abort the
whole audit run.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from pqc_audit.core.algorithms import (
    HYBRID_SCHEMES,
    AlgorithmClass,
    classify_algorithm,
    recommend_pqc_replacement,
)
from pqc_audit.core.models import (
    AuditReport,
    CryptoAsset,
    MigrationRecommendation,
    ScanResult,
)
from pqc_audit.core.risk import (
    aggregate_risk,
    calculate_agility_score,
    calculate_hndl_risk,
    calculate_qday_risk,
)
from pqc_audit.policies import load_policy
from pqc_audit.policy_engine import PolicyEvaluation, evaluate_report
from pqc_audit.scanners.base import BaseScanner, ScanTarget
from pqc_audit.scanners.tls_scanner import TLSScanner

# Default assumed lifetime of confidential data, in years. Conservative
# midpoint covering most regulated sectors (banking ~10y, health 20y+,
# state secrets 30y). Override via Auditor(data_sensitivity_years=...).
DEFAULT_DATA_SENSITIVITY_YEARS = 10


def _hybrid_for(algorithm_name: str) -> str | None:
    """Pick a sensible hybrid intermediate for the transition phase.

    Picks signature hybrids for signature primitives and KEM hybrids
    for key-exchange primitives — without this branching, EdDSA
    (Ed25519 / Ed448 signing) was silently mapped to a KEM hybrid
    (X25519+ML-KEM-768) by the default fallback, which is semantically
    wrong for a signing migration plan.
    """
    norm = algorithm_name.upper()
    if norm.startswith("RSA"):
        return "RSA-3072+ML-DSA-65"
    if norm in ("ECDSA", "ECDH") or norm.startswith("ECDSA"):
        return "ECDSA-P256+ML-DSA-65"
    if norm.startswith("EDDSA") or norm in ("ED25519", "ED448"):
        # EdDSA is a signature primitive — bridge to ML-DSA, not ML-KEM.
        return "ECDSA-P256+ML-DSA-65"
    if norm == "DH":
        return "X25519+ML-KEM-768"
    return next(iter(HYBRID_SCHEMES), None)


# Score thresholds for the 1-5 migration priority bucket.
_PRIORITY_THRESHOLDS = ((90, 5), (75, 4), (50, 3), (25, 2))


def _priority_for(hndl_score: int, qday_score: int) -> int:
    """Map (HNDL, Q-Day) scores to 1-5 migration priority."""
    high_water = max(hndl_score, qday_score)
    for threshold, level in _PRIORITY_THRESHOLDS:
        if high_water >= threshold:
            return level
    return 1


def _build_recommendation(
    algorithm_name: str,
    canonical: str,
    *,
    hndl_score: int,
    qday_score: int,
) -> MigrationRecommendation | None:
    """Build a single recommendation for one vulnerable algorithm group."""
    target = recommend_pqc_replacement(algorithm_name)
    if target is None:
        return None
    return MigrationRecommendation(
        from_algorithm=canonical,
        to_algorithm=target,
        rationale=(
            f"{canonical} is quantum-vulnerable (broken by Shor on a CRQC). "
            f"HNDL score {hndl_score}/100, Q-Day score {qday_score}/100. "
            f"Migrate to {target} (NIST FIPS PQC) and consider hybrid "
            "deployment during the transition (RFC 9794)."
        ),
        priority=_priority_for(hndl_score, qday_score),
        hybrid_intermediate=_hybrid_for(algorithm_name),
        references=(
            "https://csrc.nist.gov/projects/post-quantum-cryptography",
            "https://datatracker.ietf.org/doc/rfc9794/",
        ),
    )


def _all_assets(scan_results: list[ScanResult]) -> list[CryptoAsset]:
    """Flatten every CryptoAsset across every ScanResult."""
    out: list[CryptoAsset] = []
    for sr in scan_results:
        out.extend(sr.assets)
    return out


def enrich_report(
    report: AuditReport,
    *,
    data_sensitivity_years: int = DEFAULT_DATA_SENSITIVITY_YEARS,
) -> AuditReport:
    """Return a NEW :class:`AuditReport` with risk summary and
    migration recommendations populated.

    Pure function (the input report is frozen). The output preserves
    the original ``scan_results`` and ``policy_name`` and only adds:

    - ``metadata['risk_summary']``: aggregate stats from
      :func:`aggregate_risk`.
    - ``metadata['data_sensitivity_years']``: input parameter, recorded
      for auditability.
    - ``metadata['per_asset_risk']``: list of
      ``{asset_id, hndl, qday, agility}`` for each asset.
    - ``recommendations``: one :class:`MigrationRecommendation` per
      distinct quantum-vulnerable algorithm canonical name. Deduped.
    """
    assets = _all_assets(report.scan_results)
    summary = aggregate_risk(assets, data_sensitivity_years)

    per_asset = [
        {
            "asset_id": a.asset_id,
            "hndl": calculate_hndl_risk(a, data_sensitivity_years),
            "qday": calculate_qday_risk(a),
            "agility": calculate_agility_score(a),
        }
        for a in assets
    ]

    seen_canonicals: set[str] = set()
    recs: list[MigrationRecommendation] = list(report.recommendations)
    for asset in assets:
        if classify_algorithm(asset.algorithm.name) is not AlgorithmClass.QUANTUM_VULNERABLE:
            continue
        canonical = asset.algorithm.canonical_name
        if canonical in seen_canonicals:
            continue
        seen_canonicals.add(canonical)
        rec = _build_recommendation(
            asset.algorithm.name,
            canonical,
            hndl_score=calculate_hndl_risk(asset, data_sensitivity_years),
            qday_score=calculate_qday_risk(asset),
        )
        if rec is not None:
            recs.append(rec)

    new_metadata = dict(report.metadata)
    new_metadata["risk_summary"] = summary
    new_metadata["data_sensitivity_years"] = data_sensitivity_years
    new_metadata["per_asset_risk"] = per_asset

    return report.model_copy(
        update={
            "recommendations": recs,
            "metadata": new_metadata,
        }
    )


class Auditor:
    """High-level orchestrator over a collection of scanners.

    Args:
        policy: name of the policy to apply (informational for now;
            the policy engine lands in Phase 5).
        data_sensitivity_years: assumed lifetime of confidential data
            in the target environment, used by HNDL scoring. Defaults
            to :data:`DEFAULT_DATA_SENSITIVITY_YEARS`.
        scanners: optional list of scanner instances. Defaults to the
            built-in scanners (TLS for now).
    """

    def __init__(
        self,
        *,
        policy: str = "default",
        data_sensitivity_years: int = DEFAULT_DATA_SENSITIVITY_YEARS,
        scanners: list[BaseScanner] | None = None,
        max_concurrency: int = 16,
    ) -> None:
        self.policy = policy
        self.data_sensitivity_years = data_sensitivity_years
        self.scanners: list[BaseScanner] = (
            list(scanners) if scanners is not None else [TLSScanner()]
        )
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self.max_concurrency = max_concurrency

    async def _scan_single(
        self,
        target: ScanTarget,
        sem: asyncio.Semaphore,
    ) -> list[ScanResult]:
        """Scan one target across every applicable scanner. Bounded by ``sem``."""
        out: list[ScanResult] = []
        for scanner in self.scanners:
            if await scanner.is_applicable(target):
                async with sem:
                    out.append(await scanner.scan(target))
        return out

    async def scan(self, targets: list[ScanTarget]) -> AuditReport:
        """Run every applicable scanner against every target and
        return an enriched :class:`AuditReport`.

        Targets are scanned **concurrently**, bounded by
        ``max_concurrency`` (default 16) so we don't hammer the
        operator's network or the targets themselves. Per-target
        errors are isolated in ``ScanResult.errors`` and never abort
        the run.
        """
        sem = asyncio.Semaphore(self.max_concurrency)
        per_target = await asyncio.gather(
            *(self._scan_single(t, sem) for t in targets),
            return_exceptions=False,
        )
        results: list[ScanResult] = []
        for batch in per_target:
            results.extend(batch)

        raw_report = AuditReport(
            report_id=f"audit-{uuid.uuid4().hex[:12]}",
            scan_results=results,
            policy_name=self.policy,
            generated_at=datetime.now(UTC),
        )
        return enrich_report(raw_report, data_sensitivity_years=self.data_sensitivity_years)

    def evaluate_against_policy(
        self,
        report: AuditReport,
        *,
        policy_name: str | None = None,
    ) -> PolicyEvaluation:
        """Evaluate ``report`` against a bundled policy.

        ``policy_name`` defaults to ``self.policy``. The reserved value
        ``"default"`` is mapped to ``nist_baseline`` so callers using
        the bare ``Auditor()`` still get meaningful enforcement.
        """
        name = policy_name or self.policy
        if name == "default":
            name = "nist_baseline"
        policy = load_policy(name)
        return evaluate_report(report, policy)
