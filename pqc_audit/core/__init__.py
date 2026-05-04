"""Core data models, algorithm classification, risk calculation."""

from __future__ import annotations

from pqc_audit.core.algorithms import (
    HYBRID_SCHEMES,
    QUANTUM_RESISTANT,
    QUANTUM_VULNERABLE,
    QUANTUM_WEAKENED,
    AlgorithmClass,
    classify_algorithm,
    is_deprecated,
    recommend_pqc_replacement,
)
from pqc_audit.core.risk import (
    DEFAULT_QDAY_YEAR,
    aggregate_risk,
    calculate_agility_score,
    calculate_hndl_risk,
    calculate_qday_risk,
)
from pqc_audit.core.models import (
    Algorithm,
    AuditReport,
    CryptoAsset,
    KeyMaterial,
    MigrationRecommendation,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)

__all__ = [
    "DEFAULT_QDAY_YEAR",
    "HYBRID_SCHEMES",
    "QUANTUM_RESISTANT",
    "QUANTUM_VULNERABLE",
    "QUANTUM_WEAKENED",
    "Algorithm",
    "AlgorithmClass",
    "AuditReport",
    "CryptoAsset",
    "KeyMaterial",
    "MigrationRecommendation",
    "RiskLevel",
    "ScanCategory",
    "ScanResult",
    "Vulnerability",
    "aggregate_risk",
    "calculate_agility_score",
    "calculate_hndl_risk",
    "calculate_qday_risk",
    "classify_algorithm",
    "is_deprecated",
    "recommend_pqc_replacement",
]
