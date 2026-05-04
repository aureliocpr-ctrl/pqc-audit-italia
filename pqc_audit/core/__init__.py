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
    "classify_algorithm",
    "is_deprecated",
    "recommend_pqc_replacement",
]
