"""Cryptographic algorithm classification registry.

Three buckets:
- :data:`QUANTUM_VULNERABLE` — broken by Shor's algorithm on a CRQC.
  RSA, DSA, ECDSA, ECDH, DH. Migrate to NIST PQC standards.
- :data:`QUANTUM_WEAKENED` — Grover's algorithm halves effective
  security. Symmetric and hash primitives. Mitigation: double key size.
- :data:`QUANTUM_RESISTANT` — NIST-standardized post-quantum
  algorithms (FIPS 203 / 204 / 205) plus selected backups (HQC, etc.).

Plus :data:`HYBRID_SCHEMES` documenting transition profiles
(RFC 9794, NIST SP 800-227).

Lookups are case-insensitive on canonical names; ``classify_algorithm``
normalizes by stripping a trailing key-size suffix when not needed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class AlgorithmClass(StrEnum):
    """Classification verdict for a given algorithm name."""

    QUANTUM_VULNERABLE = "QUANTUM_VULNERABLE"
    QUANTUM_WEAKENED = "QUANTUM_WEAKENED"
    QUANTUM_RESISTANT = "QUANTUM_RESISTANT"
    HYBRID = "HYBRID"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Quantum-vulnerable: broken by Shor on a sufficiently large CRQC.
# ---------------------------------------------------------------------------
QUANTUM_VULNERABLE: dict[str, dict[str, Any]] = {
    "RSA": {
        "min_safe_size": None,  # no classical key size saves you
        "deprecated_by": "ML-KEM (encryption) / ML-DSA (signing)",
        "use": "asymmetric_encryption_signature",
    },
    "DSA": {
        "min_safe_size": None,
        "deprecated_by": "ML-DSA",
        "use": "signature",
    },
    "ECDSA": {
        "min_safe_size": None,
        "deprecated_by": "ML-DSA",
        "use": "signature",
    },
    "ECDH": {
        "min_safe_size": None,
        "deprecated_by": "ML-KEM",
        "use": "key_agreement",
    },
    "DH": {
        "min_safe_size": None,
        "deprecated_by": "ML-KEM",
        "use": "key_agreement",
    },
    "EDDSA": {
        "min_safe_size": None,
        "deprecated_by": "ML-DSA",
        "use": "signature",
    },
}


# ---------------------------------------------------------------------------
# Quantum-weakened: Grover halves effective security. Double the key size.
# ---------------------------------------------------------------------------
QUANTUM_WEAKENED: dict[str, dict[str, Any]] = {
    "AES-128": {
        "effective_security_quantum_bits": 64,
        "recommended": "AES-256",
        "deprecated": False,
    },
    "AES-192": {
        "effective_security_quantum_bits": 96,
        "recommended": "AES-256",
        "deprecated": False,
    },
    "AES-256": {
        "effective_security_quantum_bits": 128,
        "recommended": "AES-256",
        "deprecated": False,
    },
    "ChaCha20": {
        "effective_security_quantum_bits": 128,
        "recommended": "ChaCha20",
        "deprecated": False,
    },
    "SHA-256": {
        "effective_security_quantum_bits": 128,
        "recommended": "SHA-384/SHA-512",
        "deprecated": False,
    },
    "SHA-384": {
        "effective_security_quantum_bits": 192,
        "recommended": "SHA-384",
        "deprecated": False,
    },
    "SHA-512": {
        "effective_security_quantum_bits": 256,
        "recommended": "SHA-512",
        "deprecated": False,
    },
    "SHA-1": {
        "effective_security_quantum_bits": 0,
        "recommended": "SHA-256+",
        "deprecated": True,  # already broken classically
    },
    "MD5": {
        "effective_security_quantum_bits": 0,
        "recommended": "SHA-256+",
        "deprecated": True,
    },
    "3DES": {
        "effective_security_quantum_bits": 56,
        "recommended": "AES-256",
        "deprecated": True,
    },
    "RC4": {
        "effective_security_quantum_bits": 0,
        "recommended": "AES-256-GCM",
        "deprecated": True,
    },
}


# ---------------------------------------------------------------------------
# Quantum-resistant: NIST PQC standards.
# ---------------------------------------------------------------------------
QUANTUM_RESISTANT: dict[str, dict[str, Any]] = {
    # FIPS 203 — ML-KEM (key encapsulation, ex CRYSTALS-Kyber)
    "ML-KEM-512": {"fips": "203", "category": 1, "use": "key_encapsulation"},
    "ML-KEM-768": {"fips": "203", "category": 3, "use": "key_encapsulation"},
    "ML-KEM-1024": {"fips": "203", "category": 5, "use": "key_encapsulation"},
    # FIPS 204 — ML-DSA (signature, ex CRYSTALS-Dilithium)
    "ML-DSA-44": {"fips": "204", "category": 2, "use": "signature"},
    "ML-DSA-65": {"fips": "204", "category": 3, "use": "signature"},
    "ML-DSA-87": {"fips": "204", "category": 5, "use": "signature"},
    # FIPS 205 — SLH-DSA (hash-based signature, ex SPHINCS+)
    "SLH-DSA-SHA2-128s": {"fips": "205", "category": 1, "use": "signature"},
    "SLH-DSA-SHA2-128f": {"fips": "205", "category": 1, "use": "signature"},
    "SLH-DSA-SHA2-192s": {"fips": "205", "category": 3, "use": "signature"},
    "SLH-DSA-SHA2-192f": {"fips": "205", "category": 3, "use": "signature"},
    "SLH-DSA-SHA2-256s": {"fips": "205", "category": 5, "use": "signature"},
    "SLH-DSA-SHA2-256f": {"fips": "205", "category": 5, "use": "signature"},
    "SLH-DSA-SHAKE-128s": {"fips": "205", "category": 1, "use": "signature"},
    "SLH-DSA-SHAKE-128f": {"fips": "205", "category": 1, "use": "signature"},
    "SLH-DSA-SHAKE-192s": {"fips": "205", "category": 3, "use": "signature"},
    "SLH-DSA-SHAKE-192f": {"fips": "205", "category": 3, "use": "signature"},
    "SLH-DSA-SHAKE-256s": {"fips": "205", "category": 5, "use": "signature"},
    "SLH-DSA-SHAKE-256f": {"fips": "205", "category": 5, "use": "signature"},
    # Backup KEM (selected 2025-03-11)
    "HQC-128": {"fips": "TBD", "category": 1, "use": "key_encapsulation"},
    "HQC-192": {"fips": "TBD", "category": 3, "use": "key_encapsulation"},
    "HQC-256": {"fips": "TBD", "category": 5, "use": "key_encapsulation"},
    # Stateful hash-based (NIST SP 800-208) — firmware signing
    "LMS": {"fips": "SP800-208", "category": 5, "use": "stateful_signature"},
    "XMSS": {"fips": "SP800-208", "category": 5, "use": "stateful_signature"},
}


# ---------------------------------------------------------------------------
# Hybrid combinations — used during the transition (RFC 9794).
# ---------------------------------------------------------------------------
HYBRID_SCHEMES: dict[str, dict[str, Any]] = {
    "X25519+ML-KEM-768": {"rfc": "9794", "phase": "transition", "use": "key_agreement"},
    "X25519+ML-KEM-1024": {"rfc": "9794", "phase": "transition", "use": "key_agreement"},
    "P-256+ML-KEM-768": {"rfc": "9794", "phase": "transition", "use": "key_agreement"},
    "ECDSA-P256+ML-DSA-65": {"rfc": "draft", "phase": "transition", "use": "signature"},
    "RSA-3072+ML-DSA-65": {"rfc": "draft", "phase": "transition", "use": "signature"},
}


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------


def _normalize(name: str) -> str:
    """Uppercase, strip whitespace; preserve internal hyphens."""
    return name.strip().upper()


_MIN_PARTS_FOR_KEYSIZE_STRIP = 2


def _strip_keysize(name: str) -> str:
    """Drop a trailing '-<digits>' if the algorithm root carries no number."""
    parts = name.split("-")
    if len(parts) >= _MIN_PARTS_FOR_KEYSIZE_STRIP and parts[-1].isdigit():
        # Keep the suffix when it disambiguates the algorithm name itself
        # (e.g. ML-KEM-768, AES-128). Strip only when the root matches a
        # plain entry (RSA-2048 -> RSA).
        root = parts[0]
        if root in QUANTUM_VULNERABLE:
            return root
    return name


def classify_algorithm(name: str) -> AlgorithmClass:
    """Return the broad classification bucket for an algorithm name.

    Lookup order: HYBRID_SCHEMES -> QUANTUM_RESISTANT -> QUANTUM_VULNERABLE
    (with key-size strip) -> QUANTUM_WEAKENED -> UNKNOWN.
    """
    norm = _normalize(name)
    if norm in HYBRID_SCHEMES:
        return AlgorithmClass.HYBRID
    if norm in QUANTUM_RESISTANT:
        return AlgorithmClass.QUANTUM_RESISTANT
    stripped = _strip_keysize(norm)
    if stripped in QUANTUM_VULNERABLE:
        return AlgorithmClass.QUANTUM_VULNERABLE
    if norm in QUANTUM_WEAKENED:
        return AlgorithmClass.QUANTUM_WEAKENED
    return AlgorithmClass.UNKNOWN


def is_deprecated(name: str) -> bool:
    """Return True for primitives already broken or deprecated by NIST."""
    norm = _normalize(name)
    if norm in QUANTUM_WEAKENED:
        return bool(QUANTUM_WEAKENED[norm].get("deprecated", False))
    return False


def recommend_pqc_replacement(name: str) -> str | None:
    """Suggest a NIST PQC replacement for a quantum-vulnerable algorithm.

    Heuristic mapping by canonical use:
    - signature -> ML-DSA-65 (NIST category 3, balanced)
    - key_agreement / key_encapsulation -> ML-KEM-768 (NIST category 3)
    - asymmetric_encryption_signature (RSA) -> ML-KEM/ML-DSA pair, returns ML-DSA

    Returns None for unknown algorithms. Intentionally conservative —
    callers should run :mod:`pqc_audit.core.risk` to refine by category.
    """
    norm = _normalize(name)
    stripped = _strip_keysize(norm)
    meta = QUANTUM_VULNERABLE.get(stripped)
    if meta is None:
        return None
    use = meta.get("use", "")
    if use == "key_agreement":
        return "ML-KEM-768"
    if use == "signature":
        return "ML-DSA-65"
    # Mixed-purpose primitives (RSA): default to signature target.
    return "ML-DSA-65"
