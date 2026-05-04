"""Tests for pqc_audit.core.algorithms — classification registry."""

from __future__ import annotations

import pytest


def test_quantum_vulnerable_keys() -> None:
    from pqc_audit.core.algorithms import QUANTUM_VULNERABLE

    for name in ("RSA", "DSA", "ECDSA", "ECDH", "DH"):
        assert name in QUANTUM_VULNERABLE


def test_quantum_weakened_keys() -> None:
    from pqc_audit.core.algorithms import QUANTUM_WEAKENED

    assert "AES-128" in QUANTUM_WEAKENED
    assert "SHA-1" in QUANTUM_WEAKENED
    assert "MD5" in QUANTUM_WEAKENED


def test_quantum_resistant_includes_nist_finalists() -> None:
    from pqc_audit.core.algorithms import QUANTUM_RESISTANT

    for name in (
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    ):
        assert name in QUANTUM_RESISTANT
        assert QUANTUM_RESISTANT[name]["fips"] in {"203", "204"}


def test_slh_dsa_present() -> None:
    from pqc_audit.core.algorithms import QUANTUM_RESISTANT

    slh = [n for n in QUANTUM_RESISTANT if n.startswith("SLH-DSA")]
    assert slh, "SLH-DSA variants missing"
    for name in slh:
        assert QUANTUM_RESISTANT[name]["fips"] == "205"


def test_hybrid_schemes_have_rfc_or_phase() -> None:
    from pqc_audit.core.algorithms import HYBRID_SCHEMES

    for name, meta in HYBRID_SCHEMES.items():
        assert "+" in name
        assert meta.get("phase") in {"transition", "long_term"}


def test_classify_rsa() -> None:
    from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm

    assert classify_algorithm("RSA") is AlgorithmClass.QUANTUM_VULNERABLE
    assert classify_algorithm("rsa-2048") is AlgorithmClass.QUANTUM_VULNERABLE


def test_classify_aes_weakened() -> None:
    from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm

    assert classify_algorithm("AES-128") is AlgorithmClass.QUANTUM_WEAKENED


def test_classify_ml_kem_resistant() -> None:
    from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm

    assert classify_algorithm("ML-KEM-768") is AlgorithmClass.QUANTUM_RESISTANT
    assert classify_algorithm("ml-dsa-65") is AlgorithmClass.QUANTUM_RESISTANT


def test_classify_unknown_returns_unknown() -> None:
    from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm

    assert classify_algorithm("snake-oil-512") is AlgorithmClass.UNKNOWN


def test_recommend_pqc_replacement_for_rsa() -> None:
    from pqc_audit.core.algorithms import recommend_pqc_replacement

    rec = recommend_pqc_replacement("RSA")
    assert rec is not None
    assert rec.startswith("ML-")


def test_recommend_pqc_replacement_for_ecdh_signing() -> None:
    from pqc_audit.core.algorithms import recommend_pqc_replacement

    # ECDH used for KEM-style key agreement → should suggest ML-KEM
    assert recommend_pqc_replacement("ECDH") == "ML-KEM-768"


def test_recommend_pqc_replacement_unknown() -> None:
    from pqc_audit.core.algorithms import recommend_pqc_replacement

    assert recommend_pqc_replacement("snake-oil") is None


@pytest.mark.parametrize(
    "name,expected_deprecated",
    [
        ("MD5", True),
        ("SHA-1", True),
        ("SHA-256", False),
    ],
)
def test_is_deprecated(name: str, expected_deprecated: bool) -> None:
    from pqc_audit.core.algorithms import is_deprecated

    assert is_deprecated(name) is expected_deprecated
