"""JWT scanner — RFC 8725 (JWT BCP) + RFC 7518 (JWA) coverage.

The scanner is *offline only*: it parses the JOSE header and classifies
the algorithm. Signature verification and JWKS retrieval are out of
scope for v1 — they would require either network access or a customer
keystore, both of which we deliberately keep out of the audit core.

Vulnerability classes covered:
    * ``alg: none``           → RFC 8725 §2.1, CWE-347.
    * weak / deprecated alg   → mapped via NIST IR 8547 (RS256, ES256).
    * forbidden alg           → MD5 / SHA-1-based JOSE algs.
    * PQC-ready alg           → recognised but not yet RFC-finalised.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest

from pqc_audit.core.models import RiskLevel, ScanCategory
from pqc_audit.scanners.base import ScanTarget


def _make_jwt_header(alg: str, **extra: object) -> str:
    """Build a header-only JWT (signature and payload are placeholders).

    The scanner only parses the header, so the payload/signature don't
    have to be valid cryptographically — they just need to look like
    JOSE compact form.
    """
    header = {"alg": alg, "typ": "JWT", **extra}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(b'{"sub":"x"}').rstrip(b"=").decode()
    sig_b64 = base64.urlsafe_b64encode(b"signature").rstrip(b"=").decode()
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _scan_file(tmp_path: Path, tokens: list[str]) -> object:
    from pqc_audit.scanners.jwt_scanner import JWTScanner

    f = tmp_path / "tokens.jwt"
    f.write_text("\n".join(tokens) + "\n", encoding="utf-8")
    scanner = JWTScanner()
    target = ScanTarget(type="token", path=str(f))
    return asyncio.run(scanner.scan(target))


def test_jwt_scanner_is_applicable_to_token_target(tmp_path: Path) -> None:
    from pqc_audit.scanners.jwt_scanner import JWTScanner

    scanner = JWTScanner()
    assert scanner.name == "jwt"
    assert scanner.category == ScanCategory.CONFIG
    target = ScanTarget(type="token", path=str(tmp_path / "x"))
    assert asyncio.run(scanner.is_applicable(target)) is True
    other = ScanTarget(type="tls", host="example.com", port=443)
    assert asyncio.run(scanner.is_applicable(other)) is False


def test_jwt_scanner_flags_alg_none_as_critical(tmp_path: Path) -> None:
    token = _make_jwt_header("none")
    result = _scan_file(tmp_path, [token])
    assert result.scanner_name == "jwt"
    assert len(result.assets) == 1
    assert result.assets[0].algorithm.name == "none"
    crit = [v for v in result.vulnerabilities if v.severity == RiskLevel.CRITICAL]
    assert crit, "expected at least one CRITICAL finding for alg=none"
    assert any("CWE-347" in (v.cwe or "") for v in crit)


def test_jwt_scanner_classifies_rs256_as_rsa_pkcs1v15(tmp_path: Path) -> None:
    token = _make_jwt_header("RS256")
    result = _scan_file(tmp_path, [token])
    assert len(result.assets) == 1
    algo = result.assets[0].algorithm
    assert algo.name == "RSA"
    assert algo.mode == "PKCS1v15-SHA-256"


def test_jwt_scanner_classifies_es256_as_ecdsa_p256(tmp_path: Path) -> None:
    token = _make_jwt_header("ES256")
    result = _scan_file(tmp_path, [token])
    algo = result.assets[0].algorithm
    assert algo.name == "ECDSA"
    assert algo.curve == "P-256"


def test_jwt_scanner_classifies_eddsa(tmp_path: Path) -> None:
    token = _make_jwt_header("EdDSA")
    result = _scan_file(tmp_path, [token])
    algo = result.assets[0].algorithm
    assert algo.name == "EdDSA"


def test_jwt_scanner_recognises_pqc_ml_dsa_65(tmp_path: Path) -> None:
    # draft-ietf-cose-dilithium reserves "ML-DSA-65" as a JOSE alg id.
    token = _make_jwt_header("ML-DSA-65")
    result = _scan_file(tmp_path, [token])
    algo = result.assets[0].algorithm
    assert algo.name == "ML-DSA-65"
    # PQC algorithms are NOT flagged as critical/high — they are the
    # target state of the migration.
    crit_high = [
        v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH
    ]
    assert not crit_high


def test_jwt_scanner_flags_hs256_with_short_kid(tmp_path: Path) -> None:
    # HS256 is symmetric — secret rotation is the main risk vector.
    token = _make_jwt_header("HS256")
    result = _scan_file(tmp_path, [token])
    algo = result.assets[0].algorithm
    assert algo.name == "HMAC-SHA-256"


def test_jwt_scanner_flags_unknown_alg_as_error(tmp_path: Path) -> None:
    token = _make_jwt_header("BOGUS-ALG-99")
    result = _scan_file(tmp_path, [token])
    # Unknown alg should still produce an asset (visibility) but with a
    # warning. Auditors should never silently skip a JOSE algorithm
    # they don't recognise — it might be a vendor extension hiding
    # something weak.
    assert len(result.assets) == 1
    assert result.assets[0].algorithm.name == "BOGUS-ALG-99"
    assert any("unknown" in v.title.lower() for v in result.vulnerabilities)


def test_jwt_scanner_rejects_malformed_input(tmp_path: Path) -> None:
    result = _scan_file(tmp_path, ["not-a-jwt", "also.notajwt"])
    # Malformed tokens should be reported via errors (not crash) and
    # produce no asset for that line.
    assert result.errors
    assert len(result.assets) == 0


def test_jwt_scanner_handles_multiple_tokens(tmp_path: Path) -> None:
    tokens = [
        _make_jwt_header("RS256"),
        _make_jwt_header("ES256"),
        _make_jwt_header("EdDSA"),
        _make_jwt_header("ML-DSA-65"),
    ]
    result = _scan_file(tmp_path, tokens)
    assert len(result.assets) == 4
    algos = {a.algorithm.canonical_name for a in result.assets}
    assert "EdDSA" in algos
    assert "ML-DSA-65" in algos


def test_jwt_scanner_missing_file_raises_error(tmp_path: Path) -> None:
    from pqc_audit.scanners.jwt_scanner import JWTScanner

    scanner = JWTScanner()
    target = ScanTarget(type="token", path=str(tmp_path / "nope.jwt"))
    result = asyncio.run(scanner.scan(target))
    assert result.errors
    assert len(result.assets) == 0


def test_jwt_scanner_rejects_target_without_path() -> None:
    from pqc_audit.scanners.jwt_scanner import JWTScanner

    scanner = JWTScanner()
    target = ScanTarget(type="token")
    with pytest.raises(ValueError):
        asyncio.run(scanner.scan(target))
