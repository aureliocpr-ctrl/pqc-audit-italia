"""Tests for the JWKS scanner (Sprint 5 #2).

The scanner has two input modes:
  * Live HTTPS fetch (``target.host`` = URL).
  * Offline file (``target.path``).

These tests exercise the offline path with hand-crafted JWKS payloads
plus the SSRF guard. The live HTTPS path is unit-tested by
monkeypatching ``_fetch_jwks_bytes`` so we never make a real network
request inside the test suite.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest

from pqc_audit.core.models import RiskLevel
from pqc_audit.scanners.base import ScanTarget
from pqc_audit.scanners.jwks_scanner import (
    JWKSScanner,
    _fetch_jwks_bytes,
    _is_public_host,
)


def _run(scanner: JWKSScanner, target: ScanTarget):
    return asyncio.run(scanner.scan(target))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --- Offline JSON file mode -----------------------------------------


def test_jwks_scanner_flags_rsa_1024_as_critical(tmp_path: Path) -> None:
    # 1024 bits = 128 bytes of modulus
    n_b64 = _b64url(b"\xab" * 128)
    jwks = {"keys": [{"kty": "RSA", "kid": "weak-rsa-1024", "n": n_b64, "e": "AQAB"}]}
    f = tmp_path / "weak.json"
    f.write_text(json.dumps(jwks), encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    assert result.assets
    titles = [v.title for v in result.vulnerabilities]
    assert any("below FIPS minimum" in t for t in titles)
    assert any(v.severity == RiskLevel.CRITICAL for v in result.vulnerabilities)


def test_jwks_scanner_flags_rsa_2048_as_high(tmp_path: Path) -> None:
    jwks = {"keys": [{"kty": "RSA", "kid": "default", "n": _b64url(b"\x00" * 256), "e": "AQAB"}]}
    f = tmp_path / "rsa2048.json"
    f.write_text(json.dumps(jwks), encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    assert any("RSA-2048" in v.title for v in result.vulnerabilities)
    assert any(v.severity == RiskLevel.HIGH for v in result.vulnerabilities)


def test_jwks_scanner_flags_ecdsa_p256_as_high(tmp_path: Path) -> None:
    ec_x = _b64url(b"x" * 32)
    ec_y = _b64url(b"y" * 32)
    jwks = {"keys": [{"kty": "EC", "kid": "ec1", "crv": "P-256", "x": ec_x, "y": ec_y}]}
    f = tmp_path / "ec.json"
    f.write_text(json.dumps(jwks), encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    titles = [v.title for v in result.vulnerabilities]
    assert any("ECDSA-P-256" in t for t in titles)


def test_jwks_scanner_flags_symmetric_oct_key_as_medium(tmp_path: Path) -> None:
    jwks = {"keys": [{"kty": "oct", "kid": "shared", "k": _b64url(b"secret" * 8), "alg": "HS256"}]}
    f = tmp_path / "sym.json"
    f.write_text(json.dumps(jwks), encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    severities = {v.severity for v in result.vulnerabilities}
    assert RiskLevel.MEDIUM in severities


def test_jwks_scanner_flags_sha1_alg_rs1_as_high(tmp_path: Path) -> None:
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "legacy",
                "alg": "RS1",
                "n": _b64url(b"\x00" * 384),  # 3072 bits to avoid the RSA-size finding overlapping
                "e": "AQAB",
            }
        ]
    }
    f = tmp_path / "sha1.json"
    f.write_text(json.dumps(jwks), encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    titles = " || ".join(v.title for v in result.vulnerabilities)
    assert "RS1" in titles


def test_jwks_scanner_accepts_ed25519_okp_without_finding(tmp_path: Path) -> None:
    jwks = {"keys": [{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": _b64url(b"x" * 32)}]}
    f = tmp_path / "ed.json"
    f.write_text(json.dumps(jwks), encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    # Ed25519 is not in IR 8547's classical deprecation set, no HIGH/CRITICAL.
    severities = {v.severity for v in result.vulnerabilities}
    assert RiskLevel.HIGH not in severities
    assert RiskLevel.CRITICAL not in severities


def test_jwks_scanner_rejects_payload_without_keys_array(tmp_path: Path) -> None:
    f = tmp_path / "broken.json"
    f.write_text('{"not_keys": []}', encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    assert any("missing top-level 'keys' array" in e for e in result.errors)


def test_jwks_scanner_handles_malformed_json(tmp_path: Path) -> None:
    f = tmp_path / "bad.json"
    f.write_text("not json at all", encoding="utf-8")
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(f)))
    assert any("not valid JSON" in e for e in result.errors)


def test_jwks_scanner_missing_path_records_error(tmp_path: Path) -> None:
    bogus = tmp_path / "does_not_exist.json"
    result = _run(JWKSScanner(), ScanTarget(type="jwks", path=str(bogus)))
    assert any("not found" in e for e in result.errors)


# --- API surface guards ---------------------------------------------


def test_jwks_scanner_rejects_both_host_and_path(tmp_path: Path) -> None:
    placeholder = tmp_path / "placeholder.json"
    placeholder.write_text("{}", encoding="utf-8")
    target = ScanTarget(
        type="jwks",
        host="https://x.example.com/jwks.json",
        path=str(placeholder),
    )
    result = _run(JWKSScanner(), target)
    assert any("not both" in e for e in result.errors)


def test_jwks_scanner_rejects_target_without_source() -> None:
    target = ScanTarget(type="jwks")
    result = _run(JWKSScanner(), target)
    assert any("requires target.host" in e for e in result.errors)


def test_jwks_scanner_is_applicable_only_for_jwks() -> None:
    scanner = JWKSScanner()
    assert asyncio.run(scanner.is_applicable(ScanTarget(type="jwks", path="x"))) is True
    assert asyncio.run(scanner.is_applicable(ScanTarget(type="tls", host="x"))) is False


# --- SSRF guard ------------------------------------------------------


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("localhost", False),
        ("127.0.0.1", False),
        ("10.0.0.1", False),
        ("192.168.1.1", False),
        ("172.16.0.1", False),
        ("169.254.169.254", False),  # AWS metadata service — classic SSRF target
        ("::1", False),
        ("fe80::1", False),
    ],
)
def test_is_public_host_rejects_private_loopback_linklocal(hostname: str, expected: bool) -> None:
    assert _is_public_host(hostname) is expected


def test_fetch_jwks_bytes_rejects_non_https_scheme() -> None:
    with pytest.raises(ValueError, match="must use https"):
        _fetch_jwks_bytes("http://example.com/jwks.json")


def test_fetch_jwks_bytes_rejects_file_scheme() -> None:
    with pytest.raises(ValueError, match="must use https"):
        _fetch_jwks_bytes("file:///etc/passwd")


def test_fetch_jwks_bytes_rejects_localhost_url() -> None:
    with pytest.raises(ValueError, match="SSRF"):
        _fetch_jwks_bytes("https://localhost/jwks.json")


def test_fetch_jwks_bytes_rejects_aws_metadata_url() -> None:
    with pytest.raises(ValueError, match="SSRF"):
        _fetch_jwks_bytes("https://169.254.169.254/latest/meta-data/")


# --- Live HTTPS path (mocked) ---------------------------------------


def test_jwks_scanner_live_https_path_via_monkeypatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live fetch is exercised by stubbing out ``_fetch_jwks_bytes``."""
    fake_payload = json.dumps(
        {"keys": [{"kty": "RSA", "kid": "live", "n": _b64url(b"\x00" * 256), "e": "AQAB"}]}
    ).encode()

    def _fake_fetch(url: str, *, timeout: float = 10.0) -> bytes:  # noqa: ARG001
        return fake_payload

    monkeypatch.setattr("pqc_audit.scanners.jwks_scanner._fetch_jwks_bytes", _fake_fetch)
    result = _run(
        JWKSScanner(),
        ScanTarget(type="jwks", host="https://example.com/.well-known/jwks.json"),
    )
    assert len(result.assets) == 1
    assert result.assets[0].metadata["kid"] == "live"
    titles = [v.title for v in result.vulnerabilities]
    assert any("RSA-2048" in t for t in titles)


def test_jwks_scanner_live_https_path_records_fetch_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ValueError from the fetcher must surface as a ScanResult.errors entry."""

    def _fake_fetch(url: str, *, timeout: float = 10.0) -> bytes:  # noqa: ARG001
        raise ValueError("HTTP 404")

    monkeypatch.setattr("pqc_audit.scanners.jwks_scanner._fetch_jwks_bytes", _fake_fetch)
    result = _run(
        JWKSScanner(),
        ScanTarget(type="jwks", host="https://example.com/.well-known/jwks.json"),
    )
    assert result.assets == []
    assert any("could not fetch JWKS" in e for e in result.errors)
