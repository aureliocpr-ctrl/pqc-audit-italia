"""Tests for pqc_audit.scanners.cert_scanner — local certificate file scanner.

The certificate scanner has two layers:
1. Pure file parsers (parse_certificate_file, cert_to_asset) — given a
   path on disk, parse PEM / DER and produce CryptoAsset + vulnerabilities.
2. Async :class:`CertificateScanner.scan` — recurses a directory or
   handles a single file, applies the parser, aggregates a ScanResult.

Tests stay offline and use freshly minted in-memory certificates so we
never depend on bundled fixtures going stale.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def _write_self_signed_rsa(
    out_path: Path,
    *,
    key_size: int = 2048,
    hash_name: str = "SHA-256",
    encoding: str = "PEM",
) -> Path:
    """Write a self-signed RSA cert to ``out_path`` and return the path."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    hash_map = {
        "SHA-1": hashes.SHA1(),  # noqa: S303 — intentional weak hash for testing
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512(),
    }
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.it")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(key, hash_map[hash_name])
    )
    if encoding == "PEM":
        out_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    else:
        out_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return out_path


def _write_self_signed_ec(out_path: Path, *, curve_name: str = "P-256") -> Path:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    curve_map = {
        "P-192": ec.SECP192R1(),
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
    }
    key = ec.generate_private_key(curve_map[curve_name])
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec.example.it")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    out_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return out_path


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------


def test_parse_certificate_file_pem(tmp_path: Path) -> None:
    from pqc_audit.scanners.cert_scanner import parse_certificate_file

    cert_path = _write_self_signed_rsa(tmp_path / "rsa2048.pem", key_size=2048)
    cert = parse_certificate_file(cert_path)
    assert cert.subject.rfc4514_string() == "CN=test.example.it"


def test_parse_certificate_file_der(tmp_path: Path) -> None:
    from pqc_audit.scanners.cert_scanner import parse_certificate_file

    cert_path = _write_self_signed_rsa(tmp_path / "rsa2048.der", key_size=2048, encoding="DER")
    cert = parse_certificate_file(cert_path)
    assert cert.subject.rfc4514_string() == "CN=test.example.it"


def test_parse_certificate_file_missing_raises(tmp_path: Path) -> None:
    from pqc_audit.scanners.cert_scanner import parse_certificate_file

    with pytest.raises(FileNotFoundError):
        parse_certificate_file(tmp_path / "does_not_exist.pem")


def test_parse_certificate_file_garbage_raises(tmp_path: Path) -> None:
    """Non-cert content should bubble up as a ValueError, not silently parse."""
    from pqc_audit.scanners.cert_scanner import parse_certificate_file

    bad = tmp_path / "junk.pem"
    bad.write_bytes(b"this is not a certificate")
    with pytest.raises(ValueError):
        parse_certificate_file(bad)


def test_cert_to_asset_rsa_2048(tmp_path: Path) -> None:
    from pqc_audit.scanners.cert_scanner import cert_to_asset, parse_certificate_file

    cert_path = _write_self_signed_rsa(tmp_path / "rsa2048.pem", key_size=2048)
    cert = parse_certificate_file(cert_path)
    asset = cert_to_asset(cert, cert_path)
    assert asset.algorithm.name == "RSA"
    assert asset.algorithm.key_size_bits == 2048
    assert asset.location == str(cert_path)
    assert asset.asset_id.startswith("cert://")
    assert asset.key_material is not None
    assert len(asset.key_material.public_key_fingerprint_sha256) == 64


# ---------------------------------------------------------------------------
# CertificateScanner — async file/dir scan
# ---------------------------------------------------------------------------


def test_certificate_scanner_is_applicable_to_certs() -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    scanner = CertificateScanner()
    target_ok = ScanTarget(type="certs", path="/tmp/dummy.pem")  # noqa: S108 — test fixture path
    target_no = ScanTarget(type="tls", host="example.it", port=443)
    assert asyncio.run(scanner.is_applicable(target_ok)) is True
    assert asyncio.run(scanner.is_applicable(target_no)) is False


def test_certificate_scanner_rsa_2048_clean(tmp_path: Path) -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    cert_path = _write_self_signed_rsa(tmp_path / "rsa2048.pem", key_size=2048)
    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(cert_path))
    result = asyncio.run(scanner.scan(target))

    assert result.scanner_name == "certs"
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.algorithm.name == "RSA"
    assert asset.algorithm.key_size_bits == 2048
    titles = [v.title.lower() for v in result.vulnerabilities]
    # RSA 2048 is quantum-vulnerable but classically OK; expect quantum hit but no undersize hit.
    assert any("quantum" in t for t in titles)
    assert not any("under" in t for t in titles)


def test_certificate_scanner_rsa_1024_flags_undersize(tmp_path: Path) -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    cert_path = _write_self_signed_rsa(tmp_path / "rsa1024.pem", key_size=1024)
    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(cert_path))
    result = asyncio.run(scanner.scan(target))

    titles = [v.title.lower() for v in result.vulnerabilities]
    assert any("under" in t or "1024" in t for t in titles)


def test_certificate_scanner_rsa_4096_future_proof_classically(tmp_path: Path) -> None:
    """RSA-4096 is quantum-vulnerable but classically strong: only quantum hit."""
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    cert_path = _write_self_signed_rsa(tmp_path / "rsa4096.pem", key_size=4096)
    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(cert_path))
    result = asyncio.run(scanner.scan(target))

    titles = [v.title.lower() for v in result.vulnerabilities]
    assert any("quantum" in t for t in titles)
    assert not any("under" in t for t in titles)


def test_certificate_scanner_ec_p256_quantum_only(tmp_path: Path) -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    cert_path = _write_self_signed_ec(tmp_path / "ec256.pem", curve_name="P-256")
    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(cert_path))
    result = asyncio.run(scanner.scan(target))

    asset = result.assets[0]
    assert asset.algorithm.name == "ECDSA"
    titles = [v.title.lower() for v in result.vulnerabilities]
    assert any("quantum" in t for t in titles)
    assert not any("under" in t for t in titles)


def test_certificate_scanner_ec_p192_flags_undersize(tmp_path: Path) -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    cert_path = _write_self_signed_ec(tmp_path / "ec192.pem", curve_name="P-192")
    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(cert_path))
    result = asyncio.run(scanner.scan(target))

    titles = [v.title.lower() for v in result.vulnerabilities]
    assert any("under" in t or "192" in t for t in titles)


def test_certificate_scanner_sha1_signature_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SHA-1 signed certs trigger a deprecated-hash finding.

    Modern ``cryptography`` (>=42) refuses to *sign* with SHA-1, so we
    can't synthesize one with the high-level builder. Instead we sign
    with SHA-256, then patch the hash-extraction helper to report
    SHA-1 — the bit the scanner relies on for its assessment.
    """
    from pqc_audit.scanners import cert_scanner
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    cert_path = _write_self_signed_rsa(tmp_path / "weak_hash.pem", key_size=2048)
    monkeypatch.setattr(cert_scanner, "extract_signature_hash_name", lambda _cert: "SHA-1")

    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(cert_path))
    result = asyncio.run(scanner.scan(target))

    titles = [v.title.lower() for v in result.vulnerabilities]
    assert any("sha-1" in t or "deprecated hash" in t for t in titles)


def test_certificate_scanner_directory_scan_multifile(tmp_path: Path) -> None:
    """Directory scan should walk recursively and pick up .pem / .crt / .der."""
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    sub = tmp_path / "nested"
    sub.mkdir()
    _write_self_signed_rsa(tmp_path / "a.pem", key_size=2048)
    _write_self_signed_ec(tmp_path / "b.crt", curve_name="P-256")
    _write_self_signed_rsa(sub / "c.der", key_size=2048, encoding="DER")
    # Non-cert file in the dir must be ignored, not crash the run.
    (tmp_path / "readme.txt").write_text("not a certificate")

    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(tmp_path))
    result = asyncio.run(scanner.scan(target))

    assert len(result.assets) == 3
    names = [a.algorithm.name for a in result.assets]
    assert names.count("RSA") == 2
    assert names.count("ECDSA") == 1


def test_certificate_scanner_missing_path_records_error(tmp_path: Path) -> None:
    """Missing path should not raise — error is captured in ScanResult.errors."""
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    scanner = CertificateScanner()
    target = ScanTarget(type="certs", path=str(tmp_path / "does_not_exist.pem"))
    result = asyncio.run(scanner.scan(target))

    assert result.assets == []
    assert result.errors  # populated, not empty
