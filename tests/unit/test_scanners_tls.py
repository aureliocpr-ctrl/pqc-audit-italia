"""Tests for pqc_audit.scanners.tls_scanner — pure parsing logic.

The TLS scanner has two layers:
1. Pure parsing helpers — identify algorithm, key size, curve, hash
   from a parsed x509 certificate. Tested here with offline fixtures.
2. Async network handshake — covered separately in integration tests
   to keep this suite fast and offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


def _build_self_signed_rsa_cert(key_size: int = 2048):
    """Build a fresh self-signed RSA certificate in memory."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test.example.it")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert


def _build_self_signed_ecdsa_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test.example.it")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert


def test_extract_algorithm_from_rsa_cert() -> None:
    from pqc_audit.scanners.tls_scanner import extract_algorithm_from_cert

    cert = _build_self_signed_rsa_cert(key_size=2048)
    alg = extract_algorithm_from_cert(cert)
    assert alg.name == "RSA"
    assert alg.key_size_bits == 2048


def test_extract_algorithm_from_rsa_4096() -> None:
    from pqc_audit.scanners.tls_scanner import extract_algorithm_from_cert

    cert = _build_self_signed_rsa_cert(key_size=4096)
    alg = extract_algorithm_from_cert(cert)
    assert alg.key_size_bits == 4096


def test_extract_algorithm_from_ecdsa_cert() -> None:
    from pqc_audit.scanners.tls_scanner import extract_algorithm_from_cert

    cert = _build_self_signed_ecdsa_cert()
    alg = extract_algorithm_from_cert(cert)
    assert alg.name == "ECDSA"
    assert alg.curve == "secp256r1"


def test_extract_signature_hash_sha256() -> None:
    from pqc_audit.scanners.tls_scanner import extract_signature_hash_name

    cert = _build_self_signed_rsa_cert(key_size=2048)
    assert extract_signature_hash_name(cert) == "SHA-256"


def test_certificate_to_key_material_has_fingerprint() -> None:
    from pqc_audit.scanners.tls_scanner import certificate_to_key_material

    cert = _build_self_signed_rsa_cert(key_size=2048)
    km = certificate_to_key_material(cert)
    assert km.algorithm == "RSA"
    assert km.key_size_bits == 2048
    assert len(km.public_key_fingerprint_sha256) == 64
    # Hex
    int(km.public_key_fingerprint_sha256, 16)


def test_assess_rsa_2048_quantum_vulnerable() -> None:
    from pqc_audit.scanners.tls_scanner import (
        assess_certificate,
        certificate_to_key_material,
        extract_algorithm_from_cert,
    )

    cert = _build_self_signed_rsa_cert(key_size=2048)
    alg = extract_algorithm_from_cert(cert)
    km = certificate_to_key_material(cert)
    vulns = assess_certificate(alg, km, hash_name="SHA-256")
    titles = [v.title for v in vulns]
    assert any("quantum" in t.lower() for t in titles)


def test_assess_sha1_signed_cert_flags_weak_hash() -> None:
    from pqc_audit.scanners.tls_scanner import (
        assess_certificate,
        certificate_to_key_material,
    )
    from pqc_audit.core.models import Algorithm

    cert = _build_self_signed_rsa_cert(key_size=2048)
    km = certificate_to_key_material(cert)
    vulns = assess_certificate(
        Algorithm(name="RSA", key_size_bits=2048),
        km,
        hash_name="SHA-1",
    )
    titles = [v.title for v in vulns]
    assert any("sha-1" in t.lower() or "deprecated hash" in t.lower() for t in titles)


def test_assess_short_rsa_flags_undersize() -> None:
    from pqc_audit.scanners.tls_scanner import (
        assess_certificate,
        certificate_to_key_material,
    )
    from pqc_audit.core.models import Algorithm

    cert = _build_self_signed_rsa_cert(key_size=2048)
    km = certificate_to_key_material(cert)
    short_alg = Algorithm(name="RSA", key_size_bits=1024)
    vulns = assess_certificate(short_alg, km, hash_name="SHA-256")
    titles = [v.title.lower() for v in vulns]
    assert any("under" in t or "short" in t or "1024" in t for t in titles)
