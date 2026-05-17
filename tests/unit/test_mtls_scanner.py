"""mTLS scanner — client certificate chain audit.

The mTLS scanner sits on top of the regular cert scanner and adds the
checks specific to *client* certificate chains used for mutual-TLS:

    * Leaf certificate has ``digitalSignature`` Key Usage.
    * Leaf certificate has ``clientAuth`` Extended Key Usage.
    * Each intermediate has ``CA=True`` Basic Constraint and
      ``keyCertSign`` Key Usage.
    * Chain consistency: subject of cert N matches issuer of cert N-1.
    * Signature algorithm strength (delegated to the existing TLS
      assessor for parity).

The tests generate ephemeral RSA / EC keypairs and X.509 certificates
in-process to keep the suite hermetic.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pqc_audit.core.models import RiskLevel, ScanCategory
from pqc_audit.scanners.base import ScanTarget


def _build_cert(
    *,
    subject_cn: str,
    issuer_cn: str,
    issuer_key: rsa.RSAPrivateKey | None = None,
    is_ca: bool,
    key_usages: dict[str, bool] | None = None,
    eku: list[x509.ObjectIdentifier] | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    rsa_bits: int = 2048,
    sig_hash: hashes.HashAlgorithm | None = None,
) -> tuple[bytes, rsa.RSAPrivateKey]:
    """Build a single PEM-encoded X.509 cert. Returns (pem_bytes, key)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    signing_key = issuer_key if issuer_key is not None else key
    now = datetime.now(UTC)
    nbf = not_before or (now - timedelta(days=1))
    naf = not_after or (now + timedelta(days=365))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nbf)
        .not_valid_after(naf)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if key_usages is None:
        key_usages = (
            {"key_cert_sign": True, "crl_sign": True} if is_ca else {"digital_signature": True}
        )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=key_usages.get("digital_signature", False),
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=key_usages.get("key_cert_sign", False),
            crl_sign=key_usages.get("crl_sign", False),
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(signing_key, sig_hash or hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM), key


def _chain_pem(certs_pem: list[bytes]) -> str:
    return "".join(c.decode("utf-8") for c in certs_pem)


def _write_chain(tmp_path: Path, certs_pem: list[bytes]) -> Path:
    chain_path = tmp_path / "chain.pem"
    chain_path.write_text(_chain_pem(certs_pem), encoding="utf-8")
    return chain_path


def _scan(path: Path) -> object:
    from pqc_audit.scanners.mtls_scanner import MTLSScanner

    scanner = MTLSScanner()
    target = ScanTarget(type="certs", path=str(path))
    return asyncio.run(scanner.scan(target))


def test_mtls_scanner_metadata() -> None:
    from pqc_audit.scanners.mtls_scanner import MTLSScanner

    scanner = MTLSScanner()
    assert scanner.name == "mtls"
    assert scanner.category == ScanCategory.FILESYSTEM


def test_mtls_scanner_valid_chain_no_mtls_specific_findings(tmp_path: Path) -> None:
    """A well-formed chain produces NO mTLS-specific findings.

    RSA-2048 itself is flagged as quantum-vulnerable by the shared
    ``assess_certificate`` — that's a TLS-level finding, not an mTLS
    structural one. The mTLS scanner specifically must not add KU /
    EKU / chain / expiry findings to a clean chain.
    """
    root_pem, root_key = _build_cert(subject_cn="Root CA", issuer_cn="Root CA", is_ca=True)
    leaf_pem, _ = _build_cert(
        subject_cn="client.example",
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=False,
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    chain_path = _write_chain(tmp_path, [leaf_pem, root_pem])
    result = _scan(chain_path)
    mtls_specific_keywords = ("clientAuth", "digitalSignature", "chain", "expired", "keyCertSign")
    mtls_findings = [
        v for v in result.vulnerabilities if any(k in v.title for k in mtls_specific_keywords)
    ]
    assert not mtls_findings, (
        f"unexpected mTLS-structural findings: {[v.title for v in mtls_findings]}"
    )
    assert len(result.assets) == 2


def test_mtls_scanner_flags_missing_client_auth_eku(tmp_path: Path) -> None:
    root_pem, root_key = _build_cert(subject_cn="Root CA", issuer_cn="Root CA", is_ca=True)
    # Leaf has NO EKU at all → no clientAuth.
    leaf_pem, _ = _build_cert(
        subject_cn="client.example",
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=False,
        eku=None,
    )
    chain_path = _write_chain(tmp_path, [leaf_pem, root_pem])
    result = _scan(chain_path)
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert any("clientAuth" in v.title for v in high)


def test_mtls_scanner_flags_missing_digital_signature_ku(tmp_path: Path) -> None:
    root_pem, root_key = _build_cert(subject_cn="Root CA", issuer_cn="Root CA", is_ca=True)
    leaf_pem, _ = _build_cert(
        subject_cn="client.example",
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=False,
        key_usages={"key_encipherment": True},  # no digital_signature
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    chain_path = _write_chain(tmp_path, [leaf_pem, root_pem])
    result = _scan(chain_path)
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert any("digitalSignature" in v.title for v in high)


def test_mtls_scanner_flags_chain_break(tmp_path: Path) -> None:
    # Build two unrelated chains and concatenate the wrong root.
    root_a_pem, _ = _build_cert(subject_cn="Root A", issuer_cn="Root A", is_ca=True)
    root_b_pem, root_b_key = _build_cert(subject_cn="Root B", issuer_cn="Root B", is_ca=True)
    leaf_pem, _ = _build_cert(
        subject_cn="client.example",
        issuer_cn="Root B",
        issuer_key=root_b_key,
        is_ca=False,
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
    )
    # Leaf was signed by Root B but the chain ships Root A.
    chain_path = _write_chain(tmp_path, [leaf_pem, root_a_pem])
    result = _scan(chain_path)
    medium_or_higher = [v for v in result.vulnerabilities if v.severity >= RiskLevel.MEDIUM]
    assert any("chain break" in v.title.lower() for v in medium_or_higher)


def test_mtls_scanner_flags_rsa_1024(tmp_path: Path) -> None:
    root_pem, root_key = _build_cert(subject_cn="Root CA", issuer_cn="Root CA", is_ca=True)
    leaf_pem, _ = _build_cert(
        subject_cn="client.example",
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=False,
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
        rsa_bits=1024,
    )
    chain_path = _write_chain(tmp_path, [leaf_pem, root_pem])
    result = _scan(chain_path)
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert any("1024" in v.title or "undersized" in v.title.lower() for v in high), (
        f"expected undersized RSA finding, got: {[v.title for v in high]}"
    )


def test_mtls_scanner_flags_expired_leaf(tmp_path: Path) -> None:
    root_pem, root_key = _build_cert(subject_cn="Root CA", issuer_cn="Root CA", is_ca=True)
    long_ago_start = datetime.now(UTC) - timedelta(days=400)
    long_ago_end = datetime.now(UTC) - timedelta(days=30)
    leaf_pem, _ = _build_cert(
        subject_cn="client.example",
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=False,
        eku=[ExtendedKeyUsageOID.CLIENT_AUTH],
        not_before=long_ago_start,
        not_after=long_ago_end,
    )
    chain_path = _write_chain(tmp_path, [leaf_pem, root_pem])
    result = _scan(chain_path)
    crit = [v for v in result.vulnerabilities if v.severity >= RiskLevel.CRITICAL]
    assert any("expired" in v.title.lower() for v in crit)


def test_mtls_scanner_missing_file(tmp_path: Path) -> None:
    from pqc_audit.scanners.mtls_scanner import MTLSScanner

    scanner = MTLSScanner()
    target = ScanTarget(type="certs", path=str(tmp_path / "missing.pem"))
    result = asyncio.run(scanner.scan(target))
    assert result.errors


def test_mtls_scanner_requires_path() -> None:
    from pqc_audit.scanners.mtls_scanner import MTLSScanner

    scanner = MTLSScanner()
    with pytest.raises(ValueError):
        asyncio.run(scanner.scan(ScanTarget(type="certs")))
