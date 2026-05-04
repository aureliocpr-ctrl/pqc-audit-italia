"""TLS / SSL scanner.

Two layers:

* **Pure parsing helpers** — given a parsed x509 certificate, extract
  algorithm, key size, curve, hash, fingerprint, and produce
  vulnerability findings. No I/O. Unit-tested offline.

* **Async network handshake** — :class:`TLSScanner.scan` opens a
  socket to ``host:port``, performs the TLS handshake using the
  standard library ``ssl`` module, captures the peer certificate, and
  delegates to the pure layer. Exercised via integration tests.

The scanner does **not** attempt protocol downgrade or cipher fuzzing
— it only identifies what the server presents. This keeps the tool
defensive and safe to run in production environments.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm, is_deprecated
from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    KeyMaterial,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

_SCANNER_NAME = "tls"

# Minimum recommended sizes (NIST + AgID-aligned).
_MIN_RSA_BITS = 2048
_MIN_DSA_BITS = 2048
_MIN_EC_BITS = 256


def _hash_name(raw: str | None) -> str:
    """Normalize cryptography hash class repr to canonical ``SHA-256`` form."""
    if not raw:
        return "UNKNOWN"
    upper = raw.upper().replace("_", "-")
    # Common canonicalizations
    canonicals = {
        "SHA1": "SHA-1",
        "SHA224": "SHA-224",
        "SHA256": "SHA-256",
        "SHA384": "SHA-384",
        "SHA512": "SHA-512",
        "MD5": "MD5",
    }
    return canonicals.get(upper.replace("-", ""), upper)


def extract_signature_hash_name(cert: x509.Certificate) -> str:
    """Return canonical hash name used for the certificate signature."""
    if cert.signature_hash_algorithm is None:
        return "UNKNOWN"
    return _hash_name(cert.signature_hash_algorithm.name)


def extract_algorithm_from_cert(cert: x509.Certificate) -> Algorithm:
    """Inspect ``cert.public_key()`` and return a typed :class:`Algorithm`."""
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return Algorithm(name="RSA", key_size_bits=pk.key_size)
    if isinstance(pk, dsa.DSAPublicKey):
        return Algorithm(name="DSA", key_size_bits=pk.key_size)
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return Algorithm(
            name="ECDSA",
            key_size_bits=pk.curve.key_size,
            curve=pk.curve.name,
        )
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return Algorithm(name="EdDSA", key_size_bits=256, curve="Ed25519")
    if isinstance(pk, ed448.Ed448PublicKey):
        return Algorithm(name="EdDSA", key_size_bits=448, curve="Ed448")
    return Algorithm(name=type(pk).__name__)


def certificate_to_key_material(cert: x509.Certificate) -> KeyMaterial:
    """Build a :class:`KeyMaterial` (no private bits) from a certificate."""
    alg = extract_algorithm_from_cert(cert)
    pub_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(pub_der).hexdigest()
    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    self_signed = cert.subject == cert.issuer
    return KeyMaterial(
        algorithm=alg.name,
        key_size_bits=alg.key_size_bits or 0,
        public_key_fingerprint_sha256=fp,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        is_self_signed=self_signed,
        is_ca=is_ca,
    )


def assess_certificate(
    alg: Algorithm,
    km: KeyMaterial,
    *,
    hash_name: str,
    asset_id: str = "",
) -> list[Vulnerability]:
    """Pure-function vulnerability assessment based on parsed metadata."""
    vulns: list[Vulnerability] = []
    affected = (asset_id,) if asset_id else ()

    cls = classify_algorithm(alg.name)
    if cls is AlgorithmClass.QUANTUM_VULNERABLE:
        vulns.append(
            Vulnerability(
                title=f"Quantum-vulnerable algorithm in use ({alg.canonical_name})",
                description=(
                    "This certificate uses an asymmetric algorithm broken by "
                    "Shor's algorithm on a CRQC. Plan migration to NIST PQC "
                    "(FIPS 203 / 204 / 205)."
                ),
                severity=RiskLevel.HIGH,
                cwe="CWE-327",
                affected_asset_ids=affected,
                references=(
                    "https://csrc.nist.gov/projects/post-quantum-cryptography",
                ),
            )
        )
    elif cls is AlgorithmClass.QUANTUM_WEAKENED:
        vulns.append(
            Vulnerability(
                title=f"Quantum-weakened primitive ({alg.canonical_name})",
                description=(
                    "Grover's algorithm halves effective security. Consider "
                    "doubling key size where applicable."
                ),
                severity=RiskLevel.MEDIUM,
                cwe="CWE-327",
                affected_asset_ids=affected,
            )
        )

    # Key-size sanity (classical posture, independent from PQC).
    if alg.name == "RSA" and (alg.key_size_bits or 0) < _MIN_RSA_BITS:
        vulns.append(
            Vulnerability(
                title=f"RSA key undersized ({alg.key_size_bits} bits, < {_MIN_RSA_BITS})",
                description="Modern guidelines (NIST, AgID) require RSA >= 2048 bits.",
                severity=RiskLevel.HIGH,
                cwe="CWE-326",
                affected_asset_ids=affected,
            )
        )
    if alg.name == "DSA" and (alg.key_size_bits or 0) < _MIN_DSA_BITS:
        vulns.append(
            Vulnerability(
                title=f"DSA key undersized ({alg.key_size_bits} bits, < {_MIN_DSA_BITS})",
                description="DSA is being phased out; do not use < 2048 bits.",
                severity=RiskLevel.HIGH,
                cwe="CWE-326",
                affected_asset_ids=affected,
            )
        )
    if alg.name == "ECDSA" and (alg.key_size_bits or 0) < _MIN_EC_BITS:
        vulns.append(
            Vulnerability(
                title=f"EC key undersized ({alg.key_size_bits} bits, < {_MIN_EC_BITS})",
                description="Use P-256 or higher for elliptic curve signatures.",
                severity=RiskLevel.HIGH,
                cwe="CWE-326",
                affected_asset_ids=affected,
            )
        )

    # Signature hash sanity.
    if is_deprecated(hash_name):
        vulns.append(
            Vulnerability(
                title=f"Deprecated hash algorithm in signature ({hash_name})",
                description=(
                    f"Certificate signed with {hash_name}, which is broken or "
                    "deprecated. Re-issue using SHA-256 or stronger."
                ),
                severity=RiskLevel.HIGH,
                cwe="CWE-328",
                affected_asset_ids=affected,
            )
        )

    # Self-signed leaf in a public-facing TLS service.
    if km.is_self_signed and not km.is_ca:
        vulns.append(
            Vulnerability(
                title="Self-signed leaf certificate",
                description=(
                    "The presented certificate is self-signed and not a CA. "
                    "Public services should use certificates issued by a "
                    "trusted CA."
                ),
                severity=RiskLevel.LOW,
                cwe="CWE-295",
                affected_asset_ids=affected,
            )
        )

    return vulns


async def _handshake(host: str, port: int, *, timeout: float = 8.0) -> dict[str, Any]:
    """Perform a TLS handshake and capture the peer certificate (DER).

    Pure stdlib ``ssl`` to avoid heavy dependencies. Runs in a worker
    thread so the rest of the async pipeline isn't blocked.
    """
    def _blocking() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                return {
                    "der": der,
                    "version": tls.version(),
                    "cipher": tls.cipher(),  # tuple (name, ssl_version, secret_bits)
                }

    return await asyncio.to_thread(_blocking)


class TLSScanner:
    """Concrete scanner for ``type='tls'`` targets."""

    name: str = _SCANNER_NAME
    category: ScanCategory = ScanCategory.NETWORK

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "tls" and bool(target.host) and target.port is not None

    async def scan(self, target: ScanTarget) -> ScanResult:
        started = datetime.now(timezone.utc)
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        target_repr = f"{target.host}:{target.port}"

        try:
            handshake = await _handshake(target.host or "", int(target.port or 443))
            der = handshake["der"]
            if not der:
                errors.append("server returned no certificate")
            else:
                cert = x509.load_der_x509_certificate(der)
                alg = extract_algorithm_from_cert(cert)
                km = certificate_to_key_material(cert)
                hash_name = extract_signature_hash_name(cert)
                asset_id = f"tls://{target_repr}"
                assets.append(
                    CryptoAsset(
                        asset_id=asset_id,
                        category=ScanCategory.NETWORK,
                        algorithm=alg,
                        location=target_repr,
                        discovered_at=started,
                        key_material=km,
                        metadata={
                            "tls_version": handshake.get("version") or "",
                            "cipher": (handshake.get("cipher") or [""])[0]
                            if handshake.get("cipher")
                            else "",
                            "signature_hash": hash_name,
                        },
                    )
                )
                vulns.extend(
                    assess_certificate(alg, km, hash_name=hash_name, asset_id=asset_id)
                )
        except Exception as e:  # noqa: BLE001 — surfaced to caller as a soft error
            errors.append(f"{type(e).__name__}: {e}")

        finished = datetime.now(timezone.utc)
        return ScanResult(
            scanner_name=self.name,
            target=target_repr,
            assets=assets,
            vulnerabilities=vulns,
            started_at=started,
            finished_at=finished,
            errors=errors,
        )
