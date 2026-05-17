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
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm, is_deprecated
from pqc_audit.core.clock import frozen_now
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
                references=("https://csrc.nist.gov/projects/post-quantum-cryptography",),
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

    # Validity window — surface expired / not-yet-valid certs.
    # We do not depend on the *handshaking* client to refuse: a
    # browser will, but our auditor doesn't, by design (we want to
    # inspect even broken certs). Without this check the report
    # would silently miss "the cert expired six months ago" — a
    # real-world failure mode in PA / banche legacy stacks.
    now = frozen_now()
    if km.not_after is not None and km.not_after < now:
        days_expired = (now - km.not_after).days
        vulns.append(
            Vulnerability(
                title=f"Certificate expired ({days_expired} days ago)",
                description=(
                    f"Certificate validity ended at {km.not_after.isoformat()}. "
                    "Browsers and modern TLS clients reject this cert; the "
                    "service is operationally degraded and trust is broken."
                ),
                severity=RiskLevel.HIGH,
                cwe="CWE-298",
                affected_asset_ids=affected,
            )
        )
    if km.not_before is not None and km.not_before > now:
        days_until_valid = (km.not_before - now).days
        vulns.append(
            Vulnerability(
                title=f"Certificate not yet valid (starts in {days_until_valid} days)",
                description=(
                    f"Certificate validity begins at {km.not_before.isoformat()}. "
                    "Issued cert is being deployed before its activation date "
                    "— either a clock-skew issue or a deployment mistake."
                ),
                severity=RiskLevel.MEDIUM,
                cwe="CWE-298",
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


def classify_chain_positions(chain: list[x509.Certificate]) -> list[str]:
    """Label each cert in a TLS chain by its structural role.

    Given ``chain`` ordered leaf-first (the TLS Certificate handshake
    record convention), return one of:

    * ``"leaf"`` — first cert, identifies the service
    * ``"intermediate-N"`` — Nth intermediate CA (1-indexed by chain
      depth)
    * ``"root"`` — last cert AND ``subject == issuer`` (the trust
      anchor). Real-world TLS rarely ships the root on the wire — best
      practice is to terminate at the deepest intermediate and let the
      client resolve the root from its trust store. When we DO see a
      self-signed top, we still label it ``"root"`` so downstream
      reports can distinguish.

    Empty chain returns empty list.
    """
    n = len(chain)
    if n == 0:
        return []
    if n == 1:
        return ["leaf"]
    labels = ["leaf"]
    # Intermediates between leaf and the last cert
    for i in range(1, n - 1):
        labels.append(f"intermediate-{i}")
    # Classify the tail
    last = chain[-1]
    if last.subject == last.issuer:
        labels.append("root")
    else:
        labels.append(f"intermediate-{n - 1}")
    return labels


def extract_chain_summary(chain: list[x509.Certificate]) -> dict[str, Any]:
    """Produce a CBOM/SARIF-ready summary of a TLS chain.

    Output schema (stable contract used by reporters)::

        {
          "chain_length": int,
          "terminates_at_root": bool,    # last cert is self-signed
          "positions": ["leaf", "intermediate-1", ...],
          "subjects": ["CN=...", ...],
          "issuers": ["CN=...", ...],
          "signature_hashes": ["SHA-256", "SHA-384", ...],
          "algorithms": [
              {"name": "ECDSA", "key_size_bits": 256, "curve": "secp256r1"},
              ...
          ],
        }

    All lists preserve chain order (leaf first). Empty chain yields a
    dict with ``chain_length=0`` and empty lists — never raises.
    """
    n = len(chain)
    positions = classify_chain_positions(chain)
    subjects: list[str] = []
    issuers: list[str] = []
    signature_hashes: list[str] = []
    algorithms: list[dict[str, Any]] = []
    for cert in chain:
        subjects.append(cert.subject.rfc4514_string())
        issuers.append(cert.issuer.rfc4514_string())
        signature_hashes.append(extract_signature_hash_name(cert))
        alg = extract_algorithm_from_cert(cert)
        entry: dict[str, Any] = {"name": alg.name}
        if alg.key_size_bits is not None:
            entry["key_size_bits"] = alg.key_size_bits
        if alg.curve is not None:
            entry["curve"] = alg.curve
        algorithms.append(entry)
    terminates_at_root = bool(chain) and chain[-1].subject == chain[-1].issuer
    return {
        "chain_length": n,
        "terminates_at_root": terminates_at_root,
        "positions": positions,
        "subjects": subjects,
        "issuers": issuers,
        "signature_hashes": signature_hashes,
        "algorithms": algorithms,
    }


def assess_chain(
    chain: list[x509.Certificate],
    *,
    leaf_asset_id: str,
) -> list[Vulnerability]:
    """Produce chain-level vulnerability findings.

    Two layers of checks:

    1. **Per-cert** — for each intermediate/root, run
       :func:`assess_certificate` so weak intermediate keys, deprecated
       hashes, expired CAs, and quantum-vulnerable trust anchors all
       surface. ``affected_asset_ids`` points at the position-suffixed
       id (``leaf_asset_id#intermediate-1`` etc.) so downstream
       consumers can pinpoint the cert.

    2. **Chain-wide** — currently:

       * **Incomplete chain** (LOW) — server presented only a leaf and
         the leaf is NOT self-signed. Real audit finding for legacy
         stacks that forget to ship intermediates.

    The leaf itself is intentionally NOT re-assessed here:
    :class:`TLSScanner` already calls :func:`assess_certificate` on
    the leaf with the canonical ``leaf_asset_id``, and double-reporting
    would inflate severity counts in the executive summary.
    """
    findings: list[Vulnerability] = []
    if not chain:
        return findings

    positions = classify_chain_positions(chain)

    # Layer 2: chain-wide check (incomplete chain)
    if len(chain) == 1:
        only = chain[0]
        # Self-signed leaf is already handled by ``assess_certificate``
        # under the "Self-signed leaf certificate" finding. Avoid
        # double-reporting here.
        if only.subject != only.issuer:
            findings.append(
                Vulnerability(
                    title="Incomplete TLS chain (no intermediate sent)",
                    description=(
                        "Server presented only the leaf certificate. "
                        "Clients without the issuing intermediate in their "
                        "trust store will fail to validate. Legacy stacks "
                        "(old nginx/apache configs) commonly forget AIA "
                        "chasing or simply omit the chain. AgID and CA/B "
                        "Forum guidelines require shipping the full chain "
                        "except the root."
                    ),
                    severity=RiskLevel.LOW,
                    cwe="CWE-295",
                    affected_asset_ids=(leaf_asset_id,),
                )
            )

    # Layer 1: per-cert assessment for everything beyond the leaf
    for idx, (cert, label) in enumerate(zip(chain, positions, strict=False)):
        if idx == 0:
            # leaf — handled by TLSScanner.scan via assess_certificate
            continue
        alg = extract_algorithm_from_cert(cert)
        km = certificate_to_key_material(cert)
        hash_name = extract_signature_hash_name(cert)
        sub_asset_id = f"{leaf_asset_id}#{label}"
        sub_findings = assess_certificate(alg, km, hash_name=hash_name, asset_id=sub_asset_id)
        # Decorate titles with chain position so executive readers
        # immediately see WHERE in the chain the problem lives.
        for v in sub_findings:
            findings.append(
                Vulnerability(
                    title=f"[{label}] {v.title}",
                    description=v.description,
                    severity=v.severity,
                    cwe=v.cwe,
                    affected_asset_ids=v.affected_asset_ids,
                    references=v.references,
                )
            )
    return findings


async def _handshake(host: str, port: int, *, timeout_s: float = 8.0) -> dict[str, Any]:
    """Perform a TLS handshake and capture the peer certificate chain.

    Pure stdlib ``ssl`` to avoid heavy dependencies. Runs in a worker
    thread so the rest of the async pipeline isn't blocked.

    Returns a dict with:

    * ``der`` — leaf certificate DER bytes (for back-compat)
    * ``chain_der`` — full chain as ``list[bytes]`` (leaf first, root or
      last intermediate last). Empty list if the runtime does not
      support :py:meth:`ssl.SSLSocket.get_unverified_chain` (added in
      Python 3.13). Sprint 9d requires 3.13+ for chain validation.
    * ``version`` — negotiated protocol (e.g. ``"TLSv1.3"``)
    * ``cipher`` — tuple ``(name, version, secret_bits)``
    """

    def _blocking() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        # We are inspecting the certificate, not validating it: peers
        # under audit may legitimately present expired / self-signed
        # certificates that we want to surface as findings.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # noqa: S501 — intentional, see above
        with (
            socket.create_connection((host, port), timeout=timeout_s) as raw,
            ctx.wrap_socket(raw, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
            chain_der: list[bytes] = []
            # ``get_unverified_chain`` lands in Python 3.13 and returns
            # ``list[bytes]`` of DER-encoded certs (leaf first). On
            # older runtimes we degrade to ``[der]`` so callers see at
            # least the leaf instead of an empty list.
            if hasattr(tls, "get_unverified_chain"):
                try:
                    chain_der = list(tls.get_unverified_chain())
                except (ssl.SSLError, OSError, AttributeError):
                    chain_der = [der] if der else []
            elif der:
                chain_der = [der]
            return {
                "der": der,
                "chain_der": chain_der,
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
        started = frozen_now()
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        target_repr = f"{target.host}:{target.port}"

        try:
            handshake = await _handshake(target.host or "", int(target.port or 443))
            der = handshake["der"]
            chain_der_list: list[bytes] = list(handshake.get("chain_der") or [])
            # Fall back to single-cert chain if the runtime didn't surface one
            if not chain_der_list and der:
                chain_der_list = [der]

            if not der and not chain_der_list:
                errors.append("server returned no certificate")
            else:
                # Parse every cert in the chain up-front so summary +
                # per-cert assets share the same x509 objects.
                chain_certs: list[x509.Certificate] = []
                for raw in chain_der_list:
                    try:
                        chain_certs.append(x509.load_der_x509_certificate(raw))
                    except ValueError as ve:
                        errors.append(f"chain cert parse error: {ve}")
                if not chain_certs:
                    errors.append("no parsable certificates in chain")
                else:
                    summary = extract_chain_summary(chain_certs)
                    positions = summary["positions"]
                    leaf_cert = chain_certs[0]
                    leaf_alg = extract_algorithm_from_cert(leaf_cert)
                    leaf_km = certificate_to_key_material(leaf_cert)
                    leaf_hash = extract_signature_hash_name(leaf_cert)
                    leaf_asset_id = f"tls://{target_repr}"
                    assets.append(
                        CryptoAsset(
                            asset_id=leaf_asset_id,
                            category=ScanCategory.NETWORK,
                            algorithm=leaf_alg,
                            location=target_repr,
                            discovered_at=started,
                            key_material=leaf_km,
                            metadata={
                                "tls_version": handshake.get("version") or "",
                                "cipher": (handshake.get("cipher") or [""])[0]
                                if handshake.get("cipher")
                                else "",
                                "signature_hash": leaf_hash,
                                "chain_position": "leaf",
                                "chain_length": summary["chain_length"],
                                "terminates_at_root": summary["terminates_at_root"],
                                "chain_signature_hashes": summary["signature_hashes"],
                                "chain_subjects": summary["subjects"],
                            },
                        )
                    )
                    vulns.extend(
                        assess_certificate(
                            leaf_alg, leaf_km, hash_name=leaf_hash, asset_id=leaf_asset_id
                        )
                    )
                    # Emit one asset per non-leaf cert with the
                    # position-suffixed id contract from assess_chain.
                    for idx in range(1, len(chain_certs)):
                        sub_cert = chain_certs[idx]
                        sub_alg = extract_algorithm_from_cert(sub_cert)
                        sub_km = certificate_to_key_material(sub_cert)
                        sub_hash = extract_signature_hash_name(sub_cert)
                        sub_label = positions[idx]
                        sub_asset_id = f"{leaf_asset_id}#{sub_label}"
                        assets.append(
                            CryptoAsset(
                                asset_id=sub_asset_id,
                                category=ScanCategory.NETWORK,
                                algorithm=sub_alg,
                                location=target_repr,
                                discovered_at=started,
                                key_material=sub_km,
                                metadata={
                                    "signature_hash": sub_hash,
                                    "chain_position": sub_label,
                                    "subject": sub_cert.subject.rfc4514_string(),
                                    "issuer": sub_cert.issuer.rfc4514_string(),
                                },
                            )
                        )
                    vulns.extend(assess_chain(chain_certs, leaf_asset_id=leaf_asset_id))
        except Exception as e:  # noqa: BLE001 — surfaced to caller as a soft error
            errors.append(f"{type(e).__name__}: {e}")

        finished = frozen_now()
        return ScanResult(
            scanner_name=self.name,
            target=target_repr,
            assets=assets,
            vulnerabilities=vulns,
            started_at=started,
            finished_at=finished,
            errors=errors,
        )
