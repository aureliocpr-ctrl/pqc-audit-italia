"""Mutual-TLS (mTLS) client certificate chain scanner.

Operates on a PEM bundle (leaf cert first, then intermediates, then
root — the standard order used by HAProxy, nginx, Envoy, AWS ALB).
Adds the checks specific to *client* certificate chains on top of the
existing TLS / cert scanner:

    * Leaf has ``digitalSignature`` Key Usage.
    * Leaf has ``clientAuth`` Extended Key Usage.
    * Intermediates have ``CA=True`` + ``keyCertSign``.
    * Chain consistency: issuer of cert N == subject of cert N+1.
    * Algorithm strength / expiry checks via the shared
      :func:`assess_certificate` so we stay in lockstep with the TLS
      assessor instead of drifting two parallel rule sets.

CRITICAL note: mTLS is a *trust* primitive. A misconfigured client
chain is silently accepted by many TLS stacks (no clientAuth EKU
enforcement, default trust-store fallback), so the findings here
target precisely the failure modes that pass server-side checks
yet break the security model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtendedKeyUsageOID

from pqc_audit.core.models import (
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget
from pqc_audit.scanners.tls_scanner import (
    assess_certificate,
    certificate_to_key_material,
    extract_algorithm_from_cert,
    extract_signature_hash_name,
)

_MAX_CHAIN_BYTES = 16 * 1024 * 1024  # 16 MB — same family of safety as cert_scanner


def _load_chain(path: Path) -> list[x509.Certificate]:
    """Read a PEM bundle and return every certificate in file order."""
    if not path.is_file():
        raise FileNotFoundError(f"mTLS chain not found: {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"unable to stat {path}: {exc}") from exc
    if size > _MAX_CHAIN_BYTES:
        raise ValueError(f"chain file too large: {size} bytes > {_MAX_CHAIN_BYTES} cap")
    raw = path.read_bytes()
    return list(x509.load_pem_x509_certificates(raw))


def _basic_constraints(cert: x509.Certificate) -> x509.BasicConstraints | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except ExtensionNotFound:
        return None
    return ext.value


def _key_usage(cert: x509.Certificate) -> x509.KeyUsage | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except ExtensionNotFound:
        return None
    return ext.value


def _eku(cert: x509.Certificate) -> x509.ExtendedKeyUsage | None:
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except ExtensionNotFound:
        return None
    return ext.value


def _is_ca(cert: x509.Certificate) -> bool:
    bc = _basic_constraints(cert)
    return bool(bc and bc.ca)


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _validate_chain_links(certs: list[x509.Certificate]) -> list[str]:
    """Return human-readable issues for issuer/subject mismatches."""
    issues: list[str] = []
    for i in range(len(certs) - 1):
        child = certs[i]
        parent = certs[i + 1]
        if child.issuer != parent.subject:
            issues.append(
                f"chain break between position {i} ({child.subject.rfc4514_string()!r}) "
                f"and {i + 1} ({parent.subject.rfc4514_string()!r}): issuer/subject mismatch"
            )
    return issues


class MTLSScanner:
    """Audit a mutual-TLS client certificate bundle (PEM)."""

    name = "mtls"
    category = ScanCategory.FILESYSTEM

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "certs"

    async def scan(self, target: ScanTarget) -> ScanResult:  # noqa: PLR0912 — each branch is a discrete mTLS rule (leaf KU, leaf EKU, leaf-not-CA, intermediate-CA, intermediate-keyCertSign, root-self-signed, chain-link, expired, weak key). Splitting them produces churn without clarity.
        if target.path is None:
            raise ValueError("mTLS scanner requires target.path pointing to a PEM chain file")

        started_at = _now_utc()
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        path = Path(target.path)

        try:
            chain = _load_chain(path)  # noqa: ASYNC240 — local fs, protocol-async only
        except FileNotFoundError as e:
            errors.append(str(e))
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=_now_utc(),
                errors=errors,
            )
        except (ValueError, Exception) as e:  # noqa: BLE001 — surface every parse failure
            errors.append(f"could not load chain: {type(e).__name__}: {e}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=_now_utc(),
                errors=errors,
            )

        if not chain:
            errors.append("chain file contained zero certificates")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=_now_utc(),
                errors=errors,
            )

        leaf = chain[0]
        intermediates_and_root = chain[1:]

        # Build assets + delegate strength/expiry checks to the shared
        # assess_certificate so mTLS reuses TLS rules verbatim.
        now = _now_utc()
        for i, cert in enumerate(chain):
            alg = extract_algorithm_from_cert(cert)
            km = certificate_to_key_material(cert)
            hash_name = extract_signature_hash_name(cert)
            role = "leaf" if i == 0 else ("root" if i == len(chain) - 1 else "intermediate")
            asset_id = f"mtls://{path.as_posix()}#{i}-{role}"
            asset = CryptoAsset(
                asset_id=asset_id,
                category=ScanCategory.FILESYSTEM,
                algorithm=alg,
                location=f"{path}#position={i}-{role}",
                discovered_at=now,
                key_material=km,
                metadata={
                    "role": role,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "signature_hash": hash_name,
                    "is_ca": str(_is_ca(cert)),
                },
            )
            assets.append(asset)
            vulns.extend(assess_certificate(alg, km, hash_name=hash_name, asset_id=asset_id))

            # Cert-expired upgrade: assess_certificate already returns
            # warnings for near-expiry / past-expiry, but mTLS treats
            # an expired LEAF as CRITICAL (handshake will fail and
            # access will silently break — auditors need the loudest
            # severity).
            if cert.not_valid_after_utc < now:
                vulns.append(
                    Vulnerability(
                        title=f"mTLS {role} certificate expired",
                        description=(
                            f"Certificate at position {i} ({role}, subject "
                            f"{cert.subject.rfc4514_string()!r}) expired on "
                            f"{cert.not_valid_after_utc.isoformat()}."
                        ),
                        severity=RiskLevel.CRITICAL,
                        cwe="CWE-298",
                        references=(
                            "https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5",
                        ),
                        affected_asset_ids=(asset_id,),
                    )
                )

        # ----------------------- Leaf checks -----------------------
        leaf_asset_id = assets[0].asset_id
        leaf_ku = _key_usage(leaf)
        if leaf_ku is None or not leaf_ku.digital_signature:
            vulns.append(
                Vulnerability(
                    title="mTLS leaf missing digitalSignature Key Usage",
                    description=(
                        "RFC 5280 §4.2.1.3 mandates that a client certificate used "
                        "for TLS authentication carries the digitalSignature Key Usage "
                        "bit. Without it, conforming servers MUST reject the handshake."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-295",
                    references=("https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3",),
                    affected_asset_ids=(leaf_asset_id,),
                )
            )

        leaf_eku = _eku(leaf)
        if leaf_eku is None or ExtendedKeyUsageOID.CLIENT_AUTH not in leaf_eku:
            vulns.append(
                Vulnerability(
                    title="mTLS leaf missing clientAuth Extended Key Usage",
                    description=(
                        "The leaf certificate does not declare id-kp-clientAuth "
                        "(1.3.6.1.5.5.7.3.2) in its Extended Key Usage extension. "
                        "Most TLS stacks (OpenSSL, BoringSSL, NSS) reject such "
                        "certificates for client authentication."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-295",
                    references=("https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12",),
                    affected_asset_ids=(leaf_asset_id,),
                )
            )

        if _is_ca(leaf):
            vulns.append(
                Vulnerability(
                    title="mTLS leaf certificate has CA=True",
                    description=(
                        "The leaf certificate declares Basic Constraints CA=True. "
                        "Leaves used for mTLS authentication must NOT be CAs."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-295",
                    references=("https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9",),
                    affected_asset_ids=(leaf_asset_id,),
                )
            )

        # ----------------------- Intermediate checks -----------------------
        for i, cert in enumerate(intermediates_and_root, start=1):
            asset_id = assets[i].asset_id
            is_last = i == len(chain) - 1
            ku = _key_usage(cert)
            if not _is_ca(cert):
                vulns.append(
                    Vulnerability(
                        title=f"mTLS {assets[i].metadata['role']} cert at position {i} is not a CA",
                        description=(
                            "A certificate above the leaf in an mTLS chain must "
                            "declare Basic Constraints CA=True; otherwise the chain "
                            "cannot anchor trust."
                        ),
                        severity=RiskLevel.HIGH,
                        cwe="CWE-295",
                        references=(
                            "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9",
                        ),
                        affected_asset_ids=(asset_id,),
                    )
                )
            if ku is not None and not ku.key_cert_sign:
                role_label = assets[i].metadata["role"]
                vulns.append(
                    Vulnerability(
                        title=f"mTLS {role_label} cert at position {i} missing keyCertSign",
                        description=(
                            "CA certificates must include keyCertSign in their Key Usage "
                            "extension (RFC 5280 §4.2.1.3)."
                        ),
                        severity=RiskLevel.HIGH,
                        cwe="CWE-295",
                        references=(
                            "https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3",
                        ),
                        affected_asset_ids=(asset_id,),
                    )
                )
            if is_last and cert.issuer != cert.subject:
                vulns.append(
                    Vulnerability(
                        title="mTLS chain root is not self-signed",
                        description=(
                            "The final certificate in the chain has a different issuer "
                            "and subject — it is therefore not a root anchor. The "
                            "verifier will need an external trust store to terminate "
                            "the chain. Bundle the actual root or document the trust "
                            "store explicitly."
                        ),
                        severity=RiskLevel.MEDIUM,
                        cwe="CWE-295",
                        references=("https://datatracker.ietf.org/doc/html/rfc5280",),
                        affected_asset_ids=(asset_id,),
                    )
                )

        # ----------------------- Chain consistency -----------------------
        for issue in _validate_chain_links(chain):
            vulns.append(
                Vulnerability(
                    title="mTLS chain break",
                    description=issue,
                    severity=RiskLevel.HIGH,
                    cwe="CWE-295",
                    references=("https://datatracker.ietf.org/doc/html/rfc5280#section-6",),
                    affected_asset_ids=(leaf_asset_id,),
                )
            )

        return ScanResult(
            scanner_name=self.name,
            target=str(path),
            assets=assets,
            vulnerabilities=vulns,
            started_at=started_at,
            finished_at=_now_utc(),
            errors=errors,
        )


__all__ = ["MTLSScanner"]
