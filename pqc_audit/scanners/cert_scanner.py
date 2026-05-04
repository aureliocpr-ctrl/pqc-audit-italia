"""Local X.509 certificate file scanner.

Two layers, mirroring :mod:`pqc_audit.scanners.tls_scanner`:

* **Pure parsers** — :func:`parse_certificate_file` and
  :func:`cert_to_asset` work on a single path. PEM and DER are both
  accepted, picked apart by content rather than by extension. No I/O
  beyond reading the file. Unit-tested offline.

* **Async scanner** — :class:`CertificateScanner.scan` walks a single
  file or a whole directory tree, runs the parsers, and aggregates a
  :class:`pqc_audit.core.models.ScanResult`. Per-file errors are
  isolated in ``ScanResult.errors`` so one bad cert never aborts the
  full run.

The classification logic itself is delegated to the shared
:func:`pqc_audit.scanners.tls_scanner.assess_certificate` so a TLS
peer cert and a file-based cert produce identical findings — the only
thing that differs is the asset id and category.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

from pqc_audit.core.models import (
    CryptoAsset,
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

_SCANNER_NAME = "certs"

# File extensions we consider candidates inside a directory walk. Files
# with unrelated extensions are skipped silently. Files with a candidate
# extension that fail to parse are recorded as scan errors.
_CERT_SUFFIXES: frozenset[str] = frozenset({".pem", ".crt", ".cer", ".der"})


def parse_certificate_file(path: Path) -> x509.Certificate:
    """Read a certificate from disk.

    Detects PEM (``-----BEGIN CERTIFICATE-----`` envelope) vs DER (raw
    binary) by content. Raises :class:`FileNotFoundError` if the path
    does not exist and :class:`ValueError` if the content cannot be
    parsed as a valid X.509 certificate in either format.
    """
    if not path.exists():
        raise FileNotFoundError(f"certificate file not found: {path}")
    raw = path.read_bytes()
    try:
        if b"-----BEGIN CERTIFICATE-----" in raw:
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover — defensive
        raise ValueError(f"unable to parse {path}: {exc}") from exc


def cert_to_asset(cert: x509.Certificate, source_path: Path) -> CryptoAsset:
    """Build a :class:`CryptoAsset` from a parsed certificate.

    The asset id uses the absolute path so two scanners on the same
    file converge on the same identifier. Category is FILESYSTEM —
    file-based certs are not network-observed.
    """
    alg = extract_algorithm_from_cert(cert)
    km = certificate_to_key_material(cert)
    hash_name = extract_signature_hash_name(cert)
    abs_path = source_path.resolve()
    asset_id = f"cert://{abs_path.as_posix()}"

    try:
        subject_cn = cert.subject.rfc4514_string()
    except ValueError:  # malformed name attributes
        subject_cn = ""
    try:
        issuer_dn = cert.issuer.rfc4514_string()
    except ValueError:
        issuer_dn = ""

    metadata: dict[str, str] = {
        "subject": subject_cn,
        "issuer": issuer_dn,
        "signature_hash": hash_name,
        "source_path": str(abs_path),
    }
    if alg.curve:
        metadata["curve"] = alg.curve

    return CryptoAsset(
        asset_id=asset_id,
        category=ScanCategory.FILESYSTEM,
        algorithm=alg,
        location=str(source_path),
        discovered_at=datetime.now(UTC),
        key_material=km,
        metadata=metadata,
    )


def _iter_candidate_files(root: Path) -> list[Path]:
    """Walk ``root`` recursively, returning every file with a known cert suffix."""
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in _CERT_SUFFIXES)


def _scan_one_file(path: Path) -> tuple[CryptoAsset | None, list[Vulnerability], str | None]:
    """Parse + assess a single certificate file. Returns (asset, vulns, error)."""
    try:
        cert = parse_certificate_file(path)
    except (FileNotFoundError, ValueError) as exc:
        return None, [], f"{path}: {type(exc).__name__}: {exc}"

    asset = cert_to_asset(cert, path)
    hash_name = extract_signature_hash_name(cert)
    assert asset.key_material is not None  # cert_to_asset always populates it
    vulns = assess_certificate(
        asset.algorithm,
        asset.key_material,
        hash_name=hash_name,
        asset_id=asset.asset_id,
    )
    return asset, vulns, None


class CertificateScanner:
    """Concrete scanner for ``type='certs'`` targets.

    Single-file targets parse exactly one cert. Directory targets walk
    the tree and apply the parser to every ``.pem`` / ``.crt`` /
    ``.cer`` / ``.der`` file, sorted for deterministic output.
    """

    name: str = _SCANNER_NAME
    category: ScanCategory = ScanCategory.FILESYSTEM

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "certs" and bool(target.path)

    async def scan(self, target: ScanTarget) -> ScanResult:
        started = datetime.now(UTC)
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []

        path_str = target.path or ""
        target_repr = path_str
        root = Path(path_str)

        # ``Path.exists`` is sync; off-loaded so the async loop is not blocked.
        exists = await asyncio.to_thread(root.exists)
        if not exists:
            errors.append(f"path not found: {root}")
            finished = datetime.now(UTC)
            return ScanResult(
                scanner_name=self.name,
                target=target_repr,
                assets=assets,
                vulnerabilities=vulns,
                started_at=started,
                finished_at=finished,
                errors=errors,
            )

        # Heavy lifting (file I/O + RSA / EC parsing) runs in a worker
        # thread so the event loop stays responsive.
        candidates = await asyncio.to_thread(_iter_candidate_files, root)
        for path in candidates:
            asset, file_vulns, err = await asyncio.to_thread(_scan_one_file, path)
            if asset is not None:
                assets.append(asset)
                vulns.extend(file_vulns)
            if err is not None:
                errors.append(err)

        finished = datetime.now(UTC)
        return ScanResult(
            scanner_name=self.name,
            target=target_repr,
            assets=assets,
            vulnerabilities=vulns,
            started_at=started,
            finished_at=finished,
            errors=errors,
        )
