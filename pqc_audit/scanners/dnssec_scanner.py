"""DNSSEC scanner.

Enumerates the algorithms used in a DNSSEC zone by parsing
``dig +dnssec`` output or any RFC 1035 master file containing DNSKEY
records. Validation of signature chains and trust anchors is out of
scope for v1 — the goal is crypto-discovery for audit purposes, not
DNS resolution.

Algorithm catalogue follows the IANA DNSSEC Algorithm Numbers registry
plus RFC 8624 implementation guidance and the IETF
draft-ietf-dnsop-dnssec-pqc reservations for ML-DSA.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

# IANA DNSSEC Algorithm Numbers + RFC 8624 status.
# Tuple shape: (algorithm name, key size hint, curve, RFC 8624 status)
_ALG_REGISTRY: dict[int, tuple[str, int | None, str | None, str]] = {
    1: ("RSA-MD5", None, None, "MUST NOT"),
    3: ("DSA-SHA-1", None, None, "MUST NOT"),
    5: ("RSA-SHA-1", None, None, "NOT RECOMMENDED"),
    6: ("DSA-NSEC3-SHA-1", None, None, "MUST NOT"),
    7: ("RSASHA1-NSEC3-SHA-1", None, None, "NOT RECOMMENDED"),
    8: ("RSA-SHA-256", None, None, "RECOMMENDED"),
    10: ("RSA-SHA-512", None, None, "RECOMMENDED"),
    12: ("ECC-GOST", None, None, "MUST NOT"),
    # Key size is already encoded in the algorithm name (e.g. "Ed25519",
    # "ECDSA-P-256-SHA-256") so we deliberately omit ``key_size_bits``:
    # passing it would make ``canonical_name`` append a redundant -256
    # suffix.
    13: ("ECDSA-P-256-SHA-256", None, "P-256", "RECOMMENDED"),
    14: ("ECDSA-P-384-SHA-384", None, "P-384", "RECOMMENDED"),
    15: ("Ed25519", None, "Ed25519", "RECOMMENDED"),
    16: ("Ed448", None, "Ed448", "OPTIONAL"),
    # Tentative PQC reservations per draft-ietf-dnsop-dnssec-pqc.
    # Numbers are *not* yet IANA-allocated and may shift — the asset
    # carries the literal number in metadata so an auditor can still
    # cross-reference the draft revision.
    17: ("ML-DSA-44", None, None, "DRAFT (PQC)"),
    18: ("ML-DSA-65", None, None, "DRAFT (PQC)"),
    19: ("ML-DSA-87", None, None, "DRAFT (PQC)"),
}


def _algorithm_for(algo_num: int) -> tuple[Algorithm, str]:
    """Return (Algorithm, RFC 8624 status) for a DNSSEC algorithm number.

    Unknown numbers map to a placeholder ``Algorithm(name="DNSSEC-AlgN")``
    so the report shows what the zone actually advertises rather than
    silently dropping the record.
    """
    spec = _ALG_REGISTRY.get(algo_num)
    if spec is None:
        return (
            Algorithm(name=f"DNSSEC-Alg{algo_num}"),
            "UNKNOWN",
        )
    name, ksize, curve, status = spec
    return (
        Algorithm(name=name, key_size_bits=ksize, curve=curve),
        status,
    )


def _vulnerabilities_for(
    algo_num: int,
    algo: Algorithm,
    status: str,
    asset_id: str,
) -> list[Vulnerability]:
    """Translate an RFC 8624 status into findings."""
    vulns: list[Vulnerability] = []
    if status == "MUST NOT":
        vulns.append(
            Vulnerability(
                title=f"DNSSEC algorithm {algo_num} ({algo.name}) is MUST NOT per RFC 8624",
                description=(
                    f"DNSSEC algorithm number {algo_num} maps to {algo.name}, "
                    "which RFC 8624 §3.1 lists as MUST NOT for signing. "
                    "Zone operators must migrate to algorithm 8/13/14/15."
                ),
                severity=RiskLevel.CRITICAL,
                cwe="CWE-327",
                references=(
                    "https://datatracker.ietf.org/doc/html/rfc8624#section-3.1",
                ),
                affected_asset_ids=(asset_id,),
            )
        )
    elif status == "NOT RECOMMENDED":
        is_sha1 = "SHA-1" in algo.name
        vulns.append(
            Vulnerability(
                title=(
                    f"DNSSEC algorithm {algo_num} uses SHA-1 (NOT RECOMMENDED)"
                    if is_sha1
                    else f"DNSSEC algorithm {algo_num} ({algo.name}) is NOT RECOMMENDED"
                ),
                description=(
                    f"DNSSEC algorithm {algo_num} maps to {algo.name}. RFC 8624 "
                    "§3.1 lists it as NOT RECOMMENDED for signing. Migrate to "
                    "algorithm 8 (RSA/SHA-256), 13 (ECDSA P-256) or 15 (Ed25519)."
                ),
                severity=RiskLevel.HIGH,
                cwe="CWE-327",
                references=(
                    "https://datatracker.ietf.org/doc/html/rfc8624#section-3.1",
                ),
                affected_asset_ids=(asset_id,),
            )
        )
    elif status == "UNKNOWN":
        vulns.append(
            Vulnerability(
                title=f"DNSSEC unknown algorithm number {algo_num}",
                description=(
                    f"Algorithm number {algo_num} is not present in the IANA "
                    "DNSSEC Algorithm Numbers registry as of 2026-05. It may "
                    "be a private/experimental allocation — verify the zone "
                    "operator is not silently downgrading to a weak primitive."
                ),
                severity=RiskLevel.MEDIUM,
                cwe="CWE-757",
                references=(
                    "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml",
                ),
                affected_asset_ids=(asset_id,),
            )
        )
    elif status == "DRAFT (PQC)":
        # Informational — surface the use of a draft PQC algorithm so
        # operators know they may need to update bindings when the
        # final IANA allocation lands.
        vulns.append(
            Vulnerability(
                title=f"DNSSEC uses draft PQC algorithm {algo_num} ({algo.name})",
                description=(
                    f"Algorithm {algo_num} is a tentative reservation per "
                    "draft-ietf-dnsop-dnssec-pqc. Track the final IANA "
                    "allocation to avoid interop drift once finalised."
                ),
                severity=RiskLevel.INFO,
                references=(
                    "https://datatracker.ietf.org/doc/draft-ietf-dnsop-dnssec-pqc/",
                ),
                affected_asset_ids=(asset_id,),
            )
        )
    return vulns


def _parse_dnskey_line(line: str) -> int | None:
    """Return the algorithm number for a DNSKEY RR, or ``None`` for non-matches.

    Format (RFC 4034 §2.1)::

        name    ttl    class   DNSKEY    flags protocol algorithm <key>

    Indices we care about: the field immediately following ``DNSKEY``
    is the flags, then protocol, then algorithm. We use ``DNSKEY`` as a
    landmark token because TTL and class ordering can vary in real
    zone files (e.g. ``IN`` may come before TTL in BIND format).
    """
    tokens = line.split()
    try:
        idx = tokens.index("DNSKEY")
    except ValueError:
        return None
    # After DNSKEY we need at least: flags, protocol, algorithm, key.
    _MIN_FIELDS_AFTER_DNSKEY = 4
    if len(tokens) < idx + 1 + _MIN_FIELDS_AFTER_DNSKEY:
        raise ValueError(f"DNSKEY record truncated: {line!r}")
    flags_str = tokens[idx + 1]
    proto_str = tokens[idx + 2]
    algo_str = tokens[idx + 3]
    try:
        # Flags and protocol must parse to ints too, otherwise this is
        # a SIG/RRSIG line or a comment that happens to mention DNSKEY
        # as the type-covered.
        int(flags_str)
        int(proto_str)
        return int(algo_str)
    except ValueError as e:
        raise ValueError(f"DNSKEY fields are not integers: {line!r}") from e


class DNSSECScanner:
    """Offline DNSSEC zone-file scanner — DNSKEY algorithm enumeration."""

    name = "dnssec"
    category = ScanCategory.CONFIG

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "config"

    async def scan(self, target: ScanTarget) -> ScanResult:
        if target.path is None:
            raise ValueError("DNSSEC scanner requires target.path pointing to a zone file")

        started_at = datetime.now(UTC)
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        path = Path(target.path)

        if not path.is_file():  # noqa: ASYNC240 — protocol-async only, local fs metadata
            errors.append(f"zone file not found: {path}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=datetime.now(UTC),
                errors=errors,
            )

        try:
            raw = path.read_text(encoding="utf-8")  # noqa: ASYNC240 — see note above
        except OSError as e:
            errors.append(f"could not read zone file {path}: {e}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=datetime.now(UTC),
                errors=errors,
            )

        for line_no, raw_line in enumerate(raw.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(";"):
                continue
            try:
                algo_num = _parse_dnskey_line(line)
            except ValueError as e:
                errors.append(f"line {line_no}: {e}")
                continue
            if algo_num is None:
                continue
            algo, status = _algorithm_for(algo_num)
            asset_id = f"dnssec://{path.name}#L{line_no}"
            asset = CryptoAsset(
                asset_id=asset_id,
                category=ScanCategory.CONFIG,
                algorithm=algo,
                location=f"{path}:{line_no}",
                discovered_at=datetime.now(UTC),
                metadata={
                    "dnssec_algorithm_number": str(algo_num),
                    "rfc8624_status": status,
                },
            )
            assets.append(asset)
            vulns.extend(_vulnerabilities_for(algo_num, algo, status, asset_id))

        return ScanResult(
            scanner_name=self.name,
            target=str(path),
            assets=assets,
            vulnerabilities=vulns,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            errors=errors,
        )


__all__ = ["DNSSECScanner"]
