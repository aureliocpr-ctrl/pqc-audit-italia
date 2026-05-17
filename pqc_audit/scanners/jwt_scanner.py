"""JWT / JOSE scanner.

Detects the JOSE ``alg`` of every token in a file and emits a
:class:`CryptoAsset` plus the relevant :class:`Vulnerability` entries.

Scope (v1, offline):
    * Parses the JOSE header (segment 1 of the compact-form JWT).
    * Maps the ``alg`` to a canonical :class:`Algorithm`.
    * Flags ``alg: none`` (RFC 8725 §2.1, CWE-347), MD5/SHA-1 based
      algorithms, and unknown vendor extensions.
    * Does NOT verify signatures and does NOT fetch JWKS endpoints —
      those require either a customer key or network egress and would
      blur the audit boundary. They are tracked for v2 behind an
      explicit opt-in.

The file format is one JWT per line, ``#`` lines and blank lines are
ignored. Tokens that do not parse are reported via
:attr:`ScanResult.errors` rather than crashing the run.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path

from pqc_audit.core.clock import frozen_now
from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

# JWT compact form is ``header.payload.signature`` — at least the first
# two segments must be present even for unsigned tokens (alg=none keeps
# the trailing dot). We compare against this constant in ``_parse_header``.
_MIN_JWT_SEGMENTS = 2


# ---------------------------------------------------------------------------
# JOSE alg → Algorithm mapping
# ---------------------------------------------------------------------------
# Sources:
#   * RFC 7518 (JWA) — classical algorithms.
#   * RFC 8037 — EdDSA in JOSE.
#   * RFC 8725 (JWT BCP) — security considerations, especially "none".
#   * draft-ietf-cose-dilithium / draft-ietf-jose-pqc — PQC alg ids.
_JOSE_ALG_MAP: dict[str, dict[str, str | None]] = {
    "none": {"name": "none", "mode": None, "curve": None},
    "HS256": {"name": "HMAC-SHA-256", "mode": None, "curve": None},
    "HS384": {"name": "HMAC-SHA-384", "mode": None, "curve": None},
    "HS512": {"name": "HMAC-SHA-512", "mode": None, "curve": None},
    "RS256": {"name": "RSA", "mode": "PKCS1v15-SHA-256", "curve": None},
    "RS384": {"name": "RSA", "mode": "PKCS1v15-SHA-384", "curve": None},
    "RS512": {"name": "RSA", "mode": "PKCS1v15-SHA-512", "curve": None},
    "RS1": {"name": "RSA", "mode": "PKCS1v15-SHA-1", "curve": None},
    "PS256": {"name": "RSA-PSS", "mode": "SHA-256", "curve": None},
    "PS384": {"name": "RSA-PSS", "mode": "SHA-384", "curve": None},
    "PS512": {"name": "RSA-PSS", "mode": "SHA-512", "curve": None},
    "ES256": {"name": "ECDSA", "mode": None, "curve": "P-256"},
    "ES256K": {"name": "ECDSA", "mode": None, "curve": "secp256k1"},
    "ES384": {"name": "ECDSA", "mode": None, "curve": "P-384"},
    "ES512": {"name": "ECDSA", "mode": None, "curve": "P-521"},
    "EdDSA": {"name": "EdDSA", "mode": None, "curve": None},
    # PQC — draft JOSE registration in progress (IETF). Listed so an
    # auditor sees them as ALLOWED end-state, not as unknowns.
    "ML-DSA-44": {"name": "ML-DSA-44", "mode": None, "curve": None},
    "ML-DSA-65": {"name": "ML-DSA-65", "mode": None, "curve": None},
    "ML-DSA-87": {"name": "ML-DSA-87", "mode": None, "curve": None},
    "SLH-DSA-SHA2-128s": {"name": "SLH-DSA-SHA2-128s", "mode": None, "curve": None},
    "SLH-DSA-SHA2-192s": {"name": "SLH-DSA-SHA2-192s", "mode": None, "curve": None},
    "SLH-DSA-SHA2-256s": {"name": "SLH-DSA-SHA2-256s", "mode": None, "curve": None},
}


def _b64url_decode(segment: str) -> bytes:
    """RFC 7515 base64url decoder tolerant of missing ``=`` padding."""
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"malformed base64url segment: {e}") from e


def _parse_header(token: str) -> dict[str, object]:
    """Extract the JOSE header dict from a compact-form JWT.

    Raises :class:`ValueError` for any structural issue — the caller
    catches it and reports it via :attr:`ScanResult.errors`.
    """
    parts = token.strip().split(".")
    if len(parts) < _MIN_JWT_SEGMENTS:
        raise ValueError(f"not a compact-form JWT (expected 2+ segments, got {len(parts)})")
    header_bytes = _b64url_decode(parts[0])
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"header is not valid JSON: {e}") from e
    if not isinstance(header, dict):
        raise ValueError("header is not a JSON object")
    return header


def _algorithm_for(alg_id: str) -> Algorithm:
    """Map a JOSE alg id to a canonical :class:`Algorithm`."""
    spec = _JOSE_ALG_MAP.get(alg_id)
    if spec is None:
        # Unknown alg — surface it verbatim so the report shows what the
        # token actually claims. The vulnerability layer will flag it.
        return Algorithm(name=alg_id)
    return Algorithm(
        name=str(spec["name"]),
        mode=spec["mode"],
        curve=spec["curve"],
    )


def _vulnerabilities_for(alg_id: str, asset_id: str) -> list[Vulnerability]:
    """Translate a JOSE alg id into the relevant findings."""
    vulns: list[Vulnerability] = []
    if alg_id == "none":
        vulns.append(
            Vulnerability(
                title="JWT alg=none accepted",
                description=(
                    "The token declares alg=none which disables signature "
                    "verification entirely. RFC 8725 §2.1 mandates rejecting "
                    "tokens with alg=none unless the receiver explicitly opts "
                    "in to unsigned JWTs."
                ),
                severity=RiskLevel.CRITICAL,
                cwe="CWE-347",
                references=(
                    "https://datatracker.ietf.org/doc/html/rfc8725#section-2.1",
                    "https://cwe.mitre.org/data/definitions/347.html",
                ),
                affected_asset_ids=(asset_id,),
            )
        )
        return vulns

    if alg_id == "RS1" or (alg_id.startswith("HS") and alg_id.endswith("1")):
        vulns.append(
            Vulnerability(
                title=f"JWT uses SHA-1 based algorithm {alg_id}",
                description=(
                    f"SHA-1 was withdrawn by NIST in 2024 (FIPS 180-4). "
                    f"Tokens signed with {alg_id} should be rejected and "
                    "the issuer migrated to SHA-256 or stronger."
                ),
                severity=RiskLevel.HIGH,
                cwe="CWE-327",
                references=("https://csrc.nist.gov/projects/hash-functions",),
                affected_asset_ids=(asset_id,),
            )
        )

    if alg_id in {"HS256", "HS384", "HS512"}:
        vulns.append(
            Vulnerability(
                title=f"JWT uses symmetric algorithm {alg_id}",
                description=(
                    "Symmetric JOSE algorithms require the verifier to hold "
                    "the same secret as the issuer. Cross-service use is "
                    "discouraged; prefer asymmetric algorithms (RS256, "
                    "ES256, EdDSA, ML-DSA-65) for distributed verification."
                ),
                severity=RiskLevel.LOW,
                cwe="CWE-321",
                references=("https://datatracker.ietf.org/doc/html/rfc8725#section-3.5",),
                affected_asset_ids=(asset_id,),
            )
        )

    if alg_id not in _JOSE_ALG_MAP:
        vulns.append(
            Vulnerability(
                title=f"JWT unknown alg {alg_id}",
                description=(
                    f"The token declares alg={alg_id!r} which is not "
                    "registered in RFC 7518 / RFC 8037 / draft-ietf-jose-pqc. "
                    "A vendor extension may be in use — verify the issuer "
                    "is not silently downgrading to a weak primitive."
                ),
                severity=RiskLevel.MEDIUM,
                cwe="CWE-757",
                references=("https://www.iana.org/assignments/jose/jose.xhtml",),
                affected_asset_ids=(asset_id,),
            )
        )

    return vulns


class JWTScanner:
    """Scanner for JWT / JOSE tokens stored in a flat file."""

    name = "jwt"
    category = ScanCategory.CONFIG

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "token"

    async def scan(self, target: ScanTarget) -> ScanResult:
        if target.path is None:
            raise ValueError("JWT scanner requires target.path pointing to a token file")

        started_at = frozen_now()
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        path = Path(target.path)

        if not path.is_file():  # noqa: ASYNC240 — scanner is async only to satisfy the Protocol; this is local fs metadata, not blocking I/O worth offloading
            errors.append(f"token file not found: {path}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=frozen_now(),
                errors=errors,
            )

        try:
            raw = path.read_text(encoding="utf-8")  # noqa: ASYNC240 — see is_file() note above
        except OSError as e:
            errors.append(f"could not read token file {path}: {e}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=frozen_now(),
                errors=errors,
            )

        for line_no, raw_line in enumerate(raw.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                header = _parse_header(line)
            except ValueError as e:
                errors.append(f"line {line_no}: {e}")
                continue
            alg_id = str(header.get("alg") or "").strip()
            if not alg_id:
                errors.append(f"line {line_no}: header is missing 'alg'")
                continue
            asset_id = f"jwt://{path.name}#L{line_no}"
            asset = CryptoAsset(
                asset_id=asset_id,
                category=ScanCategory.CONFIG,
                algorithm=_algorithm_for(alg_id),
                location=f"{path}:{line_no}",
                discovered_at=frozen_now(),
                metadata={
                    "jose_alg": alg_id,
                    "kid": str(header.get("kid") or ""),
                    "typ": str(header.get("typ") or ""),
                },
            )
            assets.append(asset)
            vulns.extend(_vulnerabilities_for(alg_id, asset_id))

        return ScanResult(
            scanner_name=self.name,
            target=str(path),
            assets=assets,
            vulnerabilities=vulns,
            started_at=started_at,
            finished_at=frozen_now(),
            errors=errors,
        )


__all__ = ["JWTScanner"]
