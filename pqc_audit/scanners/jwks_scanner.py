"""JWKS (JSON Web Key Set) scanner — RFC 7517 + RFC 7518.

Live-fetches a JWKS endpoint (typical path:
``/.well-known/jwks.json``) and classifies every public key by
algorithm + key size. Complementary to ``jwt_scanner``: that one
inspects tokens at rest, this one inspects the *signing material*
exposed by the authority.

Scope (v1):
    * HTTPS only — refuses ``http://``, ``file://`` and any non-
      HTTPS scheme (TLS authenticity of the JWKS source is part of
      the security argument).
    * SSRF guard: hostname must resolve to a globally routable
      address. Loopback, link-local, private RFC1918, ULA fc00::/7,
      multicast, and reserved ranges are refused before the request
      is dispatched (CWE-918).
    * Response cap: 1 MiB (CWE-400). A non-2xx HTTP response is
      surfaced as a :attr:`ScanResult.errors` entry, not an asset.
    * Offline mode: a local JSON file can be inspected via
      ``target.path`` instead of ``target.host`` for airgapped use
      and reproducible test fixtures.

Key classification:
    * ``kty=RSA``: key size derived from the base64url-decoded
      modulus ``n`` (length × 8). Sub-FIPS sizes flagged CRITICAL,
      RSA-2048/3072 flagged HIGH (NIST IR 8547 deprecate 2030).
    * ``kty=EC``: curve from ``crv`` (P-256/P-384/P-521). NIST IR
      8547 deprecates P-256/P-384.
    * ``kty=OKP``: Ed25519 / Ed448 / X25519 / X448.
    * ``kty=oct``: symmetric (HMAC). Discouraged for cross-service
      verification (CWE-321).
    * ``alg=RS1`` / ``alg=HS*1``: SHA-1 based JOSE algorithm — HIGH
      (CWE-327).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

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

_DEFAULT_TIMEOUT_SECONDS = 10.0
_MAX_JWKS_BYTES = 1 * 1024 * 1024  # 1 MiB
_USER_AGENT = "pqc-audit-italia/0.3 (+https://github.com/aureliocpr-ctrl/pqc-audit-italia)"

# HTTP success range
_HTTP_OK_MIN = 200
_HTTP_OK_BELOW = 300

# NIST IR 8547 deprecation thresholds — sizes below 2048 fail FIPS
# minimum; sizes 2048/3072 are classical-and-deprecate-by-2030.
_RSA_FIPS_MIN_BITS = 2048
_RSA_DEPRECATE_AFTER_2030 = (2048, 3072)

_EC_CURVES: dict[str, dict[str, int | str]] = {
    "P-256": {"family": "ECDSA", "key_size_bits": 256},
    "P-384": {"family": "ECDSA", "key_size_bits": 384},
    "P-521": {"family": "ECDSA", "key_size_bits": 521},
    "secp256k1": {"family": "ECDSA", "key_size_bits": 256},
}


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------


def _is_public_host(hostname: str) -> bool:
    """Reject hostnames resolving to non-globally-routable addresses.

    Inspired by the SSRF mitigation in OAuth 2.0 metadata fetchers:
    we resolve the host once and refuse if ANY returned address is
    loopback / private / link-local / multicast / reserved. The check
    is intentionally conservative — a single private answer is enough
    to bail.
    """
    if not hostname or hostname in {"localhost"}:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for _, _, _, _, sockaddr in infos:
        addr_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        if (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return False
    return True


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------


def _fetch_jwks_bytes(url: str, *, timeout: float = _DEFAULT_TIMEOUT_SECONDS) -> bytes:
    """Fetch the JWKS document over HTTPS with SSRF + size guards."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"JWKS URL must use https://, got scheme={parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("JWKS URL must include a hostname")
    if not _is_public_host(parsed.hostname):
        raise ValueError(
            f"JWKS host {parsed.hostname!r} resolves to a private/loopback "
            "address (SSRF guard — CWE-918)"
        )
    req = urllib.request.Request(  # noqa: S310 — scheme is validated to https above
        url,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    )
    # Belt: hard-disable redirects. urllib by default follows up to 10
    # redirects via HTTPRedirectHandler — we install a no-op handler
    # so a 302 to http://internal/admin can't smuggle around the
    # scheme + SSRF guards. The default SSL context (certificate +
    # hostname verification on) is bound to the opener's HTTPSHandler.
    https_handler = urllib.request.HTTPSHandler(context=ssl.create_default_context())
    opener = urllib.request.build_opener(https_handler, _NoRedirectHandler())
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 — see above
        status = getattr(resp, "status", None) or resp.getcode()
        if status is None or not (_HTTP_OK_MIN <= status < _HTTP_OK_BELOW):
            raise ValueError(f"JWKS endpoint returned HTTP {status}")
        data = resp.read(_MAX_JWKS_BYTES + 1)
    if len(data) > _MAX_JWKS_BYTES:
        raise ValueError(f"JWKS response exceeds {_MAX_JWKS_BYTES} bytes")
    assert isinstance(data, bytes)  # noqa: S101 — urllib.response.read() is typed as Any
    return data


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx — see comment in :func:`_fetch_jwks_bytes`."""

    def redirect_request(  # noqa: D401 — see urllib.request signature
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"redirect refused: {newurl}",
            headers,  # type: ignore[arg-type]
            fp,  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# JWK → Algorithm + Vulnerability
# ---------------------------------------------------------------------------


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"malformed base64url: {e}") from e


def _rsa_key_size_bits(jwk: dict[str, object]) -> int | None:
    n = jwk.get("n")
    if not isinstance(n, str):
        return None
    try:
        return len(_b64url_decode(n)) * 8
    except ValueError:
        return None


def _algorithm_for_jwk(jwk: dict[str, object]) -> Algorithm:
    kty = str(jwk.get("kty") or "").upper()
    alg = str(jwk.get("alg") or "")
    if kty == "RSA":
        size = _rsa_key_size_bits(jwk)
        return Algorithm(name="RSA", key_size_bits=size or None, mode=alg or None)
    if kty == "EC":
        crv = str(jwk.get("crv") or "")
        spec = _EC_CURVES.get(crv)
        key_size = int(spec["key_size_bits"]) if spec else None
        return Algorithm(name="ECDSA", curve=crv or None, key_size_bits=key_size, mode=alg or None)
    if kty == "OKP":
        crv = str(jwk.get("crv") or "")
        # Ed25519/Ed448 carry their size in the curve name; X25519/X448
        # are key-agreement, not signature.
        return Algorithm(name=crv or "OKP", mode=alg or None)
    if kty == "OCT":
        return Algorithm(name="HMAC", mode=alg or None)
    return Algorithm(name=kty or "unknown")


def _vulnerabilities_for_jwk(jwk: dict[str, object], asset_id: str) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    kty = str(jwk.get("kty") or "").upper()
    alg = str(jwk.get("alg") or "")
    kid = str(jwk.get("kid") or "(no kid)")

    if kty == "RSA":
        size = _rsa_key_size_bits(jwk)
        if size is not None and size < _RSA_FIPS_MIN_BITS:
            vulns.append(
                Vulnerability(
                    title=f"JWKS RSA key '{kid}' below FIPS minimum ({size} bits)",
                    description=(
                        f"The JWKS exposes an RSA-{size} public key. NIST "
                        "SP 800-131A Rev. 2 disallows RSA below 2048 bits "
                        "for any FIPS-approved use."
                    ),
                    severity=RiskLevel.CRITICAL,
                    cwe="CWE-326",
                    references=("https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",),
                    affected_asset_ids=(asset_id,),
                )
            )
        elif size in _RSA_DEPRECATE_AFTER_2030:
            vulns.append(
                Vulnerability(
                    title=f"JWKS RSA-{size} key '{kid}' quantum-vulnerable (deprecate 2030)",
                    description=(
                        f"The JWKS exposes an RSA-{size} public key. NIST IR "
                        "8547 deprecates classical RSA for new use after "
                        "2030 and disallows after 2035. Plan migration to "
                        "ML-DSA (FIPS 204) before the deprecation date."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-326",
                    references=("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
                    affected_asset_ids=(asset_id,),
                )
            )

    if kty == "EC":
        crv = str(jwk.get("crv") or "")
        if crv in {"P-256", "P-384"}:
            vulns.append(
                Vulnerability(
                    title=f"JWKS ECDSA-{crv} key '{kid}' quantum-vulnerable (deprecate 2030)",
                    description=(
                        f"The JWKS exposes an ECDSA key on curve {crv}. NIST "
                        "IR 8547 deprecates classical ECDSA for new use after "
                        "2030. Plan migration to ML-DSA-65 (FIPS 204) or "
                        "ML-DSA-87 for the higher security category."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-326",
                    references=("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
                    affected_asset_ids=(asset_id,),
                )
            )
        elif crv == "secp256k1":
            vulns.append(
                Vulnerability(
                    title=f"JWKS uses non-NIST curve secp256k1 (kid '{kid}')",
                    description=(
                        "secp256k1 is not on the FIPS-approved curve list. "
                        "Acceptable for blockchain use cases but not for "
                        "PA / regulated workloads."
                    ),
                    severity=RiskLevel.MEDIUM,
                    cwe="CWE-326",
                    references=("https://csrc.nist.gov/pubs/fips/186/5/final",),
                    affected_asset_ids=(asset_id,),
                )
            )

    if kty == "OCT":
        vulns.append(
            Vulnerability(
                title=f"JWKS exposes symmetric key '{kid}' (kty=oct)",
                description=(
                    "Symmetric (HMAC) keys distributed via a JWKS endpoint "
                    "force every verifier to hold the same secret as the "
                    "issuer. RFC 8725 §3.5 discourages this for cross-"
                    "service verification."
                ),
                severity=RiskLevel.MEDIUM,
                cwe="CWE-321",
                references=("https://datatracker.ietf.org/doc/html/rfc8725#section-3.5",),
                affected_asset_ids=(asset_id,),
            )
        )

    if alg in {"RS1", "HS1", "ES1"}:
        vulns.append(
            Vulnerability(
                title=f"JWKS key '{kid}' uses SHA-1 based algorithm {alg}",
                description=(
                    f"alg={alg!r} is SHA-1 based. SHA-1 was withdrawn from "
                    "FIPS approval in 2024 and is forbidden for digital "
                    "signatures. Reject the key and rotate to SHA-256+."
                ),
                severity=RiskLevel.HIGH,
                cwe="CWE-327",
                references=("https://csrc.nist.gov/projects/hash-functions",),
                affected_asset_ids=(asset_id,),
            )
        )

    return vulns


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class JWKSScanner:
    """Scanner for a JWKS endpoint (live HTTPS) or local JSON file."""

    name = "jwks"
    category = ScanCategory.NETWORK

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "jwks"

    async def scan(self, target: ScanTarget) -> ScanResult:
        started_at = frozen_now()
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        source_label: str

        try:
            raw = self._load_jwks_bytes(target, errors)
            source_label = target.host or target.path or "(unknown)"
        except ValueError as e:
            errors.append(str(e))
            source_label = target.host or target.path or "(unknown)"
            return ScanResult(
                scanner_name=self.name,
                target=source_label,
                assets=assets,
                vulnerabilities=vulns,
                started_at=started_at,
                finished_at=frozen_now(),
                errors=errors,
            )

        if raw is None:
            return ScanResult(
                scanner_name=self.name,
                target=source_label,
                assets=assets,
                vulnerabilities=vulns,
                started_at=started_at,
                finished_at=frozen_now(),
                errors=errors,
            )

        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as e:
            errors.append(f"JWKS payload is not valid JSON: {e}")
            doc = None

        if isinstance(doc, dict):
            keys = doc.get("keys")
            if not isinstance(keys, list):
                errors.append("JWKS payload missing top-level 'keys' array (RFC 7517 §5)")
                keys = []
            for idx, jwk in enumerate(keys):
                if not isinstance(jwk, dict):
                    errors.append(f"JWKS key #{idx} is not a JSON object")
                    continue
                kid = str(jwk.get("kid") or f"idx-{idx}")
                asset_id = f"jwks://{source_label}#{kid}"
                assets.append(
                    CryptoAsset(
                        asset_id=asset_id,
                        category=ScanCategory.NETWORK,
                        algorithm=_algorithm_for_jwk(jwk),
                        location=source_label,
                        discovered_at=frozen_now(),
                        metadata={
                            "kid": kid,
                            "kty": str(jwk.get("kty") or ""),
                            "alg": str(jwk.get("alg") or ""),
                            "use": str(jwk.get("use") or ""),
                        },
                    )
                )
                vulns.extend(_vulnerabilities_for_jwk(jwk, asset_id))

        return ScanResult(
            scanner_name=self.name,
            target=source_label,
            assets=assets,
            vulnerabilities=vulns,
            started_at=started_at,
            finished_at=frozen_now(),
            errors=errors,
        )

    def _load_jwks_bytes(self, target: ScanTarget, errors: list[str]) -> bytes | None:
        """Return the raw JWKS payload from ``target.host`` (URL) or ``target.path`` (file).

        Returns ``None`` (and appends to ``errors``) on recoverable
        failures (HTTP non-2xx, file missing). Raises :class:`ValueError`
        on misuse (no source, both sources, scheme violation).
        """
        url = target.host
        path = target.path
        if url and path:
            raise ValueError(
                "JWKS scanner accepts EITHER target.host (URL) OR target.path "
                "(local file), not both"
            )
        if url:
            try:
                return _fetch_jwks_bytes(url)
            except (urllib.error.URLError, ValueError, OSError) as e:
                errors.append(f"could not fetch JWKS from {url}: {e}")
                return None
        if path:
            p = Path(path)
            if not p.is_file():  # noqa: ASYNC240 — local fs metadata, see jwt_scanner for the same convention
                errors.append(f"JWKS file not found: {p}")
                return None
            try:
                return p.read_bytes()  # noqa: ASYNC240
            except OSError as e:
                errors.append(f"could not read JWKS file {p}: {e}")
                return None
        raise ValueError("JWKS scanner requires target.host (URL) or target.path (local JSON)")


__all__ = ["JWKSScanner"]
