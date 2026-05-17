"""RFC 3161 Time-Stamp Protocol client (Sprint 8 step D).

Builds a TimeStampReq over a SHA-256 digest of the canonical report
JSON and ships it to a TSA endpoint. The implementation is pure
stdlib — no pyasn1, no asn1crypto, no third-party HTTP client —
because the wire format is small enough to hand-roll cleanly and
keeping the supply chain tight matters more than reusing a generic
ASN.1 library for one struct.

What this module DOES:
    * Builds a DER-encoded TimeStampReq (RFC 3161 §2.4.1).
    * POSTs it to an HTTPS TSA endpoint with the
      ``application/timestamp-query`` content type.
    * SSRF-guards the URL (HTTPS-only, refuses loopback / RFC1918 /
      link-local / multicast / AWS-metadata).
    * Caps the response at :data:`_MAX_TSR_BYTES` (CWE-400).
    * Returns the raw TimeStampResp body for downstream callers.

What this module does NOT do:
    * It does not parse the TimeStampResp — the bundle is shipped as
      an opaque blob to the verifier. Round-tripping (verify the TSA
      signature, verify the certificate chain, verify the genTime is
      authoritative) is the verifier's responsibility and the right
      tool there is ``openssl ts -verify`` or a dedicated library.
    * It does not promise *qualified* timestamping. ETSI EN 319 421
      qualification + AgID accreditation are paperwork on top of
      this protocol; out of scope for this codebase.

ASN.1 DER refresher (used below):
    SEQUENCE         0x30 LEN content
    INTEGER          0x02 LEN content (big-endian, unsigned with leading zero if MSB set)
    OBJECT IDENT     0x06 LEN content (subidentifier base-128)
    OCTET STRING     0x04 LEN content
    NULL             0x05 0x00
    BOOLEAN          0x01 0x01 (0xff = true, 0x00 = false)

The TimeStampReq ASN.1 module (RFC 3161 §2.4.1) is::

    TimeStampReq ::= SEQUENCE  {
       version                      INTEGER  { v1(1) },
       messageImprint               MessageImprint,
       reqPolicy             TSAPolicyId        OPTIONAL,
       nonce                 INTEGER            OPTIONAL,
       certReq               BOOLEAN            DEFAULT FALSE,
       extensions       [0] IMPLICIT Extensions OPTIONAL }

    MessageImprint ::= SEQUENCE  {
         hashAlgorithm         AlgorithmIdentifier,
         hashedMessage         OCTET STRING  }
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

_DEFAULT_TIMEOUT_SECONDS = 15.0
_MAX_TSR_BYTES = 256 * 1024  # 256 KiB — a TSR is normally a few kB
_USER_AGENT = "pqc-audit-italia/0.3 RFC3161-client"

# DER encoding magic numbers (X.690).
_DER_SHORT_FORM_MAX = 0x80  # length < 128 fits in a single byte
_DER_MIN_OID_ARCS = 2  # an OID must have at least two arcs (X.690 §8.19)

# HTTP success range used by the TSA POST.
_HTTP_OK_MIN = 200
_HTTP_OK_BELOW = 300

# Hash algorithm OID registry (only the ones we actually use).
# 2.16.840.1.101.3.4.2.1  sha256
# 2.16.840.1.101.3.4.2.2  sha384
# 2.16.840.1.101.3.4.2.3  sha512
_HASH_OIDS: dict[str, str] = {
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
}

_DIGEST_LEN: dict[str, int] = {
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}


# ---------------------------------------------------------------------------
# Minimal DER encoder
# ---------------------------------------------------------------------------


def _der_len(length: int) -> bytes:
    """Encode the length octets per X.690 §8.1.3."""
    if length < _DER_SHORT_FORM_MAX:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_integer(value: int) -> bytes:
    if value == 0:
        return _der_tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    # Add leading 0x00 if the high bit is set (X.690 §8.3.2 — preserve
    # the sign for unsigned values).
    if body[0] & 0x80:
        body = b"\x00" + body
    return _der_tlv(0x02, body)


def _der_oid(dotted: str) -> bytes:
    """Encode a dotted-decimal OID per X.690 §8.19."""
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < _DER_MIN_OID_ARCS:
        raise ValueError(f"OID needs >= {_DER_MIN_OID_ARCS} arcs, got {dotted!r}")
    first = 40 * parts[0] + parts[1]
    body = bytearray([first])
    for arc in parts[2:]:
        remaining = arc
        if remaining == 0:
            body.append(0)
            continue
        chunk: list[int] = []
        while remaining:
            chunk.insert(0, remaining & 0x7F)
            remaining >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        body.extend(chunk)
    return _der_tlv(0x06, bytes(body))


def _der_octet_string(content: bytes) -> bytes:
    return _der_tlv(0x04, content)


def _der_null() -> bytes:
    return b"\x05\x00"


def _der_boolean(value: bool) -> bytes:
    return _der_tlv(0x01, b"\xff" if value else b"\x00")


def _der_sequence(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


# ---------------------------------------------------------------------------
# RFC 3161 TimeStampReq builder
# ---------------------------------------------------------------------------


def build_timestamp_request(
    digest: bytes,
    *,
    hash_algo: str = "sha256",
    cert_req: bool = True,
) -> bytes:
    """Return the DER-encoded TimeStampReq over ``digest``.

    Args:
        digest: raw bytes of the message imprint (SHA-256: 32 bytes).
        hash_algo: ``"sha256"`` / ``"sha384"`` / ``"sha512"``.
        cert_req: when True (default) the TSA returns its signing
            certificate inside the TimeStampResp — the verifier
            doesn't need to fetch it out-of-band.

    Raises:
        ValueError: unsupported hash, or digest length mismatch.
    """
    algo = hash_algo.lower()
    if algo not in _HASH_OIDS:
        raise ValueError(f"unsupported hash algorithm: {hash_algo!r}")
    expected_len = _DIGEST_LEN[algo]
    if len(digest) != expected_len:
        raise ValueError(
            f"digest length mismatch: {algo} expects {expected_len} bytes, got {len(digest)}"
        )

    algo_identifier = _der_sequence(_der_oid(_HASH_OIDS[algo]), _der_null())
    message_imprint = _der_sequence(algo_identifier, _der_octet_string(digest))

    components: list[bytes] = [
        _der_integer(1),  # version v1
        message_imprint,
    ]
    # certReq is DEFAULT FALSE — emit it only when True to keep the
    # request compact and the DER output stable across runs.
    if cert_req:
        components.append(_der_boolean(True))
    return _der_sequence(*components)


# ---------------------------------------------------------------------------
# HTTPS POST to the TSA
# ---------------------------------------------------------------------------


def _is_public_host(hostname: str) -> bool:
    """Same SSRF posture as the JWKS scanner — see its docstring."""
    if not hostname or hostname == "localhost":
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for _, _, _, _, sockaddr in infos:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
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


def _urlopen(req: urllib.request.Request, timeout: float) -> Any:  # pragma: no cover
    """Thin wrapper kept as a module attribute so tests can monkeypatch it.

    Returns the response context manager from ``urlopen``. Typed as
    ``Any`` because urllib's hierarchy is too noisy to constrain
    further without pulling type stubs, and the caller uses it in a
    ``with`` block which mypy cannot type-check against ``object``.
    """
    https_handler = urllib.request.HTTPSHandler(context=ssl.create_default_context())
    opener = urllib.request.build_opener(https_handler)
    return opener.open(req, timeout=timeout)  # noqa: S310 — scheme is validated upstream


def request_timestamp_token(
    tsa_url: str,
    digest: bytes,
    *,
    hash_algo: str = "sha256",
    cert_req: bool = True,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> bytes:
    """POST a TimeStampReq to ``tsa_url`` and return the raw TimeStampResp body.

    Security:
        * Only HTTPS URLs are accepted; the SSRF guard refuses
          loopback / RFC1918 / link-local / multicast / AWS-metadata
          (CWE-918).
        * The response is capped at :data:`_MAX_TSR_BYTES`
          (CWE-400) so a malicious TSA cannot exhaust memory.
        * The default SSL context performs certificate + hostname
          verification.

    The returned bytes are the opaque DER TimeStampResp. This function
    does NOT verify the TSA signature — callers feed it to
    ``openssl ts -verify`` or an equivalent library.
    """
    parsed = urlparse(tsa_url)
    if parsed.scheme != "https":
        raise ValueError(f"TSA URL must use https://, got scheme={parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("TSA URL must include a hostname")
    if not _is_public_host(parsed.hostname):
        raise ValueError(
            f"TSA host {parsed.hostname!r} resolves to a private/loopback "
            "address (SSRF guard — CWE-918)"
        )

    body = build_timestamp_request(digest, hash_algo=hash_algo, cert_req=cert_req)
    req = urllib.request.Request(  # noqa: S310 — scheme validated above
        tsa_url,
        data=body,
        headers={
            "User-Agent": _USER_AGENT,
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        },
        method="POST",
    )
    try:
        with _urlopen(req, timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if status is None or not (_HTTP_OK_MIN <= status < _HTTP_OK_BELOW):
                raise ValueError(f"TSA returned HTTP {status}")
            data = resp.read(_MAX_TSR_BYTES + 1)
    except urllib.error.URLError as e:
        raise ValueError(f"TSA request failed: {e}") from e
    if len(data) > _MAX_TSR_BYTES:
        raise ValueError(f"TSA response exceeds {_MAX_TSR_BYTES} bytes")
    assert isinstance(data, bytes)  # noqa: S101 — urllib.response.read() typed as Any
    return data


__all__ = [
    "build_timestamp_request",
    "request_timestamp_token",
]
