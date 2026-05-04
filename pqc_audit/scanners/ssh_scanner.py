"""SSH endpoint scanner — KEXINIT-based crypto-agility audit.

The SSH protocol (RFC 4253) advertises every algorithm the server is
willing to negotiate inside its first message after the banner: the
SSH_MSG_KEXINIT packet. Reading that packet is enough to enumerate the
cryptography offered by the endpoint, without ever completing a key
exchange or authenticating.

Two layers, like the TLS / cert scanners:

* **Pure parsers** — :func:`parse_kexinit_payload` decodes the on-the-
  wire KEXINIT payload into a dict of name-lists. :func:`assess_ssh_
  endpoint` turns that dict into typed :class:`Algorithm` /
  :class:`Vulnerability` objects. No I/O.

* **Async network probe** — :func:`_ssh_handshake` opens a TCP socket,
  exchanges banners, reads the first KEXINIT packet, and returns the
  parsed payload. Implemented with the stdlib ``asyncio`` so we don't
  pull in paramiko / asyncssh just to enumerate algorithms.

Wire format reference:

* RFC 4253 §4.2 — protocol version exchange (banner)
* RFC 4253 §6   — binary packet protocol
* RFC 4253 §7.1 — algorithm negotiation (KEXINIT)
* RFC 4251 §5   — name-list encoding
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from datetime import UTC, datetime
from typing import Any

from pqc_audit.core.algorithms import AlgorithmClass, classify_algorithm
from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

_SCANNER_NAME = "ssh"
_DEFAULT_PORT = 22
_DEFAULT_TIMEOUT_S = 5.0
_BANNER_MAX_LEN = 255  # RFC 4253 §4.2
_PACKET_LENGTH_FIELD = 4
_PADDING_LENGTH_FIELD = 1
_COOKIE_LEN = 16
_KEXINIT_MSG_ID = 20
_NAME_LIST_FIELDS = (
    "kex",
    "server_host_key",
    "encryption_c2s",
    "encryption_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
    "languages_c2s",
    "languages_s2c",
)


# ---------------------------------------------------------------------------
# Deprecated / weak algorithm tables
# ---------------------------------------------------------------------------

# Host key types known to be deprecated. ``ssh-rsa`` is RSA + SHA-1, retired
# by OpenSSH 8.2 default and broken under SHAttered-class collisions.
_DEPRECATED_HOST_KEYS: dict[str, str] = {
    "ssh-rsa": "RSA host key signs with SHA-1; replace with rsa-sha2-256/512 or ed25519.",
    "ssh-dss": "DSA-1024 is broken; remove entirely.",
}

# KEX algorithms known to be deprecated for cryptographic reasons.
_DEPRECATED_KEX: dict[str, str] = {
    "diffie-hellman-group1-sha1": "1024-bit MODP group + SHA-1; broken.",
    "diffie-hellman-group14-sha1": "SHA-1 deprecated; use SHA-256 variant.",
    "diffie-hellman-group-exchange-sha1": "SHA-1 deprecated.",
    "rsa1024-sha1": "RSA-1024 + SHA-1; broken.",
    "gss-group1-sha1-": "SHA-1 + 1024-bit group.",
}

# MAC algorithms known to be weak.
_DEPRECATED_MACS: dict[str, str] = {
    "hmac-md5": "MD5 broken; remove.",
    "hmac-md5-96": "MD5 broken; remove.",
    "hmac-sha1": "SHA-1 deprecated.",
    "hmac-sha1-96": "SHA-1 deprecated.",
    "hmac-md5-etm@openssh.com": "MD5 broken; remove.",
    "hmac-sha1-etm@openssh.com": "SHA-1 deprecated.",
}

# Encryption algorithms known to be weak / removed by modern OpenSSH.
_DEPRECATED_CIPHERS: dict[str, str] = {
    "3des-cbc": "3DES is too weak; remove.",
    "blowfish-cbc": "Blowfish 64-bit block; insecure.",
    "arcfour": "RC4 broken; remove.",
    "arcfour128": "RC4 broken; remove.",
    "arcfour256": "RC4 broken; remove.",
    "des-cbc": "DES broken; remove.",
}


# ---------------------------------------------------------------------------
# Pure name-list / KEXINIT parser
# ---------------------------------------------------------------------------


def _read_name_list(buf: bytes, offset: int) -> tuple[list[str], int]:
    """Decode a single SSH name-list at ``offset``. Returns (entries, new_offset)."""
    if offset + 4 > len(buf):
        raise ValueError("truncated KEXINIT: missing name-list length")
    (length,) = struct.unpack_from(">I", buf, offset)
    offset += 4
    end = offset + length
    if end > len(buf):
        raise ValueError("truncated KEXINIT: name-list runs past packet end")
    if length == 0:
        return [], end
    raw = buf[offset:end].decode("ascii", errors="replace")
    return raw.split(","), end


def parse_kexinit_payload(payload: bytes) -> dict[str, Any]:
    """Decode an SSH_MSG_KEXINIT payload into name-list buckets.

    Args:
        payload: the *unframed* KEXINIT payload — i.e. starting with the
            ``20`` message-id byte, followed by 16-byte cookie, then ten
            name-list fields.

    Returns:
        Dict with one entry per name-list field plus ``"raw_msg_id"``
        and ``"first_kex_packet_follows"``. Empty name-lists map to ``[]``.

    Raises:
        ValueError: if the payload is truncated, the message id is not
            ``SSH_MSG_KEXINIT``, or any length prefix walks past the end.
    """
    if not payload:
        raise ValueError("empty KEXINIT payload")
    if payload[0] != _KEXINIT_MSG_ID:
        raise ValueError(f"expected SSH_MSG_KEXINIT (msg id {_KEXINIT_MSG_ID}), got {payload[0]}")
    if len(payload) < 1 + _COOKIE_LEN:
        raise ValueError("truncated KEXINIT: missing cookie")

    offset = 1 + _COOKIE_LEN
    out: dict[str, Any] = {"raw_msg_id": payload[0]}
    for field in _NAME_LIST_FIELDS:
        entries, offset = _read_name_list(payload, offset)
        out[field] = entries

    # ``first_kex_packet_follows`` (boolean) + 4-byte reserved trailer.
    if offset < len(payload):
        out["first_kex_packet_follows"] = bool(payload[offset])
    else:
        out["first_kex_packet_follows"] = False
    return out


# ---------------------------------------------------------------------------
# Algorithm + vulnerability assessment
# ---------------------------------------------------------------------------


def _kex_to_algorithm_name(kex_name: str) -> str:
    """Map an SSH KEX name onto a generic algorithm root for classification."""
    lower = kex_name.lower()
    if lower.startswith("curve25519"):
        return "ECDH"
    if lower.startswith("ecdh-"):
        return "ECDH"
    if lower.startswith("diffie-hellman"):
        return "DH"
    if lower.startswith("rsa"):
        return "RSA"
    if "mlkem" in lower or "ml-kem" in lower:
        return "ML-KEM-768"
    return kex_name


def _host_key_to_algorithm_name(hk: str) -> str:
    """Map an SSH host-key name onto a generic algorithm root."""
    lower = hk.lower()
    if lower.startswith("ssh-rsa") or lower.startswith("rsa-sha2"):
        return "RSA"
    if lower.startswith("ssh-dss"):
        return "DSA"
    if lower.startswith("ecdsa-"):
        return "ECDSA"
    if lower.startswith("ssh-ed25519") or lower.startswith("ssh-ed448"):
        return "EdDSA"
    if "ml-dsa" in lower or "mldsa" in lower:
        return "ML-DSA-65"
    return hk


def assess_ssh_endpoint(
    banner: str,
    kex_data: dict[str, Any],
    *,
    asset_id: str = "",
) -> tuple[list[Algorithm], list[Vulnerability]]:
    """Turn a KEXINIT name-list bundle into Algorithm + Vulnerability lists.

    The function is pure: same input produces the same output. Vulns
    are deduplicated by title to avoid spamming a single endpoint with
    repeated findings when multiple weak entries share a root cause.
    """
    algorithms: list[Algorithm] = []
    vulns: list[Vulnerability] = []
    seen_titles: set[str] = set()
    affected = (asset_id,) if asset_id else ()

    def _emit(vuln: Vulnerability) -> None:
        if vuln.title in seen_titles:
            return
        seen_titles.add(vuln.title)
        vulns.append(vuln)

    # KEX algorithms
    for raw in kex_data.get("kex", []) or []:
        alg_name = _kex_to_algorithm_name(raw)
        algorithms.append(Algorithm(name=alg_name))
        if raw in _DEPRECATED_KEX:
            _emit(
                Vulnerability(
                    title=f"Weak SSH KEX algorithm offered ({raw})",
                    description=_DEPRECATED_KEX[raw],
                    severity=RiskLevel.HIGH,
                    cwe="CWE-327",
                    affected_asset_ids=affected,
                )
            )
        if classify_algorithm(alg_name) is AlgorithmClass.QUANTUM_VULNERABLE:
            _emit(
                Vulnerability(
                    title=f"Quantum-vulnerable SSH KEX ({alg_name})",
                    description=(
                        "Classical Diffie-Hellman or ECDH key exchange is "
                        "broken by Shor's algorithm on a CRQC. Plan a "
                        "transition to ML-KEM (FIPS 203), optionally as a "
                        "hybrid with X25519 during the migration window."
                    ),
                    severity=RiskLevel.MEDIUM,
                    cwe="CWE-327",
                    affected_asset_ids=affected,
                    references=("https://csrc.nist.gov/projects/post-quantum-cryptography",),
                )
            )

    # Host key algorithms
    for raw in kex_data.get("server_host_key", []) or []:
        alg_name = _host_key_to_algorithm_name(raw)
        algorithms.append(Algorithm(name=alg_name))
        if raw in _DEPRECATED_HOST_KEYS:
            _emit(
                Vulnerability(
                    title=f"Deprecated SSH host key type ({raw})",
                    description=_DEPRECATED_HOST_KEYS[raw],
                    severity=RiskLevel.HIGH,
                    cwe="CWE-327",
                    affected_asset_ids=affected,
                )
            )
        if classify_algorithm(alg_name) is AlgorithmClass.QUANTUM_VULNERABLE:
            _emit(
                Vulnerability(
                    title=f"Quantum-vulnerable SSH host key ({alg_name})",
                    description=(
                        "Host key signature broken by Shor on a CRQC. "
                        "Plan migration to ML-DSA (FIPS 204) or SLH-DSA "
                        "(FIPS 205) when supported by your fleet."
                    ),
                    severity=RiskLevel.MEDIUM,
                    cwe="CWE-327",
                    affected_asset_ids=affected,
                )
            )

    # MACs
    for raw in (kex_data.get("mac_c2s") or []) + (kex_data.get("mac_s2c") or []):
        if raw in _DEPRECATED_MACS:
            _emit(
                Vulnerability(
                    title=f"Weak SSH MAC algorithm offered ({raw})",
                    description=_DEPRECATED_MACS[raw],
                    severity=RiskLevel.MEDIUM,
                    cwe="CWE-328",
                    affected_asset_ids=affected,
                )
            )

    # Ciphers
    for raw in (kex_data.get("encryption_c2s") or []) + (kex_data.get("encryption_s2c") or []):
        if raw in _DEPRECATED_CIPHERS:
            _emit(
                Vulnerability(
                    title=f"Weak SSH cipher offered ({raw})",
                    description=_DEPRECATED_CIPHERS[raw],
                    severity=RiskLevel.HIGH,
                    cwe="CWE-327",
                    affected_asset_ids=affected,
                )
            )

    # Banner sanity — surface the version string for auditability.
    if banner and not banner.startswith("SSH-2.0-"):
        _emit(
            Vulnerability(
                title=f"Non-SSH-2.0 banner observed ({banner!r})",
                description=(
                    "Endpoint did not advertise SSH 2.0. Older protocol "
                    "versions are obsolete and should not be reachable."
                ),
                severity=RiskLevel.LOW,
                cwe="CWE-326",
                affected_asset_ids=affected,
            )
        )

    return algorithms, vulns


# ---------------------------------------------------------------------------
# Network probe
# ---------------------------------------------------------------------------


async def _read_banner(reader: asyncio.StreamReader, timeout_s: float) -> str:
    """Read a single CRLF-terminated banner, stripping the line ending."""
    raw = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
    if len(raw) > _BANNER_MAX_LEN:
        # RFC limits banner length; truncate defensively.
        raw = raw[:_BANNER_MAX_LEN]
    return raw.decode("ascii", errors="replace").rstrip("\r\n")


async def _read_kexinit_packet(reader: asyncio.StreamReader, timeout_s: float) -> bytes:
    """Read one binary packet and return its payload (excluding padding).

    Reads only enough bytes to parse RFC 4253 §6 framing:
      uint32   packet_length
      byte     padding_length
      byte[n1] payload  (n1 = packet_length - padding_length - 1)
      byte[n2] random padding
      byte[m]  mac (NOT present pre-NEWKEYS, which is our case)

    Pre-NEWKEYS, MAC is empty by definition — the very first SSH packet
    after the banner is the server's KEXINIT, sent in plaintext.
    """
    head = await asyncio.wait_for(
        reader.readexactly(_PACKET_LENGTH_FIELD + _PADDING_LENGTH_FIELD), timeout=timeout_s
    )
    (packet_length,) = struct.unpack(">I", head[:4])
    padding_length = head[4]
    if packet_length < padding_length + 1:
        raise ValueError(f"invalid packet framing: pkt_len={packet_length} pad={padding_length}")
    payload_len = packet_length - padding_length - 1
    rest = await asyncio.wait_for(
        reader.readexactly(payload_len + padding_length), timeout=timeout_s
    )
    return rest[:payload_len]


async def _ssh_handshake(
    host: str, port: int, *, timeout_s: float = _DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Connect, exchange banners, read the server KEXINIT, return parsed data.

    Sends a minimal client banner so the server proceeds to KEXINIT.
    Never completes the actual key exchange — we only enumerate.
    """
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
    try:
        banner = await _read_banner(reader, timeout_s)
        # Send a client banner so the server proceeds. Use a generic ID
        # that does not match any real implementation, to make it
        # obvious in server logs that this is an audit probe.
        writer.write(b"SSH-2.0-pqc-audit-italia\r\n")
        await writer.drain()

        payload = await _read_kexinit_packet(reader, timeout_s)
        kex_data = parse_kexinit_payload(payload)
        return {"banner": banner, "kex": kex_data}
    finally:
        writer.close()
        with contextlib.suppress(OSError):  # pragma: no cover — connection already torn down
            await writer.wait_closed()


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class SSHScanner:
    """Concrete scanner for ``type='ssh'`` targets.

    Connects via plain ``asyncio`` (no extra deps), reads the first
    KEXINIT, classifies offered algorithms. Per-target failures are
    captured in ``ScanResult.errors`` rather than raised.
    """

    name: str = _SCANNER_NAME
    category: ScanCategory = ScanCategory.NETWORK

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "ssh" and bool(target.host)

    async def scan(self, target: ScanTarget) -> ScanResult:
        started = datetime.now(UTC)
        host = target.host or ""
        port = int(target.port) if target.port is not None else _DEFAULT_PORT
        target_repr = f"{host}:{port}"
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []

        try:
            handshake = await _ssh_handshake(host, port)
            banner = handshake.get("banner", "") or ""
            kex_data = handshake.get("kex", {}) or {}
            asset_id = f"ssh://{target_repr}"
            algorithms, found_vulns = assess_ssh_endpoint(banner, kex_data, asset_id=asset_id)

            # We surface one CryptoAsset per *distinct* algorithm offered.
            # Each entry uses the same location / source for traceability.
            seen_canonical: set[str] = set()
            for alg in algorithms:
                canonical = alg.canonical_name
                if canonical in seen_canonical:
                    continue
                seen_canonical.add(canonical)
                assets.append(
                    CryptoAsset(
                        asset_id=f"{asset_id}#{canonical}",
                        category=ScanCategory.NETWORK,
                        algorithm=alg,
                        location=target_repr,
                        discovered_at=started,
                        metadata={
                            "banner": banner,
                            "ssh_role": "server",
                        },
                    )
                )

            vulns.extend(found_vulns)
        except Exception as exc:  # noqa: BLE001 — per-target soft error
            errors.append(f"{type(exc).__name__}: {exc}")

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
