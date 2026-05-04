"""Tests for pqc_audit.scanners.ssh_scanner — SSH KEXINIT crypto-discovery.

The SSH scanner walks two layers:

1. Pure parsers (``parse_kexinit_payload``, ``assess_ssh_endpoint``)
   that take raw bytes / dicts and return typed data. Tested here,
   offline, with hand-built KEXINIT payloads.

2. Async ``SSHScanner.scan`` that opens a TCP connection, exchanges
   banners, reads the server KEXINIT and produces a ScanResult. The
   network path is exercised in
   ``tests/integration/test_ssh_scanner_local_server.py``.

The wire format follows RFC 4253 §6 (binary packet) and §7.1 (KEXINIT).
"""

from __future__ import annotations

import struct


def _name_list(items: list[str]) -> bytes:
    """Encode an SSH name-list per RFC 4251 §5: uint32 length + ASCII payload."""
    payload = ",".join(items).encode("ascii")
    return struct.pack(">I", len(payload)) + payload


def _build_kexinit_payload(
    kex: list[str],
    host_keys: list[str],
    enc_c2s: list[str],
    enc_s2c: list[str],
    mac_c2s: list[str],
    mac_s2c: list[str],
    comp_c2s: list[str] | None = None,
    comp_s2c: list[str] | None = None,
    lang_c2s: list[str] | None = None,
    lang_s2c: list[str] | None = None,
) -> bytes:
    """Assemble a SSH_MSG_KEXINIT (msg-id 20) payload as on the wire."""
    out = bytearray()
    out.append(20)  # SSH_MSG_KEXINIT
    out.extend(b"\x00" * 16)  # cookie
    out.extend(_name_list(kex))
    out.extend(_name_list(host_keys))
    out.extend(_name_list(enc_c2s))
    out.extend(_name_list(enc_s2c))
    out.extend(_name_list(mac_c2s))
    out.extend(_name_list(mac_s2c))
    out.extend(_name_list(comp_c2s or ["none"]))
    out.extend(_name_list(comp_s2c or ["none"]))
    out.extend(_name_list(lang_c2s or []))
    out.extend(_name_list(lang_s2c or []))
    out.append(0)  # first_kex_packet_follows
    out.extend(b"\x00" * 4)  # reserved
    return bytes(out)


# ---------------------------------------------------------------------------
# Pure parser
# ---------------------------------------------------------------------------


def test_parse_kexinit_payload_nominal() -> None:
    from pqc_audit.scanners.ssh_scanner import parse_kexinit_payload

    payload = _build_kexinit_payload(
        kex=["curve25519-sha256", "diffie-hellman-group14-sha256"],
        host_keys=["ssh-ed25519", "rsa-sha2-256"],
        enc_c2s=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
        enc_s2c=["chacha20-poly1305@openssh.com"],
        mac_c2s=["hmac-sha2-256-etm@openssh.com"],
        mac_s2c=["hmac-sha2-256-etm@openssh.com"],
    )
    parsed = parse_kexinit_payload(payload)
    assert parsed["kex"] == ["curve25519-sha256", "diffie-hellman-group14-sha256"]
    assert parsed["server_host_key"] == ["ssh-ed25519", "rsa-sha2-256"]
    assert "chacha20-poly1305@openssh.com" in parsed["encryption_c2s"]
    assert parsed["mac_c2s"] == ["hmac-sha2-256-etm@openssh.com"]


def test_parse_kexinit_payload_empty_namelist() -> None:
    """An empty name-list (uint32=0, no payload) must produce []."""
    from pqc_audit.scanners.ssh_scanner import parse_kexinit_payload

    payload = _build_kexinit_payload(
        kex=[],
        host_keys=["ssh-ed25519"],
        enc_c2s=["aes256-gcm@openssh.com"],
        enc_s2c=["aes256-gcm@openssh.com"],
        mac_c2s=[],
        mac_s2c=[],
    )
    parsed = parse_kexinit_payload(payload)
    assert parsed["kex"] == []
    assert parsed["mac_c2s"] == []


def test_parse_kexinit_payload_single_entry_namelist() -> None:
    from pqc_audit.scanners.ssh_scanner import parse_kexinit_payload

    payload = _build_kexinit_payload(
        kex=["curve25519-sha256"],
        host_keys=["ssh-ed25519"],
        enc_c2s=["aes256-gcm@openssh.com"],
        enc_s2c=["aes256-gcm@openssh.com"],
        mac_c2s=["hmac-sha2-256"],
        mac_s2c=["hmac-sha2-256"],
    )
    parsed = parse_kexinit_payload(payload)
    assert parsed["kex"] == ["curve25519-sha256"]
    assert parsed["server_host_key"] == ["ssh-ed25519"]


def test_parse_kexinit_payload_rejects_wrong_msg_id() -> None:
    """SSH_MSG_KEXINIT must be byte 20. Anything else is a protocol error."""
    import pytest

    from pqc_audit.scanners.ssh_scanner import parse_kexinit_payload

    payload = _build_kexinit_payload(
        kex=["curve25519-sha256"],
        host_keys=["ssh-ed25519"],
        enc_c2s=["aes256-gcm@openssh.com"],
        enc_s2c=["aes256-gcm@openssh.com"],
        mac_c2s=["hmac-sha2-256"],
        mac_s2c=["hmac-sha2-256"],
    )
    bad = bytes([99]) + payload[1:]
    with pytest.raises(ValueError):
        parse_kexinit_payload(bad)


# ---------------------------------------------------------------------------
# Endpoint assessment — vulnerability detection
# ---------------------------------------------------------------------------


def test_assess_ssh_modern_endpoint_no_findings() -> None:
    from pqc_audit.scanners.ssh_scanner import assess_ssh_endpoint

    kex_data = {
        "kex": ["curve25519-sha256", "curve25519-sha256@libssh.org"],
        "server_host_key": ["ssh-ed25519", "rsa-sha2-512"],
        "encryption_c2s": ["chacha20-poly1305@openssh.com"],
        "encryption_s2c": ["chacha20-poly1305@openssh.com"],
        "mac_c2s": ["hmac-sha2-256-etm@openssh.com"],
        "mac_s2c": ["hmac-sha2-256-etm@openssh.com"],
    }
    algorithms, vulns = assess_ssh_endpoint("SSH-2.0-OpenSSH_9.6", kex_data)
    assert algorithms  # we still detect the algorithms in use
    titles = [v.title.lower() for v in vulns]
    # No deprecated SHA-1 / DH-group1 here, so no deprecated-finding.
    assert not any("sha-1" in t or "group1" in t or "ssh-rsa" in t for t in titles)


def test_assess_ssh_legacy_ssh_rsa_flagged() -> None:
    """``ssh-rsa`` host-key uses SHA-1, deprecated by FIPS 186-5 / OpenSSH 8.2."""
    from pqc_audit.scanners.ssh_scanner import assess_ssh_endpoint

    kex_data = {
        "kex": ["curve25519-sha256"],
        "server_host_key": ["ssh-rsa", "ssh-ed25519"],
        "encryption_c2s": ["aes256-gcm@openssh.com"],
        "encryption_s2c": ["aes256-gcm@openssh.com"],
        "mac_c2s": ["hmac-sha2-256-etm@openssh.com"],
        "mac_s2c": ["hmac-sha2-256-etm@openssh.com"],
    }
    _, vulns = assess_ssh_endpoint("SSH-2.0-OpenSSH_8.0", kex_data)
    titles = [v.title.lower() for v in vulns]
    assert any("ssh-rsa" in t or "sha-1" in t for t in titles)


def test_assess_ssh_dh_group1_flagged() -> None:
    """``diffie-hellman-group1-sha1`` is broken — 1024-bit MODP + SHA-1."""
    from pqc_audit.scanners.ssh_scanner import assess_ssh_endpoint

    kex_data = {
        "kex": ["diffie-hellman-group1-sha1"],
        "server_host_key": ["ssh-ed25519"],
        "encryption_c2s": ["aes128-cbc"],
        "encryption_s2c": ["aes128-cbc"],
        "mac_c2s": ["hmac-md5"],
        "mac_s2c": ["hmac-md5"],
    }
    _, vulns = assess_ssh_endpoint("SSH-2.0-OpenSSH_5.3", kex_data)
    titles = [v.title.lower() for v in vulns]
    assert any("group1" in t or "diffie-hellman-group1" in t for t in titles)
    assert any("md5" in t or "hmac-md5" in t for t in titles)


def test_assess_ssh_quantum_vulnerable_kex_flagged() -> None:
    """Every classical KEX is quantum-vulnerable — surface at least one finding."""
    from pqc_audit.scanners.ssh_scanner import assess_ssh_endpoint

    kex_data = {
        "kex": ["curve25519-sha256", "ecdh-sha2-nistp256"],
        "server_host_key": ["ssh-ed25519"],
        "encryption_c2s": ["chacha20-poly1305@openssh.com"],
        "encryption_s2c": ["chacha20-poly1305@openssh.com"],
        "mac_c2s": ["hmac-sha2-256-etm@openssh.com"],
        "mac_s2c": ["hmac-sha2-256-etm@openssh.com"],
    }
    _, vulns = assess_ssh_endpoint("SSH-2.0-OpenSSH_9.6", kex_data)
    titles = [v.title.lower() for v in vulns]
    assert any("quantum" in t for t in titles)


# ---------------------------------------------------------------------------
# SSHScanner Protocol surface
# ---------------------------------------------------------------------------


def test_ssh_scanner_is_applicable_to_ssh() -> None:
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.ssh_scanner import SSHScanner

    scanner = SSHScanner()
    target_ok = ScanTarget(type="ssh", host="example.it", port=22)
    target_no = ScanTarget(type="tls", host="example.it", port=443)
    assert asyncio.run(scanner.is_applicable(target_ok)) is True
    assert asyncio.run(scanner.is_applicable(target_no)) is False


def test_ssh_scanner_handshake_failure_records_error() -> None:
    """Connecting to a closed port should produce errors, not raise."""
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.ssh_scanner import SSHScanner

    scanner = SSHScanner()
    # Port 1 on localhost is virtually guaranteed to refuse.
    target = ScanTarget(type="ssh", host="127.0.0.1", port=1)
    result = asyncio.run(scanner.scan(target))
    assert result.scanner_name == "ssh"
    assert result.assets == []
    assert result.errors  # populated


def test_read_kexinit_rejects_oversized_packet_length() -> None:
    """RFC 4253 §6.1 caps packet_length at 35000. A hostile peer that
    announces 1 GB must be refused BEFORE we allocate the buffer.
    """
    import asyncio
    import struct

    from pqc_audit.scanners.ssh_scanner import _read_kexinit_packet

    # Build a forged 5-byte header: packet_length=10**9, padding_length=0.
    forged_head = struct.pack(">I", 10**9) + b"\x00"

    class FakeReader:
        def __init__(self, data: bytes) -> None:
            self._data = data
            self._pos = 0

        async def readexactly(self, n: int) -> bytes:
            chunk = self._data[self._pos : self._pos + n]
            self._pos += n
            if len(chunk) < n:
                raise asyncio.IncompleteReadError(chunk, n)
            return chunk

    reader = FakeReader(forged_head)
    try:
        asyncio.run(_read_kexinit_packet(reader, timeout_s=1.0))  # type: ignore[arg-type]
    except ValueError as exc:
        assert "oversized" in str(exc).lower() or "35000" in str(exc)
        return
    raise AssertionError("oversized packet_length must raise ValueError")


def test_read_banner_rejects_unbounded_stream() -> None:
    """A peer that never sends a newline must NOT drain RAM up to the
    socket timeout. Banner read is capped at _BANNER_MAX_LEN bytes.
    """
    import asyncio

    from pqc_audit.scanners.ssh_scanner import _BANNER_MAX_LEN, _read_banner

    class NoNewlineReader:
        """Returns a constant stream of bytes without ever yielding b'\\n'."""

        def __init__(self) -> None:
            self.bytes_consumed = 0

        async def readuntil(self, separator: bytes) -> bytes:  # noqa: ARG002
            # Simulate buffer overrun the way real asyncio does it.
            raise asyncio.LimitOverrunError("no separator in stream", 0)

        async def readexactly(self, n: int) -> bytes:
            self.bytes_consumed += n
            return b"X" * n

    reader = NoNewlineReader()
    banner = asyncio.run(_read_banner(reader, timeout_s=1.0))  # type: ignore[arg-type]
    # Banner must be capped at the RFC limit.
    assert len(banner) <= _BANNER_MAX_LEN
    assert reader.bytes_consumed <= _BANNER_MAX_LEN
