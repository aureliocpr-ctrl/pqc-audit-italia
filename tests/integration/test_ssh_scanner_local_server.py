"""Integration test — SSHScanner end-to-end against a local mini-server.

Spins a tiny asyncio TCP listener on 127.0.0.1 that:
1. Sends a fake SSH-2.0 banner.
2. Reads the client banner.
3. Sends a single KEXINIT packet advertising a *known weak* algorithm
   set, so we can verify the scanner detects it.
4. Closes the connection without continuing the handshake.

This exercises the real socket + framing path of the scanner without
requiring sshd or paramiko.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct

import pytest

# Mirror of the helpers in tests/unit/test_ssh_scanner.py — duplicated
# so the integration test stays standalone (no cross-test imports).


def _name_list(items: list[str]) -> bytes:
    payload = ",".join(items).encode("ascii")
    return struct.pack(">I", len(payload)) + payload


def _build_kexinit_payload() -> bytes:
    """Build a payload advertising both modern and deprecated algorithms."""
    out = bytearray()
    out.append(20)  # SSH_MSG_KEXINIT
    out.extend(b"\x00" * 16)  # cookie
    out.extend(_name_list(["curve25519-sha256", "diffie-hellman-group1-sha1"]))
    out.extend(_name_list(["ssh-ed25519", "ssh-rsa"]))
    out.extend(_name_list(["chacha20-poly1305@openssh.com", "3des-cbc"]))
    out.extend(_name_list(["chacha20-poly1305@openssh.com"]))
    out.extend(_name_list(["hmac-sha2-256-etm@openssh.com", "hmac-md5"]))
    out.extend(_name_list(["hmac-sha2-256-etm@openssh.com"]))
    out.extend(_name_list(["none"]))
    out.extend(_name_list(["none"]))
    out.extend(_name_list([]))
    out.extend(_name_list([]))
    out.append(0)  # first_kex_packet_follows
    out.extend(b"\x00" * 4)  # reserved
    return bytes(out)


def _frame_packet(payload: bytes) -> bytes:
    """Wrap a payload in RFC 4253 §6 binary packet framing.

    Pre-NEWKEYS so no MAC is appended. Padding length must satisfy
    (packet_length + 4) % 8 == 0 with at least 4 padding bytes.
    """
    pad_len = 8 - ((4 + 1 + len(payload)) % 8)
    if pad_len < 4:
        pad_len += 8
    packet_length = 1 + len(payload) + pad_len
    return struct.pack(">I", packet_length) + bytes([pad_len]) + payload + (b"\x00" * pad_len)


async def _serve_one_kexinit() -> tuple[str, int, asyncio.Server]:
    """Start a one-shot SSH-style server. Returns (host, port, server)."""

    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.write(b"SSH-2.0-pqc-audit-mini\r\n")
            await writer.drain()
            # Read client banner (one CRLF-terminated line, bounded by RFC).
            with contextlib.suppress(TimeoutError, asyncio.IncompleteReadError):
                await asyncio.wait_for(reader.readline(), timeout=2.0)
            writer.write(_frame_packet(_build_kexinit_payload()))
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    sockets = server.sockets or ()
    if not sockets:  # pragma: no cover — defensive
        raise RuntimeError("server failed to bind")
    host, port = sockets[0].getsockname()[:2]
    return host, port, server


@pytest.mark.integration
def test_ssh_scanner_against_local_server() -> None:
    """End-to-end: scan a fake server and confirm weak algorithms are flagged."""
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.ssh_scanner import SSHScanner

    async def _run() -> None:
        host, port, server = await _serve_one_kexinit()
        try:
            scanner = SSHScanner()
            target = ScanTarget(type="ssh", host=host, port=port)
            result = await scanner.scan(target)

            assert result.scanner_name == "ssh"
            assert not result.errors, f"unexpected errors: {result.errors}"
            assert result.assets, "expected at least one asset detected"

            titles = [v.title.lower() for v in result.vulnerabilities]
            # Weak KEX advertised
            assert any("group1" in t for t in titles)
            # ssh-rsa host key advertised
            assert any("ssh-rsa" in t or "sha-1" in t for t in titles)
            # 3des cipher advertised
            assert any("3des" in t for t in titles)
            # hmac-md5 MAC advertised
            assert any("md5" in t for t in titles)
            # PQ verdict on classical KEX
            assert any("quantum" in t for t in titles)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_run())
