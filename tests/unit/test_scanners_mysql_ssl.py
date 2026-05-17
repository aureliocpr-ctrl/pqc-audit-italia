"""Tests for MySQL SSL probe — Sprint 9j.2.

MySQL is different from PostgreSQL: the server speaks FIRST, sending
an Initial Handshake Packet v10 immediately on connect. The packet
encodes the server's supported capabilities, including the
``CLIENT_SSL`` bit (0x00000800, bit 11). The probe is purely
**passive**: read the handshake, parse the capability flags, no
client-side request needed.

Reference: MySQL Protocol::HandshakeV10
(https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)
and the CLIENT_SSL capability flag = 2048 = 0x0800
(https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html).

Wire layout, MySQL packet (header + payload):

* 3 bytes payload-length (little-endian)
* 1 byte sequence-id (usually 0 for the initial handshake)
* payload bytes:
    - 1 byte protocol_version (always 10 for v10)
    - NUL-terminated server_version string
    - 4 bytes thread_id
    - 8 bytes auth-plugin-data-part-1
    - 1 byte filler (0x00)
    - 2 bytes capability_flags_1 (low 16 bits, LE) ← CLIENT_SSL HERE
    - 1 byte character_set (only the lower 8 bits)
    - 2 bytes status_flags
    - 2 bytes capability_flags_2 (high 16 bits, LE)
    - ... (rest optional, we stop parsing here)
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

# ---------------------------------------------------------------------
# Synthetic handshake fixture
# ---------------------------------------------------------------------


def _build_handshake_payload(
    *,
    server_version: bytes = b"8.0.36",
    capability_flags: int = 0x0FFE_FFFF,  # SSL set by default
) -> bytes:
    """Construct a minimal but spec-valid HandshakeV10 payload."""
    cap1 = capability_flags & 0xFFFF
    cap2 = (capability_flags >> 16) & 0xFFFF
    payload = b""
    payload += bytes([10])  # protocol_version
    payload += server_version + b"\x00"  # NUL-terminated server_version
    payload += struct.pack("<I", 12345)  # thread_id
    payload += b"01234567"  # auth-plugin-data-part-1 (8 bytes)
    payload += b"\x00"  # filler
    payload += struct.pack("<H", cap1)  # capability_flags_1
    payload += bytes([33])  # character_set (utf8_general_ci)
    payload += struct.pack("<H", 0x0002)  # status_flags (SERVER_STATUS_AUTOCOMMIT)
    payload += struct.pack("<H", cap2)  # capability_flags_2
    return payload


def _wrap_in_mysql_packet(payload: bytes) -> bytes:
    """Prepend the 4-byte MySQL packet header (3-byte length LE + 1-byte seq=0)."""
    length = len(payload)
    header = struct.pack("<I", length)[:3] + b"\x00"  # truncate to 3 bytes + seq=0
    return header + payload


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------


def test_client_ssl_capability_bit_matches_mysql_docs() -> None:
    from pqc_audit.scanners.mysql_ssl import CLIENT_SSL_BIT

    # MySQL documents this as 2048 = 0x0800.
    assert CLIENT_SSL_BIT == 0x0800
    assert CLIENT_SSL_BIT == 2048


# ---------------------------------------------------------------------
# parse_handshake_v10_capabilities — pure function
# ---------------------------------------------------------------------


def test_parse_handshake_extracts_protocol_version_and_server_version() -> None:
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    payload = _build_handshake_payload(server_version=b"8.0.36")
    out = parse_handshake_v10_capabilities(payload)
    assert out["protocol_version"] == 10
    assert out["server_version"] == "8.0.36"


def test_parse_handshake_reports_ssl_supported_when_bit_set() -> None:
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    payload = _build_handshake_payload(capability_flags=0x0000_0800)
    out = parse_handshake_v10_capabilities(payload)
    assert out["client_ssl_supported"] is True
    assert out["ssl_status"] == "supported"


def test_parse_handshake_reports_ssl_not_supported_when_bit_clear() -> None:
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    # Set every bit EXCEPT CLIENT_SSL (bit 11)
    flags = 0xFFFFFFFF ^ 0x0800
    payload = _build_handshake_payload(capability_flags=flags)
    out = parse_handshake_v10_capabilities(payload)
    assert out["client_ssl_supported"] is False
    assert out["ssl_status"] == "not_supported"


def test_parse_handshake_returns_full_capability_flags_as_hex() -> None:
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    payload = _build_handshake_payload(capability_flags=0xDEAD_BEEF)
    out = parse_handshake_v10_capabilities(payload)
    assert out["capability_flags"] == 0xDEAD_BEEF
    assert out["capability_flags_hex"] == "0xdeadbeef"


def test_parse_handshake_rejects_protocol_version_other_than_10() -> None:
    """Pre-v10 handshake (HandshakeV9) is obsolete; we surface as error."""
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    payload = b"\x09" + b"4.0.0\x00" + b"\x00" * 30
    out = parse_handshake_v10_capabilities(payload)
    assert out["ssl_status"] == "error"
    assert "protocol version" in out["error_message"].lower()


def test_parse_handshake_rejects_truncated_payload() -> None:
    """If the packet is shorter than the fixed-offset capability_flags
    field, we report error rather than reading past EOF."""
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    out = parse_handshake_v10_capabilities(b"\x0a")  # just the version byte
    assert out["ssl_status"] == "error"


def test_parse_handshake_rejects_missing_server_version_terminator() -> None:
    from pqc_audit.scanners.mysql_ssl import parse_handshake_v10_capabilities

    # Protocol version OK but server_version never NUL-terminates.
    out = parse_handshake_v10_capabilities(b"\x0a" + b"X" * 100)
    assert out["ssl_status"] == "error"


# ---------------------------------------------------------------------
# probe_mysql_ssl — schema contract via monkeypatch socket
# ---------------------------------------------------------------------


def test_probe_returns_5_key_dict(monkeypatch) -> None:
    from pqc_audit.scanners import mysql_ssl

    handshake = _wrap_in_mysql_packet(_build_handshake_payload())

    class FakeSocket:
        def __init__(self):
            self._buf = handshake

        def settimeout(self, *args):
            return None

        def recv(self, n):
            chunk = self._buf[:n]
            self._buf = self._buf[n:]
            return chunk

        def close(self):
            return None

    def fake_create_connection(*args, **kwargs):
        return FakeSocket()

    monkeypatch.setattr(mysql_ssl.socket, "create_connection", fake_create_connection)

    out = mysql_ssl.probe_mysql_ssl("db.example.com", 3306)
    assert set(out.keys()) >= {
        "host",
        "port",
        "ssl_status",
        "error_message",
        "server_version",
    }
    assert out["host"] == "db.example.com"
    assert out["port"] == 3306
    assert out["ssl_status"] == "supported"
    assert out["server_version"] == "8.0.36"


def test_probe_handles_connection_refused(monkeypatch) -> None:
    from pqc_audit.scanners import mysql_ssl

    def raise_refused(*args, **kwargs):
        raise ConnectionRefusedError("ECONNREFUSED")

    monkeypatch.setattr(mysql_ssl.socket, "create_connection", raise_refused)
    out = mysql_ssl.probe_mysql_ssl("db.example.com", 3306)
    assert out["ssl_status"] == "error"


def test_probe_handles_timeout(monkeypatch) -> None:
    from pqc_audit.scanners import mysql_ssl

    def raise_timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(mysql_ssl.socket, "create_connection", raise_timeout)
    out = mysql_ssl.probe_mysql_ssl("slow.example.com", 3306)
    assert out["ssl_status"] == "error"


# ---------------------------------------------------------------------
# Real-socket integration tests with in-process mock MySQL server
# ---------------------------------------------------------------------


def _start_mock_mysql_server(handshake_bytes: bytes) -> tuple[int, threading.Event]:
    """1-shot TCP server that sends `handshake_bytes` and closes."""
    completed = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def serve():
        try:
            conn, _ = sock.accept()
            try:
                conn.sendall(handshake_bytes)
            finally:
                conn.close()
        finally:
            sock.close()
            completed.set()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, completed


@pytest.mark.integration
def test_real_socket_probe_against_mock_with_ssl_enabled() -> None:
    from pqc_audit.scanners.mysql_ssl import probe_mysql_ssl

    handshake = _wrap_in_mysql_packet(
        _build_handshake_payload(server_version=b"8.0.36", capability_flags=0x0FFE_FFFF)
    )
    port, done = _start_mock_mysql_server(handshake)
    out = probe_mysql_ssl("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["ssl_status"] == "supported"
    assert out["server_version"] == "8.0.36"
    assert out["host"] == "127.0.0.1"
    assert out["port"] == port


@pytest.mark.integration
def test_real_socket_probe_against_mock_with_ssl_disabled() -> None:
    from pqc_audit.scanners.mysql_ssl import probe_mysql_ssl

    # Clear bit 11 (CLIENT_SSL) only
    flags_no_ssl = 0xFFFFFFFF ^ 0x0800
    handshake = _wrap_in_mysql_packet(
        _build_handshake_payload(server_version=b"5.7.42", capability_flags=flags_no_ssl)
    )
    port, done = _start_mock_mysql_server(handshake)
    out = probe_mysql_ssl("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["ssl_status"] == "not_supported"
    assert out["server_version"] == "5.7.42"


@pytest.mark.integration
def test_cli_scan_mysql_ssl_against_mock_emits_valid_json() -> None:
    import json

    from typer.testing import CliRunner

    from pqc_audit.cli import app

    handshake = _wrap_in_mysql_packet(
        _build_handshake_payload(server_version=b"10.11.6-MariaDB")
    )
    port, done = _start_mock_mysql_server(handshake)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", "mysql-ssl", "--host", "127.0.0.1", "--port", str(port), "--timeout", "5.0"],
    )
    done.wait(timeout=5.0)
    assert result.exit_code == 0, f"CLI exited {result.exit_code}: {result.stdout}"
    payload = json.loads(result.stdout)
    assert payload["host"] == "127.0.0.1"
    assert payload["port"] == port
    assert payload["probe"] == "mysql-handshake-v10-capability-flags"
    assert payload["result"]["ssl_status"] == "supported"
    assert payload["result"]["server_version"] == "10.11.6-MariaDB"
