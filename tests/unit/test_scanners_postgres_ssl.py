"""Tests for PostgreSQL SSL probe — Sprint 9j (database TLS coverage).

PostgreSQL servers do NOT speak TLS on connect — they speak the
PostgreSQL wire protocol, and a client wishing to use SSL must first
send an ``SSLRequest`` message (8 bytes: ``00 00 00 08 04 d2 16 2f``,
length=8 + magic 80877103). The server responds with a single byte:

* ``'S'`` (0x53) — SSL supported, the connection upgrades to TLS;
* ``'N'`` (0x4E) — SSL not supported, plaintext only.

A naive ``ssl.create_default_context().wrap_socket(...)`` against a
PostgreSQL server would fail because the server is not expecting a
ClientHello yet. This module implements the correct two-step probe.

Source: PostgreSQL documentation, "Message Formats — SSLRequest"
(https://www.postgresql.org/docs/current/protocol-message-formats.html).
"""

from __future__ import annotations

import asyncio
import socket
import threading

import pytest

# ---------------------------------------------------------------------
# Constants — wire format must match the PostgreSQL protocol exactly
# ---------------------------------------------------------------------


def test_ssl_request_bytes_match_wire_format() -> None:
    from pqc_audit.scanners.postgres_ssl import SSL_REQUEST_BYTES

    # Length=8 (Int32 BE) + SSL request magic 80877103 (Int32 BE)
    assert SSL_REQUEST_BYTES == b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    assert len(SSL_REQUEST_BYTES) == 8


def test_ssl_request_magic_decodes_to_80877103() -> None:
    """1234 in MSW + 5679 in LSW per Postgres docs."""
    from pqc_audit.scanners.postgres_ssl import SSL_REQUEST_BYTES

    magic = int.from_bytes(SSL_REQUEST_BYTES[4:], "big")
    assert magic == 80877103


# ---------------------------------------------------------------------
# parse_ssl_response_byte — pure function, no I/O
# ---------------------------------------------------------------------


def test_parse_response_supported_on_uppercase_S() -> None:
    from pqc_audit.scanners.postgres_ssl import parse_ssl_response_byte

    assert parse_ssl_response_byte(b"S") == "supported"


def test_parse_response_not_supported_on_uppercase_N() -> None:
    from pqc_audit.scanners.postgres_ssl import parse_ssl_response_byte

    assert parse_ssl_response_byte(b"N") == "not_supported"


def test_parse_response_error_on_empty_input() -> None:
    from pqc_audit.scanners.postgres_ssl import parse_ssl_response_byte

    assert parse_ssl_response_byte(b"") == "error"


def test_parse_response_error_on_unknown_byte() -> None:
    """Anything other than 'S' or 'N' is a protocol violation by the
    server; we surface it as 'error' instead of guessing."""
    from pqc_audit.scanners.postgres_ssl import parse_ssl_response_byte

    assert parse_ssl_response_byte(b"X") == "error"
    assert parse_ssl_response_byte(b"\x00") == "error"


def test_parse_response_ignores_extra_bytes_past_first() -> None:
    """Server should only send 1 byte, but be defensive."""
    from pqc_audit.scanners.postgres_ssl import parse_ssl_response_byte

    assert parse_ssl_response_byte(b"S\x00\x00") == "supported"
    assert parse_ssl_response_byte(b"NEXTRA") == "not_supported"


# ---------------------------------------------------------------------
# probe_postgres_ssl — schema contract via monkeypatch socket
# ---------------------------------------------------------------------


def test_probe_returns_dict_with_required_keys(monkeypatch) -> None:
    """Stable 5-key dict schema — callers depend on it."""
    from pqc_audit.scanners import postgres_ssl

    class FakeSocket:
        def __init__(self, *args, **kwargs):
            self.sent: bytes = b""

        def settimeout(self, *args):
            return None

        def connect(self, *args):
            return None

        def sendall(self, data):
            self.sent = data

        def recv(self, n):
            return b"S"

        def close(self):
            return None

    def fake_create_connection(*args, **kwargs):
        return FakeSocket()

    monkeypatch.setattr(postgres_ssl.socket, "create_connection", fake_create_connection)

    out = postgres_ssl.probe_postgres_ssl("db.example.com", 5432)
    assert set(out.keys()) == {"host", "port", "ssl_status", "error_message", "raw_response_hex"}
    assert out["host"] == "db.example.com"
    assert out["port"] == 5432
    assert out["ssl_status"] == "supported"
    assert out["error_message"] is None
    assert out["raw_response_hex"] == "53"  # 'S'


def test_probe_handles_connection_refused(monkeypatch) -> None:
    from pqc_audit.scanners import postgres_ssl

    def raise_conn_refused(*args, **kwargs):
        raise ConnectionRefusedError("ECONNREFUSED")

    monkeypatch.setattr(postgres_ssl.socket, "create_connection", raise_conn_refused)

    out = postgres_ssl.probe_postgres_ssl("db.example.com", 5432)
    assert out["ssl_status"] == "error"
    assert "ECONNREFUSED" in (out["error_message"] or "")


def test_probe_handles_timeout(monkeypatch) -> None:
    from pqc_audit.scanners import postgres_ssl

    def raise_timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(postgres_ssl.socket, "create_connection", raise_timeout)

    out = postgres_ssl.probe_postgres_ssl("slow.example.com", 5432)
    assert out["ssl_status"] == "error"
    assert "timed out" in (out["error_message"] or "").lower()


def test_probe_handles_dns_failure(monkeypatch) -> None:
    from pqc_audit.scanners import postgres_ssl

    def raise_gaierror(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(postgres_ssl.socket, "create_connection", raise_gaierror)

    out = postgres_ssl.probe_postgres_ssl("nonexistent.invalid", 5432)
    assert out["ssl_status"] == "error"


# ---------------------------------------------------------------------
# Real-socket integration test with in-process mock TCP server.
# This is "test reali" per Aurelio's directive: actual socket I/O,
# actual wire protocol bytes — not monkeypatched. The mock server is
# in-process so the test is hermetic (no Postgres install required).
# ---------------------------------------------------------------------


def _start_mock_postgres_server(response_byte: bytes) -> tuple[int, threading.Event]:
    """Start a 1-shot TCP server that:

    1. Accepts one connection.
    2. Reads exactly 8 bytes (the SSLRequest).
    3. Verifies they match the expected magic.
    4. Sends ``response_byte`` and closes.

    Returns ``(bound_port, completed_event)``.
    """
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
                received = b""
                while len(received) < 8:
                    chunk = conn.recv(8 - len(received))
                    if not chunk:
                        break
                    received += chunk
                # Sanity: client must have sent the expected magic.
                if received == b"\x00\x00\x00\x08\x04\xd2\x16\x2f":
                    conn.sendall(response_byte)
            finally:
                conn.close()
        finally:
            sock.close()
            completed.set()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, completed


@pytest.mark.integration
def test_real_socket_probe_against_mock_server_returns_supported() -> None:
    """Real socket I/O, real wire bytes, mock postgres responds 'S'."""
    from pqc_audit.scanners.postgres_ssl import probe_postgres_ssl

    port, done = _start_mock_postgres_server(b"S")
    out = probe_postgres_ssl("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["ssl_status"] == "supported"
    assert out["raw_response_hex"] == "53"
    assert out["host"] == "127.0.0.1"
    assert out["port"] == port


@pytest.mark.integration
def test_real_socket_probe_against_mock_server_returns_not_supported() -> None:
    """Real socket I/O, mock postgres responds 'N' (no SSL)."""
    from pqc_audit.scanners.postgres_ssl import probe_postgres_ssl

    port, done = _start_mock_postgres_server(b"N")
    out = probe_postgres_ssl("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["ssl_status"] == "not_supported"
    assert out["raw_response_hex"] == "4e"


@pytest.mark.integration
def test_cli_scan_postgres_ssl_against_mock_server_emits_valid_json() -> None:
    """CLI subcommand wiring with real socket + real subprocess parsing.
    Closes the production-caller gap analogous to Sprint 9f.2 v2."""
    import json

    from typer.testing import CliRunner

    from pqc_audit.cli import app

    port, done = _start_mock_postgres_server(b"S")
    runner = CliRunner()
    result = runner.invoke(
        app,
        # --raw preserves the pre-9j.3 probe-dict CLI contract.
        ["scan", "postgres-ssl", "--host", "127.0.0.1", "--port", str(port),
         "--timeout", "5.0", "--raw"],
    )
    done.wait(timeout=5.0)
    assert result.exit_code == 0, f"CLI exited {result.exit_code}: {result.stdout}"
    payload = json.loads(result.stdout)
    assert payload["host"] == "127.0.0.1"
    assert payload["port"] == port
    assert payload["probe"] == "postgres-sslrequest"
    assert payload["result"]["ssl_status"] == "supported"
    assert payload["result"]["raw_response_hex"] == "53"


@pytest.mark.integration
def test_real_socket_probe_connection_refused_on_unbound_port() -> None:
    """Bind+close to grab a port nobody is listening on, then probe it."""
    from pqc_audit.scanners.postgres_ssl import probe_postgres_ssl

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    free_port = s.getsockname()[1]
    s.close()
    out = probe_postgres_ssl("127.0.0.1", free_port, timeout=2.0)
    assert out["ssl_status"] == "error"


# Silence linter on the asyncio import — kept available for future
# async refactor (e.g. probe_many in parallel).
_ = asyncio
