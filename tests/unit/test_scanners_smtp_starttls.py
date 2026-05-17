"""Tests for SMTP STARTTLS probe — Sprint 9k.

SMTP (RFC 5321) is plaintext-by-default. A server that wants
encryption must advertise the STARTTLS extension (RFC 3207) in
response to the client's EHLO. The probe is **passive**: connect,
read banner, send EHLO, read multi-line 250 response, check
presence of ``STARTTLS`` capability line. No actual TLS upgrade
is performed — we only verify the server's *willingness* to
upgrade.

Wire protocol (RFC 5321 + RFC 3207):

* server greets with ``220 hostname ESMTP ...`` on connect;
* client sends ``EHLO client.example.com\\r\\n``;
* server replies with multi-line 250 codes, each line either
  ``250-CAPABILITY`` (intermediate) or ``250 CAPABILITY`` (final);
* one of the capability lines is ``STARTTLS`` when the server
  supports TLS upgrade.

A server without STARTTLS violates NIS2 art. 21(2)(j) /
D.Lgs. 138/2024 art. 24(2)(j) on secure communications when
the message corpus is subject to confidentiality requirements.
"""

from __future__ import annotations

import contextlib
import socket
import threading

import pytest

# ---------------------------------------------------------------------
# parse_smtp_capabilities — pure function on the EHLO response text
# ---------------------------------------------------------------------


def test_parse_returns_starttls_supported_when_capability_present() -> None:
    from pqc_audit.scanners.smtp_starttls import parse_smtp_capabilities

    ehlo_response = (
        "250-mail.example.com Hello [203.0.113.1]\r\n"
        "250-SIZE 52428800\r\n"
        "250-STARTTLS\r\n"
        "250 HELP\r\n"
    )
    out = parse_smtp_capabilities(ehlo_response)
    assert out["starttls_supported"] is True
    assert "STARTTLS" in out["capabilities"]


def test_parse_returns_starttls_not_supported_when_absent() -> None:
    from pqc_audit.scanners.smtp_starttls import parse_smtp_capabilities

    ehlo_response = (
        "250-mail.example.com Hello\r\n"
        "250-SIZE 10485760\r\n"
        "250 HELP\r\n"
    )
    out = parse_smtp_capabilities(ehlo_response)
    assert out["starttls_supported"] is False


def test_parse_is_case_insensitive_for_starttls_token() -> None:
    from pqc_audit.scanners.smtp_starttls import parse_smtp_capabilities

    out = parse_smtp_capabilities("250-mail Hello\r\n250 starttls\r\n")
    assert out["starttls_supported"] is True


def test_parse_extracts_server_banner() -> None:
    from pqc_audit.scanners.smtp_starttls import parse_smtp_capabilities

    ehlo_response = (
        "250-mx.example.it Hello server example.it [10.0.0.1]\r\n"
        "250-STARTTLS\r\n"
        "250 OK\r\n"
    )
    out = parse_smtp_capabilities(ehlo_response)
    assert "example.it" in out["server_hostname"]


def test_parse_returns_empty_capabilities_on_empty_input() -> None:
    from pqc_audit.scanners.smtp_starttls import parse_smtp_capabilities

    out = parse_smtp_capabilities("")
    assert out["starttls_supported"] is False
    assert out["capabilities"] == []


def test_parse_ignores_non_250_lines() -> None:
    from pqc_audit.scanners.smtp_starttls import parse_smtp_capabilities

    ehlo_response = (
        "500 Syntax error\r\n"
        "421 Service not available\r\n"
    )
    out = parse_smtp_capabilities(ehlo_response)
    assert out["starttls_supported"] is False
    assert out["capabilities"] == []


# ---------------------------------------------------------------------
# probe_smtp_starttls — schema + error handling via monkeypatch
# ---------------------------------------------------------------------


def test_probe_returns_required_keys(monkeypatch) -> None:
    from pqc_audit.scanners import smtp_starttls

    class FakeSocket:
        def __init__(self):
            self._buf = (
                b"220 mx.example.com ESMTP Postfix\r\n"
                b"250-mx.example.com Hello\r\n"
                b"250-STARTTLS\r\n"
                b"250 HELP\r\n"
            )
            self.sent: list[bytes] = []

        def settimeout(self, *args):
            return None

        def sendall(self, data):
            self.sent.append(data)

        def recv(self, n):
            chunk = self._buf[:n]
            self._buf = self._buf[n:]
            return chunk

        def close(self):
            return None

    monkeypatch.setattr(
        smtp_starttls.socket, "create_connection", lambda *a, **k: FakeSocket()
    )

    out = smtp_starttls.probe_smtp_starttls("mx.example.com", 25)
    assert set(out.keys()) >= {
        "host",
        "port",
        "starttls_status",
        "error_message",
        "banner",
        "capabilities",
    }
    assert out["host"] == "mx.example.com"
    assert out["port"] == 25
    assert out["starttls_status"] == "supported"
    assert "STARTTLS" in out["capabilities"]
    assert "ESMTP" in out["banner"]


def test_probe_returns_not_supported_when_capability_missing(monkeypatch) -> None:
    from pqc_audit.scanners import smtp_starttls

    class FakeSocket:
        def __init__(self):
            self._buf = (
                b"220 mx.example.com ESMTP\r\n"
                b"250-mx.example.com Hello\r\n"
                b"250 HELP\r\n"
            )

        def settimeout(self, *args):
            return None

        def sendall(self, data):
            return None

        def recv(self, n):
            chunk = self._buf[:n]
            self._buf = self._buf[n:]
            return chunk

        def close(self):
            return None

    monkeypatch.setattr(
        smtp_starttls.socket, "create_connection", lambda *a, **k: FakeSocket()
    )

    out = smtp_starttls.probe_smtp_starttls("mx.example.com", 25)
    assert out["starttls_status"] == "not_supported"


def test_probe_handles_connection_refused(monkeypatch) -> None:
    from pqc_audit.scanners import smtp_starttls

    def raise_refused(*args, **kwargs):
        raise ConnectionRefusedError("ECONNREFUSED")

    monkeypatch.setattr(smtp_starttls.socket, "create_connection", raise_refused)
    out = smtp_starttls.probe_smtp_starttls("mx.example.com", 25)
    assert out["starttls_status"] == "error"


def test_probe_handles_dns_failure(monkeypatch) -> None:
    from pqc_audit.scanners import smtp_starttls

    def raise_gaierror(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(smtp_starttls.socket, "create_connection", raise_gaierror)
    out = smtp_starttls.probe_smtp_starttls("nope.invalid", 25)
    assert out["starttls_status"] == "error"


# ---------------------------------------------------------------------
# Real-socket integration test with in-process mock SMTP server.
# ---------------------------------------------------------------------


def _start_mock_smtp(*, advertise_starttls: bool) -> tuple[int, threading.Event]:
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
                # Send banner.
                conn.sendall(b"220 mock.smtp.test ESMTP Mock\r\n")
                # Read EHLO line (up to \r\n).
                buf = b""
                while not buf.endswith(b"\r\n"):
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    buf += chunk
                # Send EHLO response.
                lines = [b"250-mock.smtp.test Hello\r\n"]
                if advertise_starttls:
                    lines.append(b"250-STARTTLS\r\n")
                lines.append(b"250 HELP\r\n")
                conn.sendall(b"".join(lines))
            finally:
                conn.close()
        finally:
            sock.close()
            completed.set()

    threading.Thread(target=serve, daemon=True).start()
    return port, completed


@pytest.mark.integration
def test_real_socket_probe_against_mock_with_starttls() -> None:
    from pqc_audit.scanners.smtp_starttls import probe_smtp_starttls

    port, done = _start_mock_smtp(advertise_starttls=True)
    out = probe_smtp_starttls("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["starttls_status"] == "supported"
    assert "STARTTLS" in out["capabilities"]


def _start_mock_smtp_banner_only(*, drop_after_banner: bool = True) -> tuple[int, threading.Event]:
    """Mock SMTP server that ships a 220 banner then hangs / drops the
    connection without responding to EHLO. Models firewall + captive
    portal + honeypot scenarios that the v1 probe misclassified as
    not_supported (false positive HIGH CWE-319) — counterexample worker
    bug found in Sprint 9k critic gate.
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
                conn.sendall(b"220 silent.smtp.test ESMTP\r\n")
                # Read EHLO but never reply.
                conn.recv(256)
                if drop_after_banner:
                    conn.close()
                else:
                    # Hold the socket so client recv times out.
                    import time
                    time.sleep(2.0)
            finally:
                with contextlib.suppress(OSError):
                    conn.close()
        finally:
            sock.close()
            completed.set()

    threading.Thread(target=serve, daemon=True).start()
    return port, completed


@pytest.mark.integration
def test_real_socket_probe_banner_then_silence_returns_error() -> None:
    """Post-critic-v1 fix: banner-only-then-silence MUST surface as
    `starttls_status="error"`, not silently classify as
    `not_supported` (which would emit a false-positive HIGH CWE-319
    Vulnerability)."""

    from pqc_audit.scanners.smtp_starttls import probe_smtp_starttls

    port, done = _start_mock_smtp_banner_only(drop_after_banner=True)
    out = probe_smtp_starttls("127.0.0.1", port, timeout=2.0)
    done.wait(timeout=5.0)
    assert out["starttls_status"] == "error"
    assert out["error_message"] and "250" in out["error_message"]


@pytest.mark.integration
def test_smtp_scanner_emits_INFO_not_HIGH_on_banner_only_silence() -> None:
    """Counterexample worker found this case: banner+silence produced a
    HIGH CWE-319 Vulnerability in v1. Post-fix it must produce INFO
    only, so an auditor does NOT cite a NIS2 art. 24 violation for a
    server that simply timed out."""
    import asyncio

    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.smtp_starttls import SMTPStartTLSScanner

    port, done = _start_mock_smtp_banner_only(drop_after_banner=True)
    scanner = SMTPStartTLSScanner()
    target = ScanTarget(type="smtp-starttls", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 0, f"expected no HIGH finding on banner-silence, got {high}"
    info = [v for v in result.vulnerabilities if v.severity == RiskLevel.INFO]
    assert len(info) == 1
    assert info[0].cwe is None


@pytest.mark.integration
def test_real_socket_probe_against_mock_without_starttls() -> None:
    from pqc_audit.scanners.smtp_starttls import probe_smtp_starttls

    port, done = _start_mock_smtp(advertise_starttls=False)
    out = probe_smtp_starttls("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["starttls_status"] == "not_supported"


# ---------------------------------------------------------------------
# Scanner class — full Auditor integration (Sprint 9k follows the
# 9j.3 "integrazione totale" pattern).
# ---------------------------------------------------------------------


def test_smtp_scanner_is_applicable_for_smtp_starttls_target() -> None:
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.smtp_starttls import SMTPStartTLSScanner

    target = ScanTarget(type="smtp-starttls", host="mx.example.com", port=25)
    assert asyncio.run(SMTPStartTLSScanner().is_applicable(target)) is True


def test_smtp_scanner_emits_high_cwe_319_on_not_supported() -> None:
    import asyncio

    from pqc_audit.core.models import RiskLevel, ScanCategory
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.smtp_starttls import SMTPStartTLSScanner

    port, done = _start_mock_smtp(advertise_starttls=False)
    scanner = SMTPStartTLSScanner()
    target = ScanTarget(type="smtp-starttls", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    assert len(result.assets) == 1
    assert result.assets[0].category == ScanCategory.NETWORK
    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 1
    assert high[0].cwe == "CWE-319"
    assert "smtp" in high[0].title.lower() or "starttls" in high[0].title.lower()


def test_smtp_scanner_no_high_vuln_when_starttls_supported() -> None:
    import asyncio

    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.smtp_starttls import SMTPStartTLSScanner

    port, done = _start_mock_smtp(advertise_starttls=True)
    scanner = SMTPStartTLSScanner()
    target = ScanTarget(type="smtp-starttls", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 0


def test_target_type_smtp_starttls_maps_to_network_category() -> None:
    from pqc_audit.core.models import ScanCategory
    from pqc_audit.scanners.base import target_to_category

    assert target_to_category("smtp-starttls") == ScanCategory.NETWORK


def test_nis2_maps_smtp_cleartext_to_art_24_2_h_and_j() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="SMTP server does not advertise STARTTLS",
        description="plaintext-only smtp endpoint",
        severity=RiskLevel.HIGH,
        cwe="CWE-319",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles
    assert NIS2Article.ART_24_2_J in articles
