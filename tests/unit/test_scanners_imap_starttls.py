"""Tests for IMAP STARTTLS probe — Sprint 9m.

IMAP (RFC 3501) defaults to plaintext. A server that wants
encryption advertises ``STARTTLS`` (RFC 2595 / 3501 §6.2.1) in
response to the client's ``CAPABILITY`` command. The probe is
purely passive: connect, read ``* OK`` greeting, send tagged
``CAPABILITY``, read multi-line response, look for ``STARTTLS``
among the capability tokens.

Wire protocol (RFC 3501):

* server greets with ``* OK ...`` (untagged OK) on connect;
* client sends ``A001 CAPABILITY\\r\\n`` (any tag will do);
* server replies with one or more lines:
   * ``* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED ...`` (untagged
     CAPABILITY response, the data line);
   * ``A001 OK CAPABILITY completed`` (tagged final OK);
* the data line contains the capability tokens.

A server without STARTTLS on a mailbox channel violates NIS2
art. 21(2)(j) / D.Lgs. 138/2024 art. 24(2)(j) and CWE-319.
"""

from __future__ import annotations

import contextlib
import socket
import threading

import pytest

# ---------------------------------------------------------------------
# parse_imap_capabilities — pure function on the CAPABILITY response
# ---------------------------------------------------------------------


def test_parse_returns_starttls_when_present() -> None:
    from pqc_audit.scanners.imap_starttls import parse_imap_capabilities

    response = (
        "* CAPABILITY IMAP4rev1 IDLE STARTTLS LOGINDISABLED\r\n"
        "A001 OK CAPABILITY completed\r\n"
    )
    out = parse_imap_capabilities(response)
    assert out["starttls_supported"] is True
    assert "STARTTLS" in out["capabilities"]


def test_parse_returns_not_supported_when_absent() -> None:
    from pqc_audit.scanners.imap_starttls import parse_imap_capabilities

    response = (
        "* CAPABILITY IMAP4rev1 IDLE LOGINDISABLED\r\n"
        "A001 OK CAPABILITY completed\r\n"
    )
    out = parse_imap_capabilities(response)
    assert out["starttls_supported"] is False
    assert "STARTTLS" not in out["capabilities"]


def test_parse_is_case_insensitive() -> None:
    from pqc_audit.scanners.imap_starttls import parse_imap_capabilities

    out = parse_imap_capabilities("* capability imap4rev1 starttls\r\nA001 OK\r\n")
    assert out["starttls_supported"] is True


def test_parse_returns_empty_on_no_capability_line() -> None:
    from pqc_audit.scanners.imap_starttls import parse_imap_capabilities

    out = parse_imap_capabilities("A001 BAD malformed\r\n")
    assert out["starttls_supported"] is False
    assert out["capabilities"] == []


def test_parse_handles_empty_input() -> None:
    from pqc_audit.scanners.imap_starttls import parse_imap_capabilities

    out = parse_imap_capabilities("")
    assert out["starttls_supported"] is False
    assert out["capabilities"] == []


# ---------------------------------------------------------------------
# probe_imap_starttls — schema + error handling
# ---------------------------------------------------------------------


def test_probe_handles_connection_refused(monkeypatch) -> None:
    from pqc_audit.scanners import imap_starttls

    def raise_refused(*args, **kwargs):
        raise ConnectionRefusedError("ECONNREFUSED")

    monkeypatch.setattr(imap_starttls.socket, "create_connection", raise_refused)
    out = imap_starttls.probe_imap_starttls("imap.example.com", 143)
    assert out["starttls_status"] == "error"


def test_probe_handles_dns_failure(monkeypatch) -> None:
    from pqc_audit.scanners import imap_starttls

    def raise_gai(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(imap_starttls.socket, "create_connection", raise_gai)
    out = imap_starttls.probe_imap_starttls("nope.invalid", 143)
    assert out["starttls_status"] == "error"


# ---------------------------------------------------------------------
# Mock IMAP server integration tests (real socket I/O).
# ---------------------------------------------------------------------


def _start_mock_imap(
    *,
    advertise_starttls: bool,
    drop_after_greeting: bool = False,
) -> tuple[int, threading.Event]:
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
                # IMAP greeting.
                conn.sendall(b"* OK IMAP4rev1 mock service ready\r\n")
                if drop_after_greeting:
                    conn.close()
                    return
                # Read CAPABILITY command up to \r\n.
                buf = b""
                while not buf.endswith(b"\r\n"):
                    chunk = conn.recv(256)
                    if not chunk:
                        break
                    buf += chunk
                # Send CAPABILITY response.
                caps = b"IMAP4rev1 IDLE LOGINDISABLED"
                if advertise_starttls:
                    caps = b"IMAP4rev1 IDLE STARTTLS LOGINDISABLED"
                conn.sendall(b"* CAPABILITY " + caps + b"\r\nA001 OK CAPABILITY completed\r\n")
            finally:
                with contextlib.suppress(OSError):
                    conn.close()
        finally:
            sock.close()
            completed.set()

    threading.Thread(target=serve, daemon=True).start()
    return port, completed


@pytest.mark.integration
def test_real_socket_probe_against_mock_with_starttls() -> None:
    from pqc_audit.scanners.imap_starttls import probe_imap_starttls

    port, done = _start_mock_imap(advertise_starttls=True)
    out = probe_imap_starttls("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["starttls_status"] == "supported"
    assert "STARTTLS" in out["capabilities"]


@pytest.mark.integration
def test_real_socket_probe_against_mock_without_starttls() -> None:
    from pqc_audit.scanners.imap_starttls import probe_imap_starttls

    port, done = _start_mock_imap(advertise_starttls=False)
    out = probe_imap_starttls("127.0.0.1", port, timeout=5.0)
    done.wait(timeout=5.0)
    assert out["starttls_status"] == "not_supported"


@pytest.mark.integration
def test_real_socket_probe_greeting_only_returns_error() -> None:
    """Anti-false-positive (lesson from Sprint 9k counterexample):
    server that sends greeting but no CAPABILITY response must NOT
    be classified as not_supported."""
    from pqc_audit.scanners.imap_starttls import probe_imap_starttls

    port, done = _start_mock_imap(advertise_starttls=False, drop_after_greeting=True)
    out = probe_imap_starttls("127.0.0.1", port, timeout=2.0)
    done.wait(timeout=5.0)
    assert out["starttls_status"] == "error"


# ---------------------------------------------------------------------
# Scanner class (full Auditor integration, "integrazione totale").
# ---------------------------------------------------------------------


def test_imap_scanner_is_applicable_for_imap_starttls_target() -> None:
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.imap_starttls import IMAPStartTLSScanner

    target = ScanTarget(type="imap-starttls", host="imap.example.com", port=143)
    assert asyncio.run(IMAPStartTLSScanner().is_applicable(target)) is True


def test_imap_scanner_emits_high_cwe_319_on_not_supported() -> None:
    import asyncio

    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.imap_starttls import IMAPStartTLSScanner

    port, done = _start_mock_imap(advertise_starttls=False)
    scanner = IMAPStartTLSScanner()
    target = ScanTarget(type="imap-starttls", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 1
    assert high[0].cwe == "CWE-319"
    assert "imap" in high[0].title.lower() or "starttls" in high[0].title.lower()


def test_imap_scanner_no_high_when_starttls_supported() -> None:
    import asyncio

    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.imap_starttls import IMAPStartTLSScanner

    port, done = _start_mock_imap(advertise_starttls=True)
    scanner = IMAPStartTLSScanner()
    target = ScanTarget(type="imap-starttls", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 0


def test_target_type_imap_starttls_maps_to_network_category() -> None:
    from pqc_audit.core.models import ScanCategory
    from pqc_audit.scanners.base import target_to_category

    assert target_to_category("imap-starttls") == ScanCategory.NETWORK


def test_nis2_maps_imap_cleartext_to_art_24_2_h_and_j() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="IMAP server does not advertise STARTTLS",
        description="plaintext-only IMAP endpoint",
        severity=RiskLevel.HIGH,
        cwe="CWE-319",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles
    assert NIS2Article.ART_24_2_J in articles
