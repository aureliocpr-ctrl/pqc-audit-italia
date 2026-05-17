"""Tests for full Scanner integration of DB SSL probes — Sprint 9j.3.

Sprint 9j (Postgres) and 9j.2 (MySQL) shipped probe functions that
returned a raw dict. That made the probes reachable only via
dedicated CLI subcommands — they did NOT participate in the
``Auditor.scan`` pipeline, so they did NOT produce
:class:`CryptoAsset` / :class:`Vulnerability` entries, did NOT
appear in the standard Markdown report, were NOT picked up by the
NIS2 mapping, and were NOT evaluated by the policy engine.

Sprint 9j.3 closes that "integration totale" gap: each probe is
wrapped in a :class:`BaseScanner`-conformant Scanner class that:

* registers under a new :class:`ScanCategory.DATABASE`;
* emits one :class:`CryptoAsset` per scanned target;
* emits a HIGH :class:`Vulnerability` with CWE-319 (Cleartext
  Transmission of Sensitive Information) when ``ssl_status ==
  "not_supported"`` — directly citable under D.Lgs. 138/2024
  art. 24(2)(h);
* emits an INFO :class:`Vulnerability` on ``ssl_status == "error"``
  so the report does not silently swallow probe failures.

The Vulnerability titles use a stable schema picked up by the
new NIS2 patterns in :mod:`pqc_audit.compliance.nis2`.
"""

from __future__ import annotations

import asyncio
import socket
import threading

import pytest


# ---------------------------------------------------------------------
# ScanCategory.DATABASE must exist
# ---------------------------------------------------------------------


def test_scan_category_database_exists() -> None:
    from pqc_audit.core.models import ScanCategory

    assert hasattr(ScanCategory, "DATABASE")
    assert ScanCategory.DATABASE.value == "DATABASE"


# ---------------------------------------------------------------------
# Target types accept postgres-ssl + mysql-ssl
# ---------------------------------------------------------------------


def test_target_type_postgres_ssl_maps_to_database_category() -> None:
    from pqc_audit.core.models import ScanCategory
    from pqc_audit.scanners.base import target_to_category

    assert target_to_category("postgres-ssl") == ScanCategory.DATABASE


def test_target_type_mysql_ssl_maps_to_database_category() -> None:
    from pqc_audit.core.models import ScanCategory
    from pqc_audit.scanners.base import target_to_category

    assert target_to_category("mysql-ssl") == ScanCategory.DATABASE


# ---------------------------------------------------------------------
# PostgresSSLScanner Scanner class
# ---------------------------------------------------------------------


def _start_mock_postgres(response_byte: bytes) -> tuple[int, threading.Event]:
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
                conn.recv(8)
                conn.sendall(response_byte)
            finally:
                conn.close()
        finally:
            sock.close()
            completed.set()

    threading.Thread(target=serve, daemon=True).start()
    return port, completed


def test_postgres_scanner_is_applicable_for_postgres_ssl_target() -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.postgres_ssl import PostgresSSLScanner

    scanner = PostgresSSLScanner()
    target = ScanTarget(type="postgres-ssl", host="db.example.com", port=5432)
    assert asyncio.run(scanner.is_applicable(target)) is True


def test_postgres_scanner_not_applicable_for_tls_target() -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.postgres_ssl import PostgresSSLScanner

    scanner = PostgresSSLScanner()
    target = ScanTarget(type="tls", host="db.example.com", port=443)
    assert asyncio.run(scanner.is_applicable(target)) is False


def test_postgres_scanner_emits_asset_and_vuln_on_not_supported() -> None:
    """Real socket via mock server → not_supported → HIGH CWE-319."""
    from pqc_audit.core.models import RiskLevel, ScanCategory
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.postgres_ssl import PostgresSSLScanner

    port, done = _start_mock_postgres(b"N")
    scanner = PostgresSSLScanner()
    target = ScanTarget(type="postgres-ssl", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.category == ScanCategory.DATABASE
    assert "postgres" in asset.asset_id.lower()

    high_vulns = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high_vulns) == 1
    v = high_vulns[0]
    assert v.cwe == "CWE-319"
    assert "postgres" in v.title.lower()
    assert "ssl" in v.title.lower() or "cleartext" in v.title.lower()
    assert asset.asset_id in v.affected_asset_ids


def test_postgres_scanner_no_high_vuln_when_supported() -> None:
    """SSL supported → asset only, no HIGH vulnerability."""
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.postgres_ssl import PostgresSSLScanner

    port, done = _start_mock_postgres(b"S")
    scanner = PostgresSSLScanner()
    target = ScanTarget(type="postgres-ssl", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    assert len(result.assets) == 1
    high_vulns = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high_vulns) == 0


# ---------------------------------------------------------------------
# MySQLSSLScanner Scanner class
# ---------------------------------------------------------------------


def _build_mysql_handshake(*, ssl_enabled: bool) -> bytes:
    import struct

    cap_flags = 0x0FFE_FFFF if ssl_enabled else (0xFFFFFFFF ^ 0x0800)
    cap1 = cap_flags & 0xFFFF
    cap2 = (cap_flags >> 16) & 0xFFFF
    payload = (
        bytes([10])
        + b"8.0.36\x00"
        + struct.pack("<I", 1)
        + b"01234567"
        + b"\x00"
        + struct.pack("<H", cap1)
        + bytes([33])
        + struct.pack("<H", 0x0002)
        + struct.pack("<H", cap2)
    )
    length = len(payload)
    header = struct.pack("<I", length)[:3] + b"\x00"
    return header + payload


def _start_mock_mysql(handshake: bytes) -> tuple[int, threading.Event]:
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
                conn.sendall(handshake)
            finally:
                conn.close()
        finally:
            sock.close()
            completed.set()

    threading.Thread(target=serve, daemon=True).start()
    return port, completed


def test_mysql_scanner_emits_asset_and_high_vuln_on_no_ssl() -> None:
    from pqc_audit.core.models import RiskLevel, ScanCategory
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.mysql_ssl import MySQLSSLScanner

    port, done = _start_mock_mysql(_build_mysql_handshake(ssl_enabled=False))
    scanner = MySQLSSLScanner()
    target = ScanTarget(type="mysql-ssl", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    assert len(result.assets) == 1
    assert result.assets[0].category == ScanCategory.DATABASE
    assert "mysql" in result.assets[0].asset_id.lower()

    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 1
    assert high[0].cwe == "CWE-319"
    assert "mysql" in high[0].title.lower()


def test_mysql_scanner_no_high_vuln_when_ssl_supported() -> None:
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.mysql_ssl import MySQLSSLScanner

    port, done = _start_mock_mysql(_build_mysql_handshake(ssl_enabled=True))
    scanner = MySQLSSLScanner()
    target = ScanTarget(type="mysql-ssl", host="127.0.0.1", port=port)
    result = asyncio.run(scanner.scan(target))
    done.wait(timeout=5.0)

    high = [v for v in result.vulnerabilities if v.severity == RiskLevel.HIGH]
    assert len(high) == 0


# ---------------------------------------------------------------------
# NIS2 mapping must classify the new finding titles
# ---------------------------------------------------------------------


def test_nis2_maps_postgres_cleartext_to_art_24_2_h() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="PostgreSQL allows non-SSL connection",
        description="cleartext on postgres",
        severity=RiskLevel.HIGH,
        cwe="CWE-319",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles
    assert NIS2Article.ART_24_2_J in articles  # secure communications


def test_nis2_maps_mysql_cleartext_to_art_24_2_h() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="MySQL allows non-SSL connection",
        description="cleartext on mysql",
        severity=RiskLevel.HIGH,
        cwe="CWE-319",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles
    assert NIS2Article.ART_24_2_J in articles


# ---------------------------------------------------------------------
# End-to-end: Auditor.scan with a DB scanner produces the right report
# ---------------------------------------------------------------------


@pytest.mark.integration
def test_e2e_auditor_scan_postgres_emits_full_audit_report() -> None:
    """Full pipeline: ScanTarget → Auditor.scan → AuditReport with
    DATABASE asset + HIGH CWE-319 vuln citable via NIS2 mapping."""
    from pqc_audit.auditor import Auditor
    from pqc_audit.compliance.nis2 import NIS2Article, apply_nis2_mapping
    from pqc_audit.core.models import RiskLevel
    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.postgres_ssl import PostgresSSLScanner

    port, done = _start_mock_postgres(b"N")
    auditor = Auditor(scanners=[PostgresSSLScanner()])
    target = ScanTarget(type="postgres-ssl", host="127.0.0.1", port=port)
    report = asyncio.run(auditor.scan([target]))
    done.wait(timeout=5.0)

    assert report.total_assets == 1
    assert report.total_vulnerabilities >= 1
    assert report.highest_severity == RiskLevel.HIGH

    nis2 = apply_nis2_mapping(report)
    # At least one finding cites art. 24(2)(h)
    cited = {a for arts in nis2.values() for a in arts}
    assert NIS2Article.ART_24_2_H in cited
