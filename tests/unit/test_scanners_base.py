"""Tests for pqc_audit.scanners.base — protocol + ScanTarget model."""

from __future__ import annotations

import pytest


def test_scan_target_network_basic() -> None:
    from pqc_audit.scanners.base import ScanTarget

    t = ScanTarget(type="tls", host="example.it", port=443)
    assert t.type == "tls"
    assert t.host == "example.it"
    assert t.port == 443


def test_scan_target_filesystem_basic() -> None:
    from pqc_audit.scanners.base import ScanTarget

    t = ScanTarget(type="filesystem", path="/etc/ssl")
    assert t.type == "filesystem"
    assert t.path == "/etc/ssl"


def test_scan_target_rejects_invalid_port() -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanTarget(type="tls", host="example.it", port=99999)


def test_scan_target_rejects_unknown_type() -> None:
    from pqc_audit.scanners.base import ScanTarget
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanTarget(type="laser-beam-scan", host="x")


def test_base_scanner_protocol_has_required_attrs() -> None:
    from pqc_audit.scanners.base import BaseScanner

    # BaseScanner is a Protocol — verify the attribute names exist
    assert "name" in BaseScanner.__annotations__
    assert "category" in BaseScanner.__annotations__


def test_scan_category_in_target() -> None:
    """The target's type maps to a ScanCategory under the hood."""
    from pqc_audit.core.models import ScanCategory
    from pqc_audit.scanners.base import target_to_category

    assert target_to_category("tls") is ScanCategory.NETWORK
    assert target_to_category("ssh") is ScanCategory.NETWORK
    assert target_to_category("filesystem") is ScanCategory.FILESYSTEM
    assert target_to_category("certs") is ScanCategory.FILESYSTEM
    assert target_to_category("code") is ScanCategory.CODE
    assert target_to_category("binary") is ScanCategory.BINARY
    assert target_to_category("config") is ScanCategory.CONFIG
