"""Tests for pqc_audit.Auditor — high-level orchestration."""

from __future__ import annotations

import pytest


def test_auditor_default_policy() -> None:
    from pqc_audit import Auditor

    a = Auditor()
    assert a.policy == "default"


def test_auditor_custom_policy() -> None:
    from pqc_audit import Auditor

    a = Auditor(policy="agid_2026")
    assert a.policy == "agid_2026"


def test_auditor_registers_default_scanners() -> None:
    from pqc_audit import Auditor

    a = Auditor()
    names = {s.name for s in a.scanners}
    assert "tls" in names


@pytest.mark.asyncio
async def test_auditor_returns_audit_report_when_target_unreachable() -> None:
    """Even on network error, the auditor returns a structured report
    with the error captured in scan_results[].errors."""
    from pqc_audit import Auditor, ScanTarget

    a = Auditor()
    # Use a TCP port that is *very* unlikely to answer to keep the test fast
    target = ScanTarget(type="tls", host="127.0.0.1", port=1)
    report = await a.scan([target])
    assert report.report_id
    assert len(report.scan_results) == 1
    sr = report.scan_results[0]
    assert sr.scanner_name == "tls"
    assert sr.errors  # something failed (refused connection / timeout)
