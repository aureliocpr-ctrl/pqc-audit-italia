"""Tests for pqc_audit.reporters.pdf_reporter — weasyprint-backed PDF."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from unittest.mock import patch


def _build_audit_report():
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        RiskLevel,
        ScanCategory,
        ScanResult,
        Vulnerability,
    )

    asset = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
    )
    vuln = Vulnerability(
        title="Quantum-vulnerable algorithm in use",
        description="RSA-2048 broken by Shor.",
        severity=RiskLevel.HIGH,
        affected_asset_ids=("tls://example.it:443",),
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=[vuln],
        started_at=datetime(2026, 5, 4, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 4, 12, 0, 5, tzinfo=UTC),
    )
    return AuditReport(
        report_id="audit-2026-001",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=[],
        generated_at=datetime(2026, 5, 4, 12, 0, 10, tzinfo=UTC),
    )


def test_pdf_reporter_renders_bytes_when_weasyprint_present() -> None:
    import pytest

    if not _weasyprint_runtime_available():
        pytest.skip("weasyprint runtime not available (e.g. Windows without GTK)")
    from pqc_audit.reporters.pdf_reporter import render

    out = render(_build_audit_report())
    assert isinstance(out, bytes)
    assert len(out) > 0
    # Real weasyprint output starts with the PDF magic bytes
    assert out[:4] == b"%PDF"


def test_pdf_reporter_raises_runtime_error_when_weasyprint_missing() -> None:
    """Simulate weasyprint being uninstalled and confirm a clear error."""
    # Patch sys.modules so the lazy import inside render() fails.
    blocked = {"weasyprint": None}
    # Drop any cached pdf_reporter so the module re-imports lazily.
    sys.modules.pop("pqc_audit.reporters.pdf_reporter", None)
    with patch.dict(sys.modules, blocked):
        from pqc_audit.reporters.pdf_reporter import render

        try:
            render(_build_audit_report())
        except RuntimeError as e:
            assert "weasyprint" in str(e).lower()
            assert "pip install" in str(e).lower()
        else:
            raise AssertionError("RuntimeError not raised when weasyprint missing")


def _weasyprint_runtime_available() -> bool:
    """True iff WeasyPrint can be imported AND its native GTK
    runtime is reachable. On Windows without GTK3, the import itself
    raises OSError (libgobject-2.0-0 not found), which
    ``pytest.importorskip`` doesn't catch — we must guard manually.
    """
    try:
        import weasyprint  # noqa: F401, PLC0415

        return True
    except (ImportError, OSError):
        return False


def test_pdf_reporter_no_network_fetcher_blocks_http() -> None:
    """SSRF guard: ``_no_network_fetcher`` rejects http(s) URLs.

    Regression test for CWE-918: an attacker-controlled
    AuditReport.vulnerabilities[].description containing
    ``![x](http://169.254.169.254/...)`` could otherwise turn the PDF
    render into an outbound HTTP fetch via the optional ``markdown``
    package → WeasyPrint default URL fetcher.

    This test does NOT require WeasyPrint: the function rejects
    non-``data:`` URLs before any WeasyPrint import.
    """
    import pytest

    from pqc_audit.reporters import pdf_reporter

    for blocked_url in (
        "http://attacker.example/leak",
        "https://attacker.example/leak",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ):
        with pytest.raises(ValueError, match="blocked"):
            pdf_reporter._no_network_fetcher(blocked_url)


def test_pdf_reporter_no_network_fetcher_blocks_file_uri() -> None:
    """SSRF/local-file guard: ``file://`` is rejected.

    Does NOT require WeasyPrint runtime."""
    import pytest

    from pqc_audit.reporters import pdf_reporter

    with pytest.raises(ValueError, match="blocked"):
        pdf_reporter._no_network_fetcher("file:///etc/passwd")


def test_pdf_reporter_no_network_fetcher_allows_data_uri() -> None:
    """Inline ``data:`` URIs (the only safe case) are allowed."""
    import pytest

    if not _weasyprint_runtime_available():
        pytest.skip("weasyprint runtime not available (e.g. Windows without GTK)")
    from pqc_audit.reporters import pdf_reporter

    # 1x1 transparent PNG, base64-encoded.
    payload = pdf_reporter._no_network_fetcher(
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    )
    # WeasyPrint's contract: either ``string`` or ``file_obj`` carries the bytes.
    assert "string" in payload or "file_obj" in payload


def test_pdf_reporter_render_uses_markdown_content() -> None:
    """The PDF body should be derived from the MarkdownReporter, so its
    HTML payload includes the executive header and the tool name."""
    import pytest

    if not _weasyprint_runtime_available():
        pytest.skip("weasyprint runtime not available (e.g. Windows without GTK)")
    # Patch the inner HTML rendering helper to return the input HTML
    # so we can introspect what's being passed to weasyprint.
    from pqc_audit.reporters import pdf_reporter

    captured: dict[str, str] = {}

    def fake_html_to_pdf(html: str) -> bytes:
        captured["html"] = html
        return b"%PDF-fake"

    original = pdf_reporter._html_to_pdf
    pdf_reporter._html_to_pdf = fake_html_to_pdf  # type: ignore[assignment]
    try:
        out = pdf_reporter.render(_build_audit_report())
    finally:
        pdf_reporter._html_to_pdf = original  # type: ignore[assignment]
    assert out == b"%PDF-fake"
    assert "pqc-audit-italia" in captured["html"]
    assert "audit-2026-001" in captured["html"]
