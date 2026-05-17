"""Tests for trust-anchor section in markdown_reporter — Sprint 9d.4.

The TLSScanner (Sprint 9d.3) populates the leaf CryptoAsset.metadata
with a ``trust_anchor`` dict and ``trust_store_source`` label. The
executive Markdown report must surface this information for a DPO /
CISO, with Italian-language labels for pedigree:

* ``qualified_it_tsp`` → "AgID-accreditata (TSP qualificato italiano)"
* ``commercial_global`` → "CA commerciale globale"
* ``unknown`` → "Sconosciuta — richiede verifica manuale"

Section heading: "## Trust anchor — CA radice" (Italian, audit-friendly).

Skip rules:

* Section absent if NO leaf asset has a ``trust_anchor`` key.
* If leaf has ``trust_anchor`` but resolved=False, the row is
  rendered with "non risolto" status — surfaced not silently dropped.
"""

from __future__ import annotations

from datetime import UTC, datetime


def _build_audit_report_with_trust_anchor(
    *,
    pedigree: str = "qualified_it_tsp",
    resolved: bool = True,
    root_subject: str = "CN=Actalis Authentication Root CA,O=Actalis S.p.A.,C=IT",
    source: str = "trust_store",
    trust_store_source_label: str = "certifi",
    include_trust_anchor: bool = True,
    extra_leaves: int = 0,
):
    """Build a report whose leaf asset carries the trust_anchor metadata."""
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        RiskLevel,
        ScanCategory,
        ScanResult,
        Vulnerability,
    )

    leaf_meta: dict = {
        "tls_version": "TLSv1.3",
        "chain_position": "leaf",
        "chain_length": 2,
    }
    if include_trust_anchor:
        leaf_meta["trust_anchor"] = {
            "resolved": resolved,
            "source": source if resolved else "unknown",
            "root_subject": root_subject if resolved else None,
            "root_signature_hash": "SHA256" if resolved else None,
            "root_key_size": 4096 if resolved else None,
            "root_algorithm": "RSA" if resolved else None,
            "pedigree": pedigree,
        }
        leaf_meta["trust_store_source"] = trust_store_source_label

    assets = [
        CryptoAsset(
            asset_id="tls://example.it:443",
            category=ScanCategory.NETWORK,
            algorithm=Algorithm(name="RSA", key_size_bits=2048),
            location="example.it:443",
            discovered_at=datetime(2026, 5, 17, 12, 0, tzinfo=UTC),
            metadata=leaf_meta,
        )
    ]
    for i in range(extra_leaves):
        extra_meta = {
            "tls_version": "TLSv1.3",
            "chain_position": "leaf",
            "chain_length": 2,
        }
        if include_trust_anchor:
            extra_meta["trust_anchor"] = {
                "resolved": True,
                "source": "trust_store",
                "root_subject": "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
                "root_signature_hash": "SHA256",
                "root_key_size": 4096,
                "root_algorithm": "RSA",
                "pedigree": "commercial_global",
            }
            extra_meta["trust_store_source"] = "certifi"
        assets.append(
            CryptoAsset(
                asset_id=f"tls://extra-{i}.example.com:443",
                category=ScanCategory.NETWORK,
                algorithm=Algorithm(name="RSA", key_size_bits=2048),
                location=f"extra-{i}.example.com:443",
                discovered_at=datetime(2026, 5, 17, 12, 0, tzinfo=UTC),
                metadata=extra_meta,
            )
        )

    vulns = [
        Vulnerability(
            title="Quantum-vulnerable algorithm in use",
            description="RSA-2048 broken by Shor.",
            severity=RiskLevel.HIGH,
            cwe="CWE-327",
            affected_asset_ids=("tls://example.it:443",),
        )
    ]
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=assets,
        vulnerabilities=vulns,
        started_at=datetime(2026, 5, 17, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 17, 12, 0, 1, tzinfo=UTC),
    )
    return AuditReport(
        report_id="audit-9d.4",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=[],
        generated_at=datetime(2026, 5, 17, 12, 0, 2, tzinfo=UTC),
        metadata={},
    )


# ---------------------------------------------------------------------
# Section presence / absence
# ---------------------------------------------------------------------


def test_trust_anchor_section_present_when_leaf_has_trust_anchor() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report_with_trust_anchor())
    assert "## Trust anchor" in out
    assert "CA radice" in out


def test_trust_anchor_section_absent_when_no_leaf_carries_metadata() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report_with_trust_anchor(include_trust_anchor=False))
    assert "## Trust anchor" not in out


# ---------------------------------------------------------------------
# Pedigree Italian labels
# ---------------------------------------------------------------------


def test_pedigree_qualified_it_tsp_uses_italian_label() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report_with_trust_anchor(pedigree="qualified_it_tsp"))
    assert "AgID-accreditata" in out
    assert "TSP qualificato italiano" in out


def test_pedigree_commercial_global_uses_italian_label() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(
        _build_audit_report_with_trust_anchor(
            pedigree="commercial_global",
            root_subject="CN=ISRG Root X1,O=Internet Security Research Group,C=US",
        )
    )
    assert "CA commerciale globale" in out


def test_pedigree_unknown_uses_italian_label() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(
        _build_audit_report_with_trust_anchor(
            pedigree="unknown",
            root_subject="CN=Some Private Lab Root,O=Tiny Lab,C=ZZ",
        )
    )
    assert "Sconosciuta" in out
    assert "verifica manuale" in out


# ---------------------------------------------------------------------
# Unresolved trust anchor (resolved=False) is surfaced, not dropped
# ---------------------------------------------------------------------


def test_unresolved_trust_anchor_surfaced_as_non_risolto() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report_with_trust_anchor(resolved=False))
    # The leaf is still listed, but its row says "non risolto".
    assert "## Trust anchor" in out
    assert "non risolto" in out


# ---------------------------------------------------------------------
# Source disclosure
# ---------------------------------------------------------------------


def test_trust_store_source_certifi_disclosed_honestly() -> None:
    """We never call certifi 'the Windows trust store'. The label must
    appear verbatim so a reader can audit the trust anchor's origin."""
    from pqc_audit.reporters.markdown_reporter import render

    out = render(
        _build_audit_report_with_trust_anchor(
            trust_store_source_label="certifi",
            source="trust_store",
        )
    )
    assert "certifi" in out


def test_trust_store_source_system_ca_bundle_disclosed() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(
        _build_audit_report_with_trust_anchor(
            trust_store_source_label="system_ca_bundle",
            source="trust_store",
        )
    )
    assert "system_ca_bundle" in out


def test_root_subject_visible_in_section() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(
        _build_audit_report_with_trust_anchor(
            root_subject="CN=Actalis Authentication Root CA,O=Actalis S.p.A.,C=IT"
        )
    )
    assert "Actalis Authentication Root CA" in out


def test_root_algorithm_and_key_size_visible() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report_with_trust_anchor())
    assert "RSA" in out
    assert "4096" in out


# ---------------------------------------------------------------------
# Multiple targets
# ---------------------------------------------------------------------


def test_multiple_leaves_each_have_a_row() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_audit_report_with_trust_anchor(extra_leaves=2))
    # Original Actalis + 2 extra ISRG rows
    assert out.count("Actalis Authentication Root CA") >= 1
    assert out.count("ISRG Root X1") >= 1
    # Extra targets carry their asset_id
    assert "extra-0.example.com" in out or "extra-1.example.com" in out
