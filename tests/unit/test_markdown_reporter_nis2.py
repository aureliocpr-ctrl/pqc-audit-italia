"""Tests for NIS2 / D.Lgs. 138/2024 art. 24 section in markdown_reporter.

Sprint 9h-integration — the standalone `pqc-audit compliance nis2` CLI
already maps findings to lettered measures, but a PwC-grade audit report
needs the citation inline in the executive Markdown so a DPO / CISO can
ship it to the regulator without running a second command.

The new section must:

* appear after the policy "## Compliance" section and before the footer
* be titled "## NIS2 — D.Lgs. 138/2024 art. 24" (NOT "## Compliance
  NIS2") so it does not collide with the policy "## Compliance" test
* be skipped entirely if there are no vulnerabilities (graceful empty)
* emit one row per distinct vulnerability title, with the article
  citation OR "—" + "needs review" marker if unmapped
* list distinct articles implicated (order-preserving via
  :func:`summarize_articles`)
* cite the sanction caps from D.Lgs. 138/2024 art. 38 as constants,
  NOT magic numbers
"""

from __future__ import annotations

from datetime import UTC, datetime


def _build_report(*, vuln_titles: list[str], with_policy_eval: bool = False):
    """Build an AuditReport with one vuln per title. Asset is shared."""
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
        discovered_at=datetime(2026, 5, 17, 12, 0, tzinfo=UTC),
    )
    vulns = [
        Vulnerability(
            title=title,
            description=f"Synthetic test vulnerability: {title}",
            severity=RiskLevel.MEDIUM,
            cwe="CWE-327",
            affected_asset_ids=("tls://example.it:443",),
        )
        for title in vuln_titles
    ]
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=vulns,
        started_at=datetime(2026, 5, 17, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 5, 17, 12, 0, 1, tzinfo=UTC),
    )
    metadata: dict = {}
    if with_policy_eval:
        metadata["policy_evaluation"] = {
            "overall_verdict": "FAIL",
            "policy_name": "agid_2026",
            "total_assets_evaluated": 1,
            "compliant_assets": 0,
            "non_compliant_assets": 1,
            "violations": [],
        }
    return AuditReport(
        report_id="audit-9h-integration",
        scan_results=[sr],
        policy_name="agid_2026",
        recommendations=[],
        generated_at=datetime(2026, 5, 17, 12, 0, 2, tzinfo=UTC),
        metadata=metadata,
    )


# ---------------------------------------------------------------------
# Visibility / structure
# ---------------------------------------------------------------------


def test_nis2_section_present_when_vulnerability_maps_to_article() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    assert "## NIS2" in out
    assert "D.Lgs. 138/2024" in out
    assert "art. 24" in out


def test_nis2_section_absent_when_no_vulnerabilities() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=[]))
    # No vulns at all → the NIS2 mapping has nothing to say.
    assert "## NIS2" not in out


def test_nis2_section_appears_after_policy_compliance_section() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(
        _build_report(
            vuln_titles=["Quantum-vulnerable algorithm in use"],
            with_policy_eval=True,
        )
    )
    pos_policy = out.find("## Compliance")
    pos_nis2 = out.find("## NIS2")
    assert pos_policy != -1, "policy Compliance section must be present"
    assert pos_nis2 != -1, "NIS2 section must be present"
    assert pos_policy < pos_nis2, "NIS2 section must follow policy Compliance section"


def test_nis2_section_title_does_not_start_with_compliance_word() -> None:
    """Anti-collision with existing 'no policy Compliance section' test."""
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    # The section heading itself should start with "## NIS2", NOT
    # "## Compliance NIS2" — because the latter would break the
    # existing test that asserts "## Compliance" not in out when
    # policy_evaluation is absent.
    assert "## Compliance NIS2" not in out


# ---------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------


def test_nis2_section_cites_lettered_article_h_for_quantum_vulnerable() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    # The canonical citation from NIS2Article.ART_24_2_H.legal_reference
    # is "D.Lgs. 138/2024, art. 24, comma 2, lett. (h)".
    assert "lett. (h)" in out


def test_nis2_section_cites_eu_directive_reference() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    assert "Direttiva (UE) 2022/2555" in out


def test_nis2_section_includes_article_topic_text() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    # ART_24_2_H topic mentions "crittografia"
    assert "crittografia" in out.lower()


def test_nis2_section_marks_unmapped_finding_for_review() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    # "Synthetic invented title" does not match any _TITLE_PATTERNS → [].
    # The reporter MUST surface it as needs-review, not silently drop it.
    out = render(_build_report(vuln_titles=["Some title with no NIS2 mapping yet"]))
    # The vuln title appears in the table
    assert "Some title with no NIS2 mapping yet" in out
    # And the row is flagged for manual review
    lower = out.lower()
    assert "da revisionare" in lower or "needs review" in lower


def test_nis2_section_dedups_distinct_articles_in_summary() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    # Two findings both map to ART_24_2_H → the "articoli implicati"
    # summary must list the article only once.
    out = render(
        _build_report(
            vuln_titles=[
                "Quantum-vulnerable algorithm in use",
                "Quantum-weakened key encapsulation",
            ]
        )
    )
    # Count occurrences of the canonical article citation in the summary.
    # We expect at least once in the table (per row) AND at least once in
    # the summary block. The summary itself must NOT duplicate it.
    # Strategy: check that the topic string appears, and assert summary
    # block contains lett. (h) exactly once.
    summary_start = out.find("Articoli implicati")
    assert summary_start != -1, "section must include 'Articoli implicati' summary"
    summary_block = out[summary_start:]
    # In the summary block, "lett. (h)" should appear exactly once.
    assert summary_block.count("lett. (h)") == 1


# ---------------------------------------------------------------------
# Sanctions block (art. 38)
# ---------------------------------------------------------------------


def test_nis2_section_includes_sanction_essential_cap() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    # 10 000 000 EUR cap for soggetti essenziali (with thousands separator
    # OR plain digits — both acceptable, but the digits must be present).
    assert "10 000 000" in out or "10,000,000" in out or "10000000" in out
    assert "2.0" in out or "2 %" in out or "2%" in out


def test_nis2_section_includes_sanction_important_cap() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    assert "7 000 000" in out or "7,000,000" in out or "7000000" in out
    assert "1.4" in out or "1.4 %" in out or "1.4%" in out


def test_nis2_section_cites_art_38_for_sanctions() -> None:
    from pqc_audit.reporters.markdown_reporter import render

    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    assert "art. 38" in out


# ---------------------------------------------------------------------
# Backwards compatibility — the new section must not break the
# existing "no Compliance section when policy_evaluation absent" test.
# ---------------------------------------------------------------------


def test_existing_no_policy_compliance_section_invariant_holds() -> None:
    """Re-assert the contract from test_markdown_reporter_no_compliance_..."""
    from pqc_audit.reporters.markdown_reporter import render

    # No policy_evaluation → the policy "## Compliance" section must
    # NOT appear, even though the NIS2 section may appear.
    out = render(_build_report(vuln_titles=["Quantum-vulnerable algorithm in use"]))
    # No "## Compliance" prefix appears anywhere (the NIS2 heading is
    # "## NIS2 — D.Lgs. 138/2024 art. 24" which does not start with
    # "## Compliance").
    assert "## Compliance" not in out
