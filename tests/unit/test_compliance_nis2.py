"""Tests for NIS2 / D.Lgs. 138/2024 compliance mapping (Sprint 9h).

Each `Vulnerability` produced by the scanners must be mapped to one or
more articles of the Italian transposition of NIS2 (Decreto Legislativo
4 settembre 2024, n. 138, art. 23/24/25) so a PwC-grade audit report
can cite chapter-and-verse why every finding matters legally — not just
technically.

Authoritative sources used to build the mapping:

* Directive (EU) 2022/2555 (NIS 2), Article 21(2), letters (a)-(j)
* D.Lgs. 138/2024 (G.U. 2024-10-01), articolo 24, comma 2,
  lettere (a)-(j)  — Italian transposition, same letter ordering
* Implementing Regulation (EU) 2024/2690 — significant incident
  criteria
* ACN normativa pages (https://www.acn.gov.it/portale/en/nis/la-normativa)

Sanction frame: art. 38 D.Lgs. 138/2024 — administrative fines up to
EUR 10,000,000 or 2% of global annual turnover for soggetti essenziali,
EUR 7,000,000 or 1.4% for soggetti importanti.

The mapping is intentionally surface-level (one-finding → one-or-more
articles); it does NOT replace a regulatory gap analysis, only feeds
its input.
"""

from __future__ import annotations

# -------------------- NIS2Article enum + reference --------------------


def test_nis2_article_enum_has_ten_letters() -> None:
    """Art. 24(2) D.Lgs. 138/2024 lists ten letters (a..j) of measures."""
    from pqc_audit.compliance.nis2 import NIS2Article

    expected = {
        "ART_24_2_A",  # risk analysis + InfoSec policies
        "ART_24_2_B",  # incident management
        "ART_24_2_C",  # business continuity / DR
        "ART_24_2_D",  # supply chain security
        "ART_24_2_E",  # vulnerability handling / SDLC
        "ART_24_2_F",  # cyber hygiene + training
        "ART_24_2_G",  # HR security, access control, asset mgmt
        "ART_24_2_H",  # cryptography + encryption policies
        "ART_24_2_I",  # access control / asset management
        "ART_24_2_J",  # MFA + secure communications
    }
    actual = {m.name for m in NIS2Article}
    # The mapping module MUST cover all 10 lettered measures, even if
    # no current finding maps to some of them — we want every audit
    # report to be able to point at the right article on day 1.
    assert expected.issubset(actual), f"missing letters: {expected - actual}"


def test_nis2_article_carries_legal_reference() -> None:
    """Each enum member must expose the Italian legal anchor."""
    from pqc_audit.compliance.nis2 import NIS2Article

    h = NIS2Article.ART_24_2_H
    # Italian source-of-truth string
    assert "138/2024" in h.legal_reference
    assert "art. 24" in h.legal_reference
    assert "lett. h" in h.legal_reference or "(h)" in h.legal_reference
    # EU mirror
    assert "21" in h.eu_directive_reference  # NIS 2 Directive art. 21(2)(h)
    # Short topical name
    assert any(kw in h.topic.lower() for kw in ("crittografia", "encryption", "crypto"))


# -------------------- map_finding_to_nis2 --------------------


def test_map_quantum_vulnerable_to_crypto_article() -> None:
    """RSA/ECDSA quantum-vulnerable findings → art. 24(2)(h)."""
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="Quantum-vulnerable algorithm in use (ECDSA-256)",
        description="...",
        severity=RiskLevel.HIGH,
        cwe="CWE-327",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles


def test_map_deprecated_hash_to_crypto_article() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="Deprecated hash algorithm in signature (SHA-1)",
        description="...",
        severity=RiskLevel.HIGH,
        cwe="CWE-328",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles


def test_map_expired_cert_to_crypto_and_vuln_handling() -> None:
    """Expired cert is both a crypto-policy lapse AND a SDLC/vuln-handling
    failure (someone forgot to rotate)."""
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="Certificate expired (12 days ago)",
        description="...",
        severity=RiskLevel.HIGH,
        cwe="CWE-298",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles
    assert NIS2Article.ART_24_2_E in articles


def test_map_undersized_key_to_crypto_article() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="RSA key undersized (1024 bits, < 2048)",
        description="...",
        severity=RiskLevel.HIGH,
        cwe="CWE-326",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles


def test_map_no_revocation_mechanism_to_crypto_and_vuln() -> None:
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="No revocation mechanism advertised by certificate",
        description="...",
        severity=RiskLevel.LOW,
        cwe="CWE-295",
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles
    assert NIS2Article.ART_24_2_E in articles


def test_map_must_staple_positive_finding_to_crypto_article() -> None:
    """Positive INFO finding still maps to the crypto article — useful
    for compliance reports to count POSITIVE evidence under art. 24(2)(h)."""
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="OCSP Must-Staple asserted (RFC 7633)",
        description="...",
        severity=RiskLevel.INFO,
        cwe=None,
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles


def test_map_pqc_hybrid_active_to_crypto_article() -> None:
    """`PQC hybrid migration active` is positive evidence of crypto policy
    maturity (preparing for NIST 2030)."""
    from pqc_audit.compliance.nis2 import NIS2Article, map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="PQC hybrid migration active (X25519MLKEM768)",
        description="...",
        severity=RiskLevel.INFO,
        cwe=None,
    )
    articles = map_finding_to_nis2(v)
    assert NIS2Article.ART_24_2_H in articles


def test_map_unknown_finding_returns_empty_list() -> None:
    """Unmapped finding titles must not silently force an article — that
    would be fuffa. Return [] so reporters can highlight 'unmapped'."""
    from pqc_audit.compliance.nis2 import map_finding_to_nis2
    from pqc_audit.core.models import RiskLevel, Vulnerability

    v = Vulnerability(
        title="Something completely unrelated like 'wifi password weak'",
        description="...",
        severity=RiskLevel.LOW,
        cwe="CWE-521",
    )
    articles = map_finding_to_nis2(v)
    assert articles == []


# -------------------- apply_nis2_mapping (report-level) --------------------


def test_apply_nis2_mapping_enriches_every_vulnerability(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Walk a full AuditReport, attach `nis2_articles` to each
    vulnerability via a new top-level metadata dict (we cannot mutate
    frozen pydantic models in place, so the function returns an
    augmented dict keyed by vuln-title).
    """
    from datetime import UTC, datetime

    from pqc_audit.compliance.nis2 import (
        NIS2Article,
        apply_nis2_mapping,
    )
    from pqc_audit.core.models import (
        AuditReport,
        RiskLevel,
        ScanResult,
        Vulnerability,
    )

    v_quantum = Vulnerability(
        title="Quantum-vulnerable algorithm in use (ECDSA-256)",
        description="...",
        severity=RiskLevel.HIGH,
        cwe="CWE-327",
    )
    v_unmapped = Vulnerability(
        title="Some unrelated wifi issue",
        description="...",
        severity=RiskLevel.LOW,
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[],
        vulnerabilities=[v_quantum, v_unmapped],
        started_at=datetime(2026, 5, 17, tzinfo=UTC),
        finished_at=datetime(2026, 5, 17, tzinfo=UTC),
    )
    report = AuditReport(
        report_id="test",
        scan_results=[sr],
        generated_at=datetime(2026, 5, 17, tzinfo=UTC),
    )

    enriched = apply_nis2_mapping(report)
    # Every vulnerability has an entry (even unmapped, which has [])
    assert v_quantum.title in enriched
    assert v_unmapped.title in enriched
    assert NIS2Article.ART_24_2_H in enriched[v_quantum.title]
    assert enriched[v_unmapped.title] == []


def test_summarize_articles_aggregates_distinct_articles() -> None:
    """The summary helper must return distinct NIS2Article values."""
    from pqc_audit.compliance.nis2 import (
        NIS2Article,
        map_finding_to_nis2,
        summarize_articles,
    )
    from pqc_audit.core.models import RiskLevel, Vulnerability

    vs = [
        Vulnerability(
            title="Quantum-vulnerable algorithm in use (ECDSA-256)",
            description="...",
            severity=RiskLevel.HIGH,
            cwe="CWE-327",
        ),
        Vulnerability(
            title="Certificate expired (12 days ago)",
            description="...",
            severity=RiskLevel.HIGH,
            cwe="CWE-298",
        ),
    ]
    all_articles = [a for v in vs for a in map_finding_to_nis2(v)]
    summary = summarize_articles(all_articles)
    assert NIS2Article.ART_24_2_H in summary
    assert NIS2Article.ART_24_2_E in summary
    # Distinct (set semantics): no duplicates
    assert len(summary) == len(set(summary))


# -------------------- sanction reference --------------------


def test_essential_subject_sanction_reference_is_exposed() -> None:
    """Art. 38 D.Lgs. 138/2024 — fines up to €10M / 2% turnover for
    soggetti essenziali. We expose this as a typed constant so the
    Markdown reporter can cite the figure without hard-coding."""
    from pqc_audit.compliance.nis2 import (
        SANCTION_ESSENTIAL_FINE_CAP_EUR,
        SANCTION_ESSENTIAL_TURNOVER_PCT,
        SANCTION_IMPORTANT_FINE_CAP_EUR,
        SANCTION_IMPORTANT_TURNOVER_PCT,
    )

    assert SANCTION_ESSENTIAL_FINE_CAP_EUR == 10_000_000
    assert SANCTION_ESSENTIAL_TURNOVER_PCT == 2.0
    assert SANCTION_IMPORTANT_FINE_CAP_EUR == 7_000_000
    assert SANCTION_IMPORTANT_TURNOVER_PCT == 1.4
