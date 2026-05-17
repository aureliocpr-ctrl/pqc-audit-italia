"""Markdown reporter — executive summary for non-technical readers (IT manager / DPO).

Pure function ``render(report) -> str``. No side effects, no I/O.
The output is plain Markdown (CommonMark + GFM tables) and is meant
to be either piped to a viewer, embedded in a ticket, or transformed
into PDF by :mod:`pqc_audit.reporters.pdf_reporter`.

Tone: factual, Italian-language section headers, English vulnerability
descriptions (because they come from the underlying scanners). Useful
in a NIS2/DORA bundle as the "report esecutivo" annex.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from pqc_audit import __version__
from pqc_audit.compliance.nis2 import (
    SANCTION_ESSENTIAL_FINE_CAP_EUR,
    SANCTION_ESSENTIAL_TURNOVER_PCT,
    SANCTION_IMPORTANT_FINE_CAP_EUR,
    SANCTION_IMPORTANT_TURNOVER_PCT,
    NIS2Article,
    apply_nis2_mapping,
    summarize_articles,
)
from pqc_audit.core.models import AuditReport, CryptoAsset, RiskLevel, Vulnerability

_DISCLAIMER = (
    "_Report generato automaticamente da_ **pqc-audit-italia** _v"
    + __version__
    + "_ — _GitHub: https://github.com/aureliocpr-ctrl/pqc-audit-italia_."
)


def _all_assets(report: AuditReport) -> list[CryptoAsset]:
    out: list[CryptoAsset] = []
    for sr in report.scan_results:
        out.extend(sr.assets)
    return out


def _all_vulnerabilities(report: AuditReport) -> list[Vulnerability]:
    out: list[Vulnerability] = []
    for sr in report.scan_results:
        out.extend(sr.vulnerabilities)
    return out


def _severity_for_asset(report: AuditReport, asset_id: str) -> RiskLevel:
    """Highest severity among vulnerabilities that name this asset, or INFO."""
    sev = RiskLevel.INFO
    for v in _all_vulnerabilities(report):
        if asset_id in v.affected_asset_ids:
            sev = max(sev, v.severity)
    return sev


def _section(title: str) -> str:
    return f"\n## {title}\n\n"


def _render_header(report: AuditReport) -> str:
    targets = ", ".join(sr.target for sr in report.scan_results) or "—"
    return (
        f"# pqc-audit-italia — report esecutivo\n\n"
        f"- **Tool:** pqc-audit-italia v{__version__}\n"
        f"- **Report ID:** `{report.report_id}`\n"
        f"- **Policy:** `{report.policy_name}`\n"
        f"- **Generato:** {report.generated_at.isoformat()}\n"
        f"- **Target analizzati:** {targets}\n"
    )


def _render_summary(report: AuditReport) -> str:
    risk_md: list[str] = []
    risk_meta = report.metadata.get("risk_summary")
    if isinstance(risk_meta, dict):
        hndl = risk_meta.get("hndl_max")
        qday = risk_meta.get("qday_max")
        if hndl is not None:
            risk_md.append(f"- **Esposizione HNDL (max):** {hndl}/100")
        if qday is not None:
            risk_md.append(f"- **Esposizione Q-Day (max):** {qday}/100")
    body = (
        f"- **Asset crittografici:** {report.total_assets}\n"
        f"- **Vulnerabilità totali:** {report.total_vulnerabilities}\n"
        f"- **Severità massima:** {report.highest_severity.name}\n"
    )
    if risk_md:
        body += "\n".join(risk_md) + "\n"
    return _section("Sintesi esecutiva") + body


def _render_assets(report: AuditReport) -> str:
    assets = _all_assets(report)
    if not assets:
        return _section("Asset analizzati") + "_Nessun asset crittografico individuato._\n"
    rows = [
        "| Identifier | Algoritmo | Key size | Severity |",
        "| --- | --- | --- | --- |",
    ]
    for a in assets:
        keysize = str(a.algorithm.key_size_bits) if a.algorithm.key_size_bits else "—"
        sev = _severity_for_asset(report, a.asset_id).name
        rows.append(f"| `{a.asset_id}` | {a.algorithm.canonical_name} | {keysize} | {sev} |")
    return _section("Asset analizzati") + "\n".join(rows) + "\n"


def _render_vulnerabilities(report: AuditReport) -> str:
    vulns = _all_vulnerabilities(report)
    if not vulns:
        return _section("Vulnerabilità") + "_Nessuna vulnerabilità individuata._\n"
    by_sev: dict[RiskLevel, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        by_sev[v.severity].append(v)
    parts: list[str] = []
    # CRITICAL -> INFO order (highest first)
    for sev in sorted(by_sev.keys(), reverse=True):
        parts.append(f"### {sev.name}\n")
        for v in by_sev[sev]:
            cwe = f" ({v.cwe})" if v.cwe else ""
            assets_str = (
                ", ".join(f"`{a}`" for a in v.affected_asset_ids) if v.affected_asset_ids else "—"
            )
            parts.append(f"- **{v.title}**{cwe}\n  - {v.description}\n  - Asset: {assets_str}")
            if v.references:
                refs = ", ".join(v.references)
                parts.append(f"  - Riferimenti: {refs}")
        parts.append("")
    return _section("Vulnerabilità") + "\n".join(parts)


def _render_recommendations(report: AuditReport) -> str:
    if not report.recommendations:
        return (
            _section("Raccomandazioni migrazione PQC")
            + "_Nessuna raccomandazione di migrazione necessaria._\n"
        )
    rows: list[str] = []
    for rec in sorted(report.recommendations, key=lambda r: -r.priority):
        line = f"- **P{rec.priority}**: `{rec.from_algorithm}` → `{rec.to_algorithm}`"
        rows.append(line)
        if rec.hybrid_intermediate:
            rows.append(f"  - Hybrid intermediate: `{rec.hybrid_intermediate}`")
        rows.append(f"  - Razionale: {rec.rationale}")
        if rec.references:
            refs = ", ".join(rec.references)
            rows.append(f"  - Riferimenti: {refs}")
    return _section("Raccomandazioni migrazione PQC") + "\n".join(rows) + "\n"


def _render_compliance(report: AuditReport) -> str:
    pe: Any = report.metadata.get("policy_evaluation")
    if not isinstance(pe, dict):
        return ""
    verdict = pe.get("overall_verdict", "UNKNOWN")
    name = pe.get("policy_name", report.policy_name)
    total = pe.get("total_assets_evaluated", 0)
    compliant = pe.get("compliant_assets", 0)
    non_compliant = pe.get("non_compliant_assets", 0)
    body = (
        f"- **Policy:** `{name}`\n"
        f"- **Verdetto:** **{verdict}**\n"
        f"- **Asset valutati:** {total}\n"
        f"- **Compliant:** {compliant}\n"
        f"- **Non-compliant:** {non_compliant}\n"
    )
    violations = pe.get("violations") or []
    if violations:
        body += "\n#### Violazioni\n\n"
        body += "| Asset | Regola | Atteso | Attuale | Severità |\n"
        body += "| --- | --- | --- | --- | --- |\n"
        for v in violations:
            body += (
                f"| `{v.get('asset_identifier', '—')}` "
                f"| {v.get('rule', '—')} "
                f"| {v.get('expected', '—')} "
                f"| {v.get('actual', '—')} "
                f"| {v.get('severity', '—')} |\n"
            )
    return _section("Compliance") + body


_PEDIGREE_IT_LABEL: dict[str, str] = {
    "qualified_it_tsp": "AgID-accreditata (TSP qualificato italiano)",
    "commercial_global": "CA commerciale globale",
    "unknown": "Sconosciuta — richiede verifica manuale",
}

_SOURCE_IT_LABEL: dict[str, str] = {
    "on_wire": "presente sulla wire (server-shipped root)",
    "trust_store": "risolta dal trust store locale",
    "unknown": "non risolto",
}


def _collect_leaves_with_trust_anchor(report: AuditReport) -> list[CryptoAsset]:
    """Return all leaf-position assets that carry a ``trust_anchor`` key."""
    out: list[CryptoAsset] = []
    for sr in report.scan_results:
        for a in sr.assets:
            md = a.metadata or {}
            if md.get("chain_position") != "leaf":
                continue
            if "trust_anchor" not in md:
                continue
            out.append(a)
    return out


def _render_trust_anchor(report: AuditReport) -> str:
    """Render the "Trust anchor — CA radice" section.

    The section answers the eIDAS-relevant question every Italian PA
    audit needs: who is the trust anchor, and is it an AgID-accredited
    qualified TSP? The pedigree label is Italian and audit-friendly.

    Skipped entirely when no leaf asset carries the ``trust_anchor``
    metadata. Unresolved anchors are surfaced with "non risolto"
    instead of silently dropped — same anti-fuffa stance as the
    NIS2 mapping in Sprint 9h-integration.
    """
    leaves = _collect_leaves_with_trust_anchor(report)
    if not leaves:
        return ""

    lines: list[str] = [_section("Trust anchor — CA radice")]
    lines.append(
        "| Target | Stato | Fonte | Root subject | Pedigree | "
        "Algoritmo | Key size | Hash | Trust store source |\n"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")

    for asset in leaves:
        md = asset.metadata or {}
        ta: dict = md.get("trust_anchor") or {}
        resolved = bool(ta.get("resolved"))
        source_key = str(ta.get("source") or "unknown")
        source_label = _SOURCE_IT_LABEL.get(source_key, source_key)
        root_subj = ta.get("root_subject") or "—"
        pedigree_key = str(ta.get("pedigree") or "unknown")
        pedigree_label = _PEDIGREE_IT_LABEL.get(pedigree_key, pedigree_key)
        algo = ta.get("root_algorithm") or "—"
        ksize = ta.get("root_key_size")
        ksize_text = str(ksize) if ksize else "—"
        sig_hash = ta.get("root_signature_hash") or "—"
        ts_source = md.get("trust_store_source") or "—"
        status = "risolto" if resolved else "non risolto"
        lines.append(
            f"| `{asset.asset_id}` | {status} | {source_label} | "
            f"`{root_subj}` | {pedigree_label} | {algo} | {ksize_text} | "
            f"{sig_hash} | `{ts_source}` |\n"
        )

    lines.append(
        "\n_La pedigree `AgID-accreditata` indica che la CA radice "
        "appartiene a un TSP qualificato italiano nel TSL pubblicato "
        "da AgID (eIDAS art. 25). `CA commerciale globale` indica una "
        "CA non italiana ma riconosciuta internazionalmente. "
        "`Sconosciuta` richiede verifica manuale: la pedigree list "
        "implementata è un sottoinsieme hand-curated, non un "
        "catalogo completo._\n"
    )
    return "".join(lines)


def _render_nis2_compliance(report: AuditReport) -> str:
    """Render NIS2 / D.Lgs. 138/2024 art. 24 mapping inline in the report.

    Skipped entirely if the audit has zero vulnerabilities — there is
    nothing to cite. Unmapped findings (no pattern match in
    :data:`pqc_audit.compliance.nis2._TITLE_PATTERNS`) are surfaced as
    "da revisionare manualmente" rather than silently dropped, per the
    project's anti-fuffa stance: inventing a regulation citation would
    be worse than admitting the gap.

    The section heading is "## NIS2 — D.Lgs. 138/2024 art. 24" (NOT
    "## Compliance NIS2") to avoid colliding with the policy-engine
    "## Compliance" section. Both can coexist in the same report.
    """
    if report.total_vulnerabilities == 0:
        return ""
    mapping = apply_nis2_mapping(report)
    if not mapping:
        return ""

    lines: list[str] = [_section("NIS2 — D.Lgs. 138/2024 art. 24")]
    lines.append("| Vulnerability | Articolo D.Lgs. 138/2024 | Direttiva UE | Topic |\n")
    lines.append("| --- | --- | --- | --- |\n")

    all_articles: list[NIS2Article] = []
    for title, articles in mapping.items():
        if not articles:
            lines.append(
                f"| `{title}` | — | — | _da revisionare manualmente_ |\n"
            )
            continue
        legal_refs = "; ".join(a.legal_reference for a in articles)
        eu_refs = "; ".join(a.eu_directive_reference for a in articles)
        topics = "; ".join(a.topic for a in articles)
        lines.append(f"| `{title}` | {legal_refs} | {eu_refs} | {topics} |\n")
        all_articles.extend(articles)

    distinct = summarize_articles(all_articles)
    if distinct:
        lines.append("\n### Articoli implicati\n\n")
        for art in distinct:
            lines.append(
                f"- **{art.legal_reference}** — {art.topic} "
                f"({art.eu_directive_reference})\n"
            )

    lines.append("\n### Quadro sanzionatorio art. 38 D.Lgs. 138/2024\n\n")
    lines.append(
        f"- Soggetti essenziali: fino a EUR {SANCTION_ESSENTIAL_FINE_CAP_EUR:,} "
        f"o {SANCTION_ESSENTIAL_TURNOVER_PCT}% del fatturato mondiale annuo "
        "(applicato il maggiore).\n"
    )
    lines.append(
        f"- Soggetti importanti: fino a EUR {SANCTION_IMPORTANT_FINE_CAP_EUR:,} "
        f"o {SANCTION_IMPORTANT_TURNOVER_PCT}% del fatturato mondiale annuo "
        "(applicato il maggiore).\n"
    )
    return "".join(lines)


def _render_footer() -> str:
    return (
        "\n---\n\n"
        + _DISCLAIMER
        + "\n\n"
        + "_Disclaimer: il report riflette l'evidenza al momento dello scan; le decisioni "
        "operative restano in capo al titolare del trattamento / RFC del sistema._\n"
    )


def render(report: AuditReport) -> str:
    """Serialize an :class:`AuditReport` to an executive Markdown string.

    The output is intentionally compact and is suitable for inclusion in
    NIS2 / DORA documentation bundles. Use :mod:`pqc_audit.reporters.json_reporter`
    when you need machine-readable output, and :mod:`pqc_audit.reporters.pdf_reporter`
    to convert this Markdown to PDF.
    """
    parts: list[str] = [
        _render_header(report),
        _render_summary(report),
        _render_assets(report),
        _render_trust_anchor(report),
        _render_vulnerabilities(report),
        _render_recommendations(report),
        _render_compliance(report),
        _render_nis2_compliance(report),
        _render_footer(),
    ]
    return "".join(parts)
