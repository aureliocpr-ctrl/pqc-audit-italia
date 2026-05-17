"""Italian NIS2 transposition mapping — D.Lgs. 138/2024, articolo 24.

Maps :class:`pqc_audit.core.models.Vulnerability` findings to the
specific lettered measure of NIS2 art. 21(2) / D.Lgs. 138/2024 art.
24(2) they implicate. A PwC-grade audit report can then cite chapter
and verse, with the EU directive AND the Italian implementing decree
side by side.

The mapping is title-pattern-based (substring match, case-insensitive)
because :class:`Vulnerability` titles are stable strings produced by
the scanners — they evolve in lockstep with this file. If a scanner
introduces a new finding title, the mapping returns ``[]`` until this
file is updated. We surface ``[]`` explicitly rather than guessing —
silently inventing a regulation citation would be fuffa.

Authoritative sources:

* Directive (EU) 2022/2555 (NIS 2), art. 21(2) lett. (a)-(j) —
  https://eur-lex.europa.eu/eli/dir/2022/2555/oj
* Decreto Legislativo 4 settembre 2024, n. 138 (G.U. 2024-10-01),
  art. 24(2) lett. (a)-(j) —
  https://www.gazzettaufficiale.it/eli/id/2024/10/01/24G00155/SG
* ACN — autorità competente NIS in Italia (art. 4 D.Lgs. 138/2024) —
  https://www.acn.gov.it/portale/en/nis/la-normativa
* Implementing Regulation (EU) 2024/2690 — significant incident
  criteria for specific provider categories.

Sanction frame — art. 38 D.Lgs. 138/2024:

* Soggetti essenziali: fino a 10 000 000 EUR o 2 % del fatturato
  mondiale annuo, applicato il maggiore.
* Soggetti importanti: fino a 7 000 000 EUR o 1.4 % del fatturato.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from pqc_audit.core.models import AuditReport, Vulnerability

# ---------------------------------------------------------------------
# Sanction reference (art. 38 D.Lgs. 138/2024).
# Reporters cite these constants instead of hard-coding magic numbers.
# ---------------------------------------------------------------------

SANCTION_ESSENTIAL_FINE_CAP_EUR: int = 10_000_000
SANCTION_ESSENTIAL_TURNOVER_PCT: float = 2.0
SANCTION_IMPORTANT_FINE_CAP_EUR: int = 7_000_000
SANCTION_IMPORTANT_TURNOVER_PCT: float = 1.4


# ---------------------------------------------------------------------
# NIS2 article enum + per-letter legal reference.
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class _ArticleSpec:
    legal_reference: str
    eu_directive_reference: str
    topic: str


class NIS2Article(Enum):
    """The ten lettered measures of D.Lgs. 138/2024 art. 24(2)."""

    ART_24_2_A = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (a)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(a)",
        topic="Analisi del rischio e politiche di sicurezza dei sistemi informativi",
    )
    ART_24_2_B = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (b)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(b)",
        topic="Gestione degli incidenti",
    )
    ART_24_2_C = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (c)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(c)",
        topic="Continuità operativa, backup e disaster recovery",
    )
    ART_24_2_D = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (d)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(d)",
        topic="Sicurezza della catena di approvvigionamento (supply chain)",
    )
    ART_24_2_E = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (e)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(e)",
        topic="Sicurezza acquisizione/sviluppo/manutenzione SI, vulnerability handling",
    )
    ART_24_2_F = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (f)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(f)",
        topic="Strategie e procedure per valutare l'efficacia delle misure",
    )
    ART_24_2_G = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (g)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(g)",
        topic="Pratiche di igiene informatica di base, formazione cybersecurity",
    )
    ART_24_2_H = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (h)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(h)",
        topic="Politiche e procedure relative all'uso della crittografia e cifratura",
    )
    ART_24_2_I = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (i)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(i)",
        topic="Sicurezza HR, controllo accessi e gestione asset",
    )
    ART_24_2_J = _ArticleSpec(
        legal_reference="D.Lgs. 138/2024, art. 24, comma 2, lett. (j)",
        eu_directive_reference="Direttiva (UE) 2022/2555 art. 21(2)(j)",
        topic="MFA, comunicazioni sicure e di emergenza",
    )

    @property
    def legal_reference(self) -> str:
        return self.value.legal_reference

    @property
    def eu_directive_reference(self) -> str:
        return self.value.eu_directive_reference

    @property
    def topic(self) -> str:
        return self.value.topic


# ---------------------------------------------------------------------
# Title-pattern → list[NIS2Article] mapping.
# Each pattern is a case-insensitive substring of the Vulnerability
# title produced by a scanner. Multiple articles may apply.
# ---------------------------------------------------------------------

_TITLE_PATTERNS: tuple[tuple[re.Pattern[str], tuple[NIS2Article, ...]], ...] = (
    # Quantum-vulnerable / weakened primitives
    (
        re.compile(r"quantum-?vulnerable", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    (
        re.compile(r"quantum-?weakened", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    (
        re.compile(r"pqc hybrid", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    (
        re.compile(r"no pqc hybrid", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    # Key-size sanity
    (
        re.compile(r"(?:rsa|dsa|ec|elliptic)\s*key\s*undersize", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    # Signature hash sanity
    (
        re.compile(r"deprecated hash algorithm", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    # Certificate validity / lifecycle
    (
        re.compile(r"certificate expired", re.IGNORECASE),
        (NIS2Article.ART_24_2_H, NIS2Article.ART_24_2_E),
    ),
    (
        re.compile(r"certificate not yet valid", re.IGNORECASE),
        (NIS2Article.ART_24_2_E,),
    ),
    # Chain hygiene
    (
        re.compile(r"self-signed leaf certificate", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    (
        re.compile(r"incomplete tls chain", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    # Revocation
    (
        re.compile(r"no revocation mechanism", re.IGNORECASE),
        (NIS2Article.ART_24_2_H, NIS2Article.ART_24_2_E),
    ),
    (
        re.compile(r"ocsp must-staple", re.IGNORECASE),
        (NIS2Article.ART_24_2_H,),
    ),
    # Sprint 9j.3 — database cleartext (CWE-319). Both (h) crittografia
    # and (j) comunicazioni sicure apply because a plaintext DB
    # connection violates encryption-in-transit AND the broader
    # "secure communications" obligation.
    (
        re.compile(r"postgres(?:ql)?\s+allows\s+non-?ssl", re.IGNORECASE),
        (NIS2Article.ART_24_2_H, NIS2Article.ART_24_2_J),
    ),
    (
        re.compile(r"mysql\s+allows\s+non-?ssl", re.IGNORECASE),
        (NIS2Article.ART_24_2_H, NIS2Article.ART_24_2_J),
    ),
    # Sprint 9k — SMTP STARTTLS missing (RFC 3207). Same dual-citation
    # as DB cleartext: (h) crittografia + (j) comunicazioni sicure.
    (
        re.compile(r"smtp.*(?:starttls|not advertise)", re.IGNORECASE),
        (NIS2Article.ART_24_2_H, NIS2Article.ART_24_2_J),
    ),
)


def map_finding_to_nis2(vulnerability: Vulnerability) -> list[NIS2Article]:
    """Return the list of NIS2 articles a vulnerability implicates.

    Empty list if no pattern matches — callers MUST surface ``[]`` to
    the user instead of forcing a default article. Inventing a citation
    would be exactly the kind of "fuffa" the project bans.
    """
    matched: list[NIS2Article] = []
    seen: set[NIS2Article] = set()
    for pattern, articles in _TITLE_PATTERNS:
        if pattern.search(vulnerability.title):
            for art in articles:
                if art not in seen:
                    matched.append(art)
                    seen.add(art)
    return matched


def apply_nis2_mapping(report: AuditReport) -> dict[str, list[NIS2Article]]:
    """Walk every vulnerability in ``report`` and produce a mapping
    ``title -> list[NIS2Article]``.

    Titles are used as keys because :class:`Vulnerability` is a frozen
    pydantic model and cannot be mutated in place. The mapping dict is
    suitable for embedding under ``report.metadata.nis2_mapping`` or
    rendering as a Markdown table.

    Unmapped findings appear with ``[]`` so the reporter can highlight
    "needs review" rows instead of silently dropping them.
    """
    out: dict[str, list[NIS2Article]] = {}
    for sr in report.scan_results:
        for v in sr.vulnerabilities:
            out.setdefault(v.title, map_finding_to_nis2(v))
    return out


def summarize_articles(articles: list[NIS2Article]) -> list[NIS2Article]:
    """Return the distinct articles in the input list, preserving order.

    Useful for the executive summary: "this audit hit articles X, Y, Z
    of D.Lgs. 138/2024 art. 24(2)".
    """
    seen: set[NIS2Article] = set()
    distinct: list[NIS2Article] = []
    for art in articles:
        if art not in seen:
            distinct.append(art)
            seen.add(art)
    return distinct
