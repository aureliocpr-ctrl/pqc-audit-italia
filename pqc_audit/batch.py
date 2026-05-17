"""Batch PQC audit runner — pure helpers.

This module contains the parsing / summarization / rendering logic
for the ``pqc-audit batch`` CLI subcommand. It is deliberately
side-effect free at import time, so unit tests can exercise the
pure helpers without spinning up the typer runner.

Use cases
---------

- Periodic scan of a known portfolio of TLS endpoints (PA, Regioni,
  Ministeri, banche) to track PQC adoption over time.
- Pre-tender deliverable: snapshot of crypto-readiness across a
  customer's full digital perimeter, in one document.
- CI smoke for the auditor against a stable target list.

CSV format (header optional, comma-separated)::

    host[,port][,scope]

If ``port`` is missing, defaults to 443. If ``scope`` is missing,
defaults to the eTLD+1 of ``host`` (best-effort: last two
dot-separated tokens).
"""

from __future__ import annotations

import asyncio
import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pqc_audit import Auditor, ScanTarget

# Magic-value constants — extracted so PLR2004 stays clean and the
# numbers carry semantics, not just bare integers in expressions.
_ETLD_MIN_PARTS = 2  # eTLD+1 fallback needs ≥2 dot-separated tokens.
_CSV_COL_PORT = 1  # CSV column index where ``port`` appears (if present).
_CSV_COL_SCOPE = 2  # CSV column index where ``scope`` appears (if present).
_CSV_COL_TYPE = 3  # CSV column index where ``type`` appears (if present, Sprint 9l).
_HNDL_HIGH_THRESHOLD = 80  # HNDL ≥ this is treated as a "critical" row.

# Sprint 9l — recognized target types beyond the default ``tls``.
# Any prefix not in this set is treated as part of the host name and
# the target falls back to ``tls`` (never raise on user input).
#
# v2 (post-critic): the set must be a STRICT SUBSET of
# :data:`pqc_audit.scanners.base.TargetType` Literal AND every entry
# must have either a default-stack scanner or an explicit one in
# :func:`_build_scanners_for_target_type`. ``pqc-mldsa-sig`` was
# removed because it has no Scanner class yet (it is a standalone
# CLI subcommand that calls :func:`probe_all_mldsa_sigalgs` directly).
# Listing it here would let users pass ``pqc-mldsa-sig://host`` in a
# batch run, which would crash on ``ScanTarget(type='pqc-mldsa-sig')``
# pydantic validation because the Literal does not allow it.
_KNOWN_TARGET_TYPES: frozenset[str] = frozenset(
    {
        "tls",
        "postgres-ssl",
        "mysql-ssl",
        "smtp-starttls",
        "imap-starttls",
        "pqc-hybrid",
    }
)
# Default ports per target type so users can omit the port column.
_DEFAULT_PORT_BY_TYPE: dict[str, int] = {
    "tls": 443,
    "postgres-ssl": 5432,
    "mysql-ssl": 3306,
    "smtp-starttls": 25,
    "imap-starttls": 143,
    "pqc-hybrid": 443,
}


@dataclass(frozen=True)
class Target:
    """One audit endpoint plus the scope label used for reporting.

    Sprint 9l: ``target_type`` (default ``"tls"``) drives the dispatch
    in :func:`run_one` so a single batch can mix TLS, Postgres SSL,
    MySQL SSL, SMTP STARTTLS, and PQC hybrid / ML-DSA probes.
    """

    host: str
    port: int = 443
    scope: str = ""
    target_type: str = "tls"

    def resolved_scope(self) -> str:
        """Return ``scope`` if set, otherwise the eTLD+1 of ``host``."""
        if self.scope:
            return self.scope
        parts = [p for p in self.host.split(".") if p]
        if len(parts) >= _ETLD_MIN_PARTS:
            return ".".join(parts[-_ETLD_MIN_PARTS:])
        return self.host


def parse_inline_targets(raw: str) -> list[Target]:
    """Parse comma-separated targets, optionally with ``type://`` prefix.

    Accepted forms (Sprint 9l):

    * ``host`` — default tls, default port 443
    * ``host:port`` — default tls
    * ``type://host`` — explicit type, default port for that type
    * ``type://host:port`` — fully qualified

    Unknown ``type`` prefixes (anything not in :data:`_KNOWN_TARGET_TYPES`)
    are treated as part of the host name and the target falls back to
    ``tls``. We never raise on user input.
    """
    out: list[Target] = []
    for chunk in (s.strip() for s in raw.split(",")):
        if not chunk:
            continue
        target_type = "tls"
        remainder = chunk
        if "://" in chunk:
            prefix, _, after = chunk.partition("://")
            if prefix.strip().lower() in _KNOWN_TARGET_TYPES:
                target_type = prefix.strip().lower()
                remainder = after
        if ":" in remainder:
            host, _, port_s = remainder.partition(":")
            try:
                port = int(port_s)
            except ValueError:
                port = _DEFAULT_PORT_BY_TYPE.get(target_type, 443)
        else:
            host, port = remainder, _DEFAULT_PORT_BY_TYPE.get(target_type, 443)
        out.append(
            Target(host=host.strip(), port=port, target_type=target_type)
        )
    return out


def parse_csv(path: Path) -> list[Target]:
    """Parse a CSV with rows ``host[,port[,scope]]``.

    ``utf-8-sig`` swallows the BOM Excel writes when saving as
    "CSV UTF-8". Without this, the first cell of the header row
    would arrive as ``"﻿host"`` and the header check below
    wouldn't match.
    """
    out: list[Target] = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            cells = [c.strip() for c in row if c is not None]
            if not cells:
                continue
            if cells[0].lower() in {"host", "hostname", "domain"}:
                continue
            host = cells[0]
            # Sprint 9l: optional 4th column ``type``. Unknown values
            # fall back to ``tls`` silently — never raise on user input.
            raw_type = (
                cells[_CSV_COL_TYPE].lower()
                if len(cells) > _CSV_COL_TYPE and cells[_CSV_COL_TYPE]
                else "tls"
            )
            target_type = raw_type if raw_type in _KNOWN_TARGET_TYPES else "tls"
            default_port = _DEFAULT_PORT_BY_TYPE.get(target_type, 443)
            port = (
                int(cells[_CSV_COL_PORT])
                if len(cells) > _CSV_COL_PORT and cells[_CSV_COL_PORT]
                else default_port
            )
            scope = cells[_CSV_COL_SCOPE] if len(cells) > _CSV_COL_SCOPE else ""
            out.append(
                Target(host=host, port=port, scope=scope, target_type=target_type)
            )
    return out


def _build_scanners_for_target_type(target_type: str) -> list | None:
    """Return the scanner stack appropriate for ``target_type``, or
    ``None`` to let :class:`Auditor` use its default stack.

    The default stack already covers ``tls`` and ``pqc-hybrid`` (see
    :func:`pqc_audit.auditor.Auditor.__init__`). The Sprint 9j / 9k
    scanners are NOT in the default stack — we wire them explicitly
    here so the batch can drive them.
    """
    t = target_type.lower()
    if t == "postgres-ssl":
        from pqc_audit.scanners.postgres_ssl import (  # noqa: PLC0415
            PostgresSSLScanner,
        )
        return [PostgresSSLScanner()]
    if t == "mysql-ssl":
        from pqc_audit.scanners.mysql_ssl import MySQLSSLScanner  # noqa: PLC0415
        return [MySQLSSLScanner()]
    if t == "smtp-starttls":
        from pqc_audit.scanners.smtp_starttls import (  # noqa: PLC0415
            SMTPStartTLSScanner,
        )
        return [SMTPStartTLSScanner()]
    if t == "imap-starttls":
        from pqc_audit.scanners.imap_starttls import (  # noqa: PLC0415
            IMAPStartTLSScanner,
        )
        return [IMAPStartTLSScanner()]
    # tls / pqc-hybrid / pqc-mldsa-sig → fall back to Auditor default.
    return None


async def run_one(
    target: Target,
    *,
    policy: str,
    sensitivity: int,
    enforce: bool,
) -> dict[str, Any]:
    """Scan one TLS endpoint and return a JSON-serialisable dict.

    Errors during the handshake are captured and turned into a
    minimal ``{host, port, error}`` payload so the batch never
    aborts because one host is unreachable.
    """
    # Sprint 9l — dispatch by target_type so a single batch can mix
    # tls / postgres-ssl / mysql-ssl / smtp-starttls / pqc-hybrid /
    # pqc-mldsa-sig endpoints. Backward compatibility: target_type
    # defaults to "tls" so pre-9l CSVs still work.
    scanners = _build_scanners_for_target_type(target.target_type)
    if scanners is None:
        auditor = Auditor(policy=policy, data_sensitivity_years=sensitivity)
    else:
        auditor = Auditor(
            policy=policy,
            data_sensitivity_years=sensitivity,
            scanners=scanners,
        )
    # Defense-in-depth (Sprint 9l v2): if _KNOWN_TARGET_TYPES ever
    # drifts out of sync with the ScanTarget Literal, pydantic raises
    # ValidationError here. Catch it as a per-host error so the batch
    # never aborts, preserving the documented "batch never aborts"
    # contract.
    try:
        scan_target = ScanTarget(
            type=target.target_type, host=target.host, port=target.port
        )
    except Exception as exc:  # noqa: BLE001 — pydantic ValidationError + any future variant
        return {
            "host": target.host,
            "port": target.port,
            "target_type": target.target_type,
            "error": f"unsupported target_type: {type(exc).__name__}: {exc}",
        }
    try:
        report = await auditor.scan([scan_target])
    except Exception as exc:  # noqa: BLE001 — we intentionally swallow per host
        return {
            "host": target.host,
            "port": target.port,
            "error": f"{type(exc).__name__}: {exc}",
        }
    payload: dict[str, Any] = json.loads(report.model_dump_json())
    if enforce:
        evaluation = auditor.evaluate_against_policy(report)
        payload["policy_evaluation"] = json.loads(evaluation.model_dump_json())
    return payload


def summarize_one(host: str, report: dict[str, Any]) -> dict[str, Any]:
    """Distill a single AuditReport (as dict) into one summary row.

    Two failure modes produce ``status="error"``:

    1. Top-level error stub from ``run_one`` (transport refused before
       any TLS handshake — DNS resolve failed, connection refused).
    2. Inner ``scan_results[0].errors`` non-empty AND ``assets``
       empty: the auditor produced a structured report but the scanner
       couldn't extract any cert from the target. We refuse to call
       this "ok" because the policy evaluation that comes back is
       vacuously ``PASS`` (no asset = no violation), which would
       become a *false green* in the executive table.
    """
    if "error" in report:
        return {
            "host": host,
            "status": "error",
            "error": report["error"],
        }
    sr_list = report.get("scan_results") or []
    sr = sr_list[0] if sr_list else {}
    assets = sr.get("assets") or []
    inner_errors = sr.get("errors") or []
    if not assets and inner_errors:
        # Inner-scanner failure → surface as error so the row doesn't
        # carry a misleading ``policy_verdict=PASS`` next to no data.
        return {
            "host": host,
            "status": "error",
            "error": str(inner_errors[0]),
        }
    vulns = sr.get("vulnerabilities") or []
    risk = (report.get("metadata") or {}).get("risk_summary") or {}
    pe = report.get("policy_evaluation") or {}
    algo = (assets[0].get("algorithm") or {}) if assets else {}
    recos = report.get("recommendations") or []
    return {
        "host": host,
        "status": "ok",
        "algorithm": f"{algo.get('name', '?')}-{algo.get('key_size_bits', '?')}",
        "vulns": len(vulns),
        "hndl": risk.get("hndl_max"),
        "qday": risk.get("qday_max"),
        "policy_verdict": pe.get("overall_verdict") or "n/v",
        "violations": len(pe.get("violations") or []),
        "top_reco": (recos[0].get("to_algorithm") if recos else "—"),
    }


def render_markdown(
    rows: list[dict[str, Any]],
    *,
    policy: str,
    sensitivity: int,
    enforce: bool,
) -> str:
    """Italian-language executive summary, one Markdown table."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    n = len(rows)
    ok = sum(1 for r in rows if r["status"] == "ok")
    err = n - ok
    high = sum(
        1 for r in rows if r["status"] == "ok" and (r.get("hndl") or 0) >= _HNDL_HIGH_THRESHOLD
    )
    pqc_present = sum(
        1
        for r in rows
        if r["status"] == "ok"
        and any(
            p in (r.get("algorithm") or "")
            for p in ("ML-DSA", "ML-KEM", "SLH-DSA", "sntrup", "FALCON")
        )
    )

    lines = [
        "# Batch PQC audit — sintesi esecutiva",
        "",
        f"- **Generato:** {now}",
        f"- **Policy applicata:** `{policy}`",
        f"- **Sensitivity (anni):** {sensitivity}",
        f"- **Enforce policy:** {'sì' if enforce else 'no'}",
        f"- **Target totali:** {n} (ok: {ok}, errori: {err})",
        f"- **Target HNDL ≥ 80:** {high} / {ok}",
        f"- **Target con algoritmo PQC negoziato:** {pqc_present} / {ok}",
        "",
        "## Tabella per host",
        "",
        "| Host | Algoritmo | Vulns | HNDL | Q-Day | Verdict policy | Top reco |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for r in rows:
        if r["status"] == "ok":
            verdict_cell = r["policy_verdict"]
            v = r.get("violations") or 0
            if v:
                verdict_cell = f"{verdict_cell} ({v} viol.)"
            lines.append(
                f"| `{r['host']}` | {r['algorithm']} | {r['vulns']} | "
                f"{r.get('hndl', '?')} | {r.get('qday', '?')} | "
                f"{verdict_cell} | {r['top_reco']} |"
            )
        else:
            lines.append(f"| `{r['host']}` | (errore) | — | — | — | — | {r.get('error', '?')} |")
    lines.append("")
    if pqc_present == 0 and ok > 0:
        lines.append(
            "> **Nota:** nessuno dei target valutati ha negoziato un algoritmo "
            "NIST PQC (ML-KEM / ML-DSA / SLH-DSA) né un hybrid sntrup. La "
            "raccomandazione di migrazione è **uniformemente P5** — coerente "
            "con il quadro globale tipicamente rilevato in PA italiana."
        )
    return "\n".join(lines) + "\n"


async def run_batch(
    targets: Iterable[Target],
    *,
    policy: str,
    sensitivity: int,
    enforce: bool,
    concurrency: int = 1,
) -> list[tuple[Target, dict[str, Any]]]:
    """Scan every target and pair each with its report dict.

    With ``concurrency=1`` (default) the targets are scanned in
    strict sequence — same behaviour as before this option was
    introduced. With ``concurrency=N>1`` up to ``N`` scans run
    in parallel via ``asyncio.gather`` bounded by an
    ``asyncio.Semaphore(N)``. The pairing ``(target, report)``
    is preserved in both modes.
    """
    # Materialise the iterable once so we can both run the scans
    # and emit deterministic ordering on the output.
    target_list = list(targets)

    if concurrency <= 1:
        out: list[tuple[Target, dict[str, Any]]] = []
        for tgt in target_list:
            report = await run_one(
                tgt,
                policy=policy,
                sensitivity=sensitivity,
                enforce=enforce,
            )
            out.append((tgt, report))
        return out

    sem = asyncio.Semaphore(concurrency)

    async def _bounded(tgt: Target) -> tuple[Target, dict[str, Any]]:
        async with sem:
            report = await run_one(
                tgt,
                policy=policy,
                sensitivity=sensitivity,
                enforce=enforce,
            )
            return tgt, report

    return await asyncio.gather(*(_bounded(t) for t in target_list))


__all__ = [
    "Target",
    "parse_inline_targets",
    "parse_csv",
    "run_one",
    "summarize_one",
    "render_markdown",
    "run_batch",
]
