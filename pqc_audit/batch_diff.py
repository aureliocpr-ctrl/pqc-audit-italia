"""Compare two ``pqc-audit batch`` snapshots over time.

Use case: re-run the same batch every month, save the resulting
``batch_report.json`` as a build artefact, and run this module to
surface PQC adoption trends across a portfolio. The output is one
short Markdown table — what improved, what regressed, what stayed
the same — that drops cleanly into a status report or executive
deck.

The module is intentionally pure (no I/O, no globals, no template
engine). The CLI / reporter wiring lives elsewhere.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# Algorithms the auditor recognises as "PQC-negotiated" for the
# purpose of trend tracking. Same list the markdown reporter uses
# for its "uniformemente P5" advisory.
_PQC_MARKERS = ("ML-DSA", "ML-KEM", "SLH-DSA", "sntrup", "FALCON")


def _algorithm_string(report: dict[str, Any]) -> str:
    """Distill a single AuditReport-shaped dict into ``NAME-BITS``.

    Returns ``""`` if the report is an error stub or has no asset.
    """
    if "error" in report and "scan_results" not in report:
        return ""
    sr_list = report.get("scan_results") or []
    if not sr_list:
        return ""
    assets = sr_list[0].get("assets") or []
    if not assets:
        return ""
    algo = assets[0].get("algorithm") or {}
    name = str(algo.get("name") or "?")
    bits = algo.get("key_size_bits")
    if bits:
        return f"{name}-{bits}"
    return name


def _verdict(report: dict[str, Any]) -> str:
    """Return the policy verdict, ``"ERROR"`` if the report is a
    transport stub, or ``"n/v"`` if the auditor wasn't run with
    ``--enforce`` for this entry."""
    if "error" in report and "scan_results" not in report:
        return "ERROR"
    pe = report.get("policy_evaluation") or {}
    return str(pe.get("overall_verdict") or "n/v").upper()


def _has_pqc(algorithm: str) -> bool:
    return any(p in (algorithm or "") for p in _PQC_MARKERS)


def _host_of(report: dict[str, Any]) -> str:
    """Best-effort host extraction from the report dict."""
    # Error stub: ``host`` is at the top level (set by batch.run_one).
    if "host" in report:
        return str(report["host"])
    # Real audit report: pull from metadata or the first scan target.
    meta = report.get("metadata") or {}
    if "target_host" in meta:
        return str(meta["target_host"])
    sr_list = report.get("scan_results") or []
    if sr_list:
        target = sr_list[0].get("target", "")
        if isinstance(target, str):
            return target.split(":")[0]
    return ""


def _index_by_host(reports: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in reports:
        host = _host_of(r)
        if host:
            out[host] = r
    return out


def compare_batches(
    prev: list[dict[str, Any]],
    curr: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Classify every host into improved / regressed / unchanged /
    added / removed.

    Parameters
    ----------
    prev:
        Previous ``batch_report.json`` payload (list of audit dicts).
    curr:
        Current ``batch_report.json`` payload.

    Returns
    -------
    dict
        Five-key dict, each key mapping to a sorted list of hostnames.
        Hosts present on both sides land in exactly one of the first
        three buckets; hosts present on only one side land in
        ``added`` or ``removed``.
    """
    prev_idx = _index_by_host(prev)
    curr_idx = _index_by_host(curr)

    improved: list[str] = []
    regressed: list[str] = []
    unchanged: list[str] = []

    for host in prev_idx.keys() & curr_idx.keys():
        p = prev_idx[host]
        c = curr_idx[host]
        p_alg = _algorithm_string(p)
        c_alg = _algorithm_string(c)
        p_v = _verdict(p)
        c_v = _verdict(c)

        # Verdict signals dominate. ERROR → measurable counts as
        # "improved" (we can now see the host).
        if p_v == "ERROR" and c_v in ("PASS", "FAIL"):
            improved.append(host)
            continue
        if c_v == "ERROR" and p_v in ("PASS", "FAIL"):
            regressed.append(host)
            continue
        if p_v == "FAIL" and c_v == "PASS":
            improved.append(host)
            continue
        if p_v == "PASS" and c_v == "FAIL":
            regressed.append(host)
            continue

        # PQC-negotiated signals. Going classical → PQC is improvement
        # even if the verdict stays the same.
        p_pqc = _has_pqc(p_alg)
        c_pqc = _has_pqc(c_alg)
        if not p_pqc and c_pqc:
            improved.append(host)
            continue
        if p_pqc and not c_pqc:
            regressed.append(host)
            continue

        unchanged.append(host)

    added = sorted(curr_idx.keys() - prev_idx.keys())
    removed = sorted(prev_idx.keys() - curr_idx.keys())

    return {
        "improved": sorted(improved),
        "regressed": sorted(regressed),
        "unchanged": sorted(unchanged),
        "added": added,
        "removed": removed,
    }


def render_diff_markdown(
    diff: dict[str, list[str]],
    *,
    before_label: str,
    after_label: str,
) -> str:
    """Render the diff as one short Italian-language Markdown report."""
    n_imp = len(diff["improved"])
    n_reg = len(diff["regressed"])
    n_unc = len(diff["unchanged"])
    n_add = len(diff["added"])
    n_rem = len(diff["removed"])

    lines = [
        "# Batch PQC audit — diff temporale",
        "",
        f"- **Before:** `{before_label}`",
        f"- **After:** `{after_label}`",
        f"- **Migliorati (improved):** {n_imp}",
        f"- **Peggiorati (regressed):** {n_reg}",
        f"- **Invariati (unchanged):** {n_unc}",
        f"- **Aggiunti (added):** {n_add}",
        f"- **Rimossi (removed):** {n_rem}",
        "",
        "## Dettaglio",
        "",
    ]

    def _section(title: str, hosts: list[str]) -> None:
        lines.append(f"### {title}")
        if not hosts:
            lines.append("_(nessuno)_")
        else:
            for h in hosts:
                lines.append(f"- `{h}`")
        lines.append("")

    _section("Migliorati ✅", diff["improved"])
    _section("Peggiorati ⚠️", diff["regressed"])
    _section("Invariati", diff["unchanged"])
    _section("Aggiunti", diff["added"])
    _section("Rimossi", diff["removed"])

    return "\n".join(lines) + "\n"


__all__ = ["compare_batches", "render_diff_markdown"]
