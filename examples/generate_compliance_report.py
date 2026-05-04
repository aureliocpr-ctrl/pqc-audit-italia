"""Example: scan a list of TLS targets and emit a compliance summary
that maps findings to NIS2 / DORA / AgID controls.

Usage::

    python examples/generate_compliance_report.py www.agid.gov.it www.inps.it

The output is a human-readable Markdown summary printed to stdout. It
is intentionally compact — the full machine-readable JSON lives in
the JSON reporter; this script is the auditor-facing companion.
"""

from __future__ import annotations

import asyncio
import sys
from collections import Counter

from pqc_audit import Auditor, ScanTarget


def _md_section(title: str) -> str:
    bar = "=" * len(title)
    return f"\n## {title}\n{bar}\n"


async def main() -> None:
    hosts = sys.argv[1:]
    if not hosts:
        print("usage: generate_compliance_report.py <host> [host ...]", file=sys.stderr)
        sys.exit(2)

    auditor = Auditor(policy="agid_2026", data_sensitivity_years=15)
    targets = [ScanTarget(type="tls", host=h, port=443) for h in hosts]
    report = await auditor.scan(targets)

    risk = report.metadata["risk_summary"]
    sev_count: Counter[str] = Counter()
    for sr in report.scan_results:
        for v in sr.vulnerabilities:
            sev_count[v.severity.name] += 1

    print(f"# pqc-audit-italia — compliance summary  ({report.report_id})")
    print(f"Policy: **{report.policy_name}** — generated at {report.generated_at.isoformat()}")

    print(_md_section("Executive summary"))
    print(f"- Targets scanned:       **{len(targets)}**")
    print(f"- Crypto assets found:   **{risk['asset_count']}**")
    print(f"- Quantum-vulnerable:    **{risk['vulnerable_count']}**")
    print(f"- Quantum-resistant:     **{risk['resistant_count']}**")
    print(f"- HNDL exposure (max):   **{risk['hndl_max']}/100**")
    print(f"- Q-Day exposure (max):  **{risk['qday_max']}/100**")
    for sev, n in sorted(sev_count.items(), key=lambda x: -ord(x[0][0])):
        print(f"- {sev:8s} findings: **{n}**")

    print(_md_section("Migration recommendations"))
    if not report.recommendations:
        print("_No migration recommendations — all assets pass the policy._")
    for rec in report.recommendations:
        print(f"- **P{rec.priority}**: `{rec.from_algorithm}` → `{rec.to_algorithm}`")
        if rec.hybrid_intermediate:
            print(f"  - hybrid intermediate: `{rec.hybrid_intermediate}`")
        print(f"  - {rec.rationale}")

    print(_md_section("Compliance mapping"))
    print("- NIS2 art. 21(2)(h) — cryptography policy")
    print("- DORA art. 9        — protection and prevention")
    print("- AgID Linee Guida   — funzioni crittografiche")
    print("\n_See `docs/compliance/` for the full mapping per finding._")


if __name__ == "__main__":
    asyncio.run(main())
