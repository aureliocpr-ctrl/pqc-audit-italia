"""End-to-end PA italiana audit workflow — runnable example.

Demonstrates a complete audit pass against the public face of an
Italian public administration: TLS handshake + chain validation
+ AgID Trusted List cross-check + PQC hybrid readiness + ML-DSA
signature readiness + Markdown report with NIS2 mapping inline.

The script targets real public endpoints and prints what an
auditor would see today. No credentials, no PII, no perturbation
of server state — only what the servers already advertise.

Run with::

    python examples/audit_pa_italiana.py

Output: prints structured findings to stdout, writes a Markdown
audit report to ``audit_pa_italiana.md`` in the current directory.

Sprint 9d.6 + 9j.3 + 9h-integration: every step uses the integrated
Auditor pipeline, so the Markdown report's NIS2 mapping cites
:literal:`D.Lgs. 138/2024 art. 24(2)(h)` automatically when a
quantum-vulnerable algorithm is detected, and
:literal:`qualified_it_tsp_verified_via_tsl` when the resolved
root CA is in the live AgID TSL.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from pqc_audit import Auditor, ScanTarget
from pqc_audit.compliance.agid_tsl import (
    AgIDTSLFetchError,
    AgIDTSLParseError,
    fetch_agid_tsl,
    parse_agid_tsl,
)
from pqc_audit.reporters.markdown_reporter import render as render_markdown
from pqc_audit.scanners.tls_pqc_sig import probe_all_mldsa_sigalgs
from pqc_audit.scanners.tls_scanner import TLSScanner

# Real public Italian PA / qualified-TSP endpoints. Stable HTTPS only.
TARGETS = [
    ("aruba.it", 443),  # IT qualified TSP (Actalis root)
    ("agid.gov.it", 443),  # AgID itself (Let's Encrypt root)
]


def fetch_tsl_optional() -> dict | None:
    """Try to load the live AgID TSL; return ``None`` on any failure.

    Failures are non-fatal — the audit degrades gracefully to the
    hand-curated pattern list when the TSL is unreachable (air-gapped
    audits, network outage, etc.).
    """
    try:
        xml_bytes = fetch_agid_tsl(timeout=30.0)
        return parse_agid_tsl(xml_bytes)
    except (AgIDTSLFetchError, AgIDTSLParseError) as exc:
        print(f"  (TSL unavailable, continuing without enrichment: {exc})", file=sys.stderr)
        return None


async def audit_one(host: str, port: int, tsl_data: dict | None) -> dict:
    """Run TLS scan + ML-DSA sigalg probe in parallel."""
    scanner = TLSScanner(agid_tsl_data=tsl_data)
    auditor = Auditor(scanners=[scanner])
    target = ScanTarget(type="tls", host=host, port=port)

    tls_task = asyncio.create_task(auditor.scan([target]))
    mldsa_task = asyncio.to_thread(probe_all_mldsa_sigalgs, host, port)
    report, mldsa = await asyncio.gather(tls_task, mldsa_task)
    return {"report": report, "mldsa": mldsa}


async def main() -> int:
    print("=" * 70)
    print(" PQC-audit-italia — PA italiana end-to-end audit")
    print("=" * 70)

    print("\n[1/3] Fetching live AgID Trusted List (eIDAS) ...")
    tsl_data = fetch_tsl_optional()
    if tsl_data is not None:
        print(
            f"      Loaded {len(tsl_data['tsps'])} TSPs, "
            f"{len(tsl_data['qualified_certs'])} qualified-CA certificates."
        )

    print("\n[2/3] Scanning targets ...")
    results = {}
    for host, port in TARGETS:
        print(f"  -> {host}:{port}")
        try:
            results[host] = await audit_one(host, port, tsl_data)
        except Exception as exc:  # noqa: BLE001 — example wants to keep going
            print(f"     scan failed: {type(exc).__name__}: {exc}")

    print("\n[3/3] Findings summary")
    print("-" * 70)
    for host, payload in results.items():
        report = payload["report"]
        print(f"\n# {host}")
        print(f"  total_assets:          {report.total_assets}")
        print(f"  total_vulnerabilities: {report.total_vulnerabilities}")
        print(f"  highest_severity:      {report.highest_severity.name}")

        for sr in report.scan_results:
            for asset in sr.assets:
                ta = asset.metadata.get("trust_anchor") or {}
                if not ta or asset.metadata.get("chain_position") != "leaf":
                    continue
                root_subject = ta.get("root_subject") or "—"
                pedigree = ta.get("pedigree", "—")
                verified = ta.get("verified_in_agid_tsl", None)
                print(f"  trust anchor:          {root_subject}")
                print(f"  pedigree:              {pedigree}")
                if verified is not None:
                    print(f"  verified_in_agid_tsl:  {verified}")

        # ML-DSA sigalg readiness
        any_supported = any(
            r["status"] == "supported" for r in payload["mldsa"].values()
        )
        print(f"  ML-DSA sig support:    {'YES' if any_supported else 'no'}")

    # Render combined markdown audit report for the first host.
    if TARGETS:
        primary_host = TARGETS[0][0]
        if primary_host in results:
            md = render_markdown(results[primary_host]["report"])
            out_path = Path("audit_pa_italiana.md")
            out_path.write_text(md, encoding="utf-8")
            print(f"\nMarkdown audit report written to: {out_path.resolve()}")
            print("(includes inline NIS2 / D.Lgs. 138/2024 art. 24 mapping)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
