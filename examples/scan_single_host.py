"""Example: scan a single host's TLS endpoint and print a JSON audit report.

Usage::

    python examples/scan_single_host.py www.agid.gov.it 443
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

from pqc_audit.core.models import AuditReport
from pqc_audit.reporters.json_reporter import render
from pqc_audit.scanners import ScanTarget, TLSScanner


async def main() -> None:
    if len(sys.argv) < 2:
        print("usage: scan_single_host.py <host> [port]", file=sys.stderr)
        sys.exit(2)
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    scanner = TLSScanner()
    target = ScanTarget(type="tls", host=host, port=port)
    result = await scanner.scan(target)

    report = AuditReport(
        report_id=f"single-host-{host}-{port}",
        scan_results=[result],
        policy_name="agid_2026",
        generated_at=datetime.now(timezone.utc),
    )
    print(render(report))


if __name__ == "__main__":
    asyncio.run(main())
