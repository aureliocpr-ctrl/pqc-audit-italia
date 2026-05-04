"""Example: scan an entire infrastructure described by a YAML file.

Usage::

    python examples/scan_infrastructure.py infra.yaml > report.json

Where ``infra.yaml`` looks like::

    policy: agid_2026
    data_sensitivity_years: 30
    targets:
      - {type: tls, host: www.agid.gov.it, port: 443}
      - {type: tls, host: www.governo.it, port: 443}
      - {type: tls, host: www.inps.it,    port: 443}
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import yaml

from pqc_audit import Auditor, ScanTarget
from pqc_audit.reporters.json_reporter import render


async def main() -> None:
    if len(sys.argv) < 2:
        print("usage: scan_infrastructure.py <infra.yaml>", file=sys.stderr)
        sys.exit(2)
    cfg = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))

    targets = [ScanTarget(**t) for t in cfg.get("targets", [])]
    auditor = Auditor(
        policy=cfg.get("policy", "default"),
        data_sensitivity_years=int(cfg.get("data_sensitivity_years", 10)),
        max_concurrency=int(cfg.get("max_concurrency", 16)),
    )
    report = await auditor.scan(targets)
    print(render(report))


if __name__ == "__main__":
    asyncio.run(main())
