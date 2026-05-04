"""High-level orchestrator: pick scanners by target type, run them,
aggregate into a single :class:`AuditReport`.

Usage::

    from pqc_audit import Auditor, ScanTarget

    auditor = Auditor(policy="agid_2026")
    report = await auditor.scan([
        ScanTarget(type="tls", host="example.it", port=443),
    ])

The Auditor never raises on per-target errors — failures are captured
in ``ScanResult.errors`` so a single broken target does not abort the
whole audit run.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pqc_audit.core.models import AuditReport, ScanResult
from pqc_audit.scanners.base import BaseScanner, ScanTarget
from pqc_audit.scanners.tls_scanner import TLSScanner


class Auditor:
    """High-level orchestrator over a collection of scanners.

    Args:
        policy: name of the policy to apply (informational for now;
            policy engine lands in Phase 5).
        scanners: optional list of scanner instances. Defaults to the
            built-in scanners (TLS for now).
    """

    def __init__(
        self,
        *,
        policy: str = "default",
        scanners: list[BaseScanner] | None = None,
    ) -> None:
        self.policy = policy
        self.scanners: list[BaseScanner] = (
            list(scanners) if scanners is not None else [TLSScanner()]
        )

    async def scan(self, targets: list[ScanTarget]) -> AuditReport:
        """Run every applicable scanner against every target."""
        results: list[ScanResult] = []
        for target in targets:
            for scanner in self.scanners:
                if await scanner.is_applicable(target):
                    results.append(await scanner.scan(target))

        return AuditReport(
            report_id=f"audit-{uuid.uuid4().hex[:12]}",
            scan_results=results,
            policy_name=self.policy,
            generated_at=datetime.now(UTC),
        )
