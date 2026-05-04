"""Tests for Auditor concurrency control."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest


class _SlowScanner:
    """Async scanner that sleeps for ``delay`` seconds, returning empty result."""

    name = "slow-test"
    category = None  # type: ignore[assignment]

    def __init__(self, delay: float = 0.05) -> None:
        self.delay = delay

    async def is_applicable(self, target):  # noqa: ANN001 — dynamic protocol
        return target.type == "tls"

    async def scan(self, target):  # noqa: ANN001
        from pqc_audit.core.models import ScanResult

        await asyncio.sleep(self.delay)
        now = datetime.now(UTC)
        return ScanResult(
            scanner_name=self.name,
            target=str(target.host),
            assets=[],
            vulnerabilities=[],
            started_at=now,
            finished_at=now,
        )


@pytest.mark.asyncio
async def test_scan_runs_targets_concurrently() -> None:
    """5 targets * 100ms each, max_concurrency=5 -> wall time ~100ms,
    well under 5*100ms = 500ms (would be the sequential lower bound)."""
    from pqc_audit import Auditor, ScanTarget

    auditor = Auditor(scanners=[_SlowScanner(delay=0.1)], max_concurrency=5)
    targets = [ScanTarget(type="tls", host=f"h{i}", port=443) for i in range(5)]

    started = asyncio.get_event_loop().time()
    report = await auditor.scan(targets)
    elapsed = asyncio.get_event_loop().time() - started

    assert len(report.scan_results) == 5
    assert elapsed < 0.4, f"expected concurrent (<0.4s), got {elapsed:.2f}s"


def test_max_concurrency_zero_rejected() -> None:
    from pqc_audit import Auditor

    with pytest.raises(ValueError, match="max_concurrency"):
        Auditor(max_concurrency=0)


@pytest.mark.asyncio
async def test_concurrency_bound_respected() -> None:
    """With max_concurrency=2, 4 targets * 100ms => wall time roughly 2*100ms."""
    from pqc_audit import Auditor, ScanTarget

    auditor = Auditor(scanners=[_SlowScanner(delay=0.1)], max_concurrency=2)
    targets = [ScanTarget(type="tls", host=f"h{i}", port=443) for i in range(4)]

    started = asyncio.get_event_loop().time()
    await auditor.scan(targets)
    elapsed = asyncio.get_event_loop().time() - started

    # 4 jobs, 2 at a time, each 0.1s -> ~0.2s. Allow generous slack.
    assert 0.15 <= elapsed < 0.5, f"unexpected elapsed: {elapsed:.2f}s"
