"""JSON reporter — structured machine-readable output for tools / CI.

Pure function ``render(report, pretty=True) -> str``. No side effects,
no I/O. Datetime values are emitted as ISO 8601 with timezone offset.
``RiskLevel`` is serialized as its uppercase name (HIGH, CRITICAL, ...)
to keep diffs readable.

The JSON shape is documented in ``docs/architecture.md`` and forms part
of the public contract — adding new optional fields is a minor bump,
removing or renaming is a breaking change.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from typing import Any

from pqc_audit import __version__
from pqc_audit.core.models import AuditReport


def _to_jsonable(obj: Any) -> Any:
    """Recursive coercion of pydantic v2 / datetime / Enum to JSON-safe."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.name
    if hasattr(obj, "model_dump"):
        return _to_jsonable(obj.model_dump())
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    return obj


def render(report: AuditReport, *, pretty: bool = True) -> str:
    """Serialize an :class:`AuditReport` to a JSON string.

    Args:
        report: the audit report to serialize.
        pretty: when True (default), pretty-print with ``indent=2``.
            When False, emits compact single-line JSON.

    Returns:
        JSON string. Caller decides whether to write to a file or stream.
    """
    summary = {
        "tool": "pqc-audit-italia",
        "tool_version": __version__,
        "total_scan_results": len(report.scan_results),
        "total_assets": report.total_assets,
        "total_vulnerabilities": report.total_vulnerabilities,
        "highest_severity": report.highest_severity.name,
    }

    payload = _to_jsonable(report)
    if not isinstance(payload, dict):
        # Defensive: should not happen given the model is a BaseModel.
        payload = {"report": payload}
    payload["summary"] = summary

    indent = 2 if pretty else None
    separators = None if pretty else (",", ":")
    return json.dumps(
        payload, indent=indent, separators=separators, sort_keys=False, ensure_ascii=False
    )
