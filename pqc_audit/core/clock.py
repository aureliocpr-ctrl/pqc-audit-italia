"""Frozen-clock helper for deterministic / legally reproducible audits.

The end-to-end smoke at the end of Sprint 8b found that two
back-to-back ``scan iac`` runs on the same fixture produced
different report SHA-256 digests because ``datetime.now(UTC)`` was
sprinkled across the scanner orchestrator (``AuditReport.generated_at``,
``ScanResult.started_at``, ``ScanResult.finished_at``,
``CryptoAsset.discovered_at``, ``PolicyEvaluation.evaluated_at``).
For an audit deliverable that needs to be signed and re-derivable by
a regulator, every one of those timestamps must come from a single,
auditable source.

The auditor freezes the clock by setting the env var::

    PQC_AUDIT_FROZEN_AT=2026-05-17T12:00:00Z

Then every ``frozen_now()`` call in this run returns that exact UTC
instant. Two re-runs with the same env var produce bit-identical
JSON, which feeds bit-identical canonical bytes, which produces a
bit-identical SHA-256 — the legal fingerprint round-trips.

Design choices:

* **Env var, not CLI flag.** The timestamp surfaces in 9 subcommands
  + the batch orchestrator + the policy engine + every scanner.
  Threading a flag through all of them is invasive and error-prone;
  reading one env var in one helper keeps the change surgical.
* **UTC normalization.** A naive ISO datetime in the env var is
  interpreted as UTC, not local time — otherwise two auditors in
  different timezones get different frozen instants.
* **``Z`` suffix accepted.** RFC 3339 short form
  (``2026-05-17T12:00:00Z``) is accepted alongside the
  ``+00:00`` form.
* **Invalid input is a warning, not a crash.** If the env var is
  unparseable we log at WARNING and fall back to ``datetime.now(UTC)``
  — the auditor's run continues but the determinism guarantee is
  documented as lost. (We could fail closed; we choose to warn so a
  typo in CI doesn't dynamite the whole job.)
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

log = logging.getLogger(__name__)

FROZEN_AT_ENV_VAR = "PQC_AUDIT_FROZEN_AT"
REPORT_ID_ENV_VAR = "PQC_AUDIT_REPORT_ID"


def _parse_frozen(raw: str) -> datetime | None:
    """Parse an ISO-8601 datetime string from the env var.

    Returns ``None`` if the string is not a valid datetime, so the
    caller can fall back to the real clock instead of crashing.
    """
    candidate = raw.strip()
    if not candidate:
        return None
    # ``datetime.fromisoformat`` rejects the trailing ``Z`` in Python
    # < 3.11. We're on 3.11+ so it should work, but normalize anyway
    # so the behaviour matches across patch versions.
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def frozen_now() -> datetime:
    """Return ``datetime.now(UTC)`` unless ``PQC_AUDIT_FROZEN_AT`` overrides it.

    The override must be an ISO-8601 datetime string. A naive
    datetime is interpreted as UTC. A ``Z`` suffix is accepted.
    """
    raw = os.environ.get(FROZEN_AT_ENV_VAR)
    if raw:
        parsed = _parse_frozen(raw)
        if parsed is not None:
            return parsed
        log.warning(
            "%s is set but not a valid ISO-8601 datetime (%r); "
            "falling back to datetime.now(UTC). Audit reproducibility "
            "is lost for this run.",
            FROZEN_AT_ENV_VAR,
            raw,
        )
    return datetime.now(UTC)


def report_id_override() -> str | None:
    """Return ``PQC_AUDIT_REPORT_ID`` if set and non-empty, else ``None``.

    The Auditor uses this to pin the report id for legally
    reproducible audits. Two runs with the same env var and the same
    frozen clock produce a bit-identical report JSON, which feeds a
    bit-identical SHA-256 fingerprint. Without an override the
    Auditor generates a random ``audit-<hex>`` id and the run is
    NOT reproducible — that mode is preserved for ad-hoc scans.
    """
    raw = os.environ.get(REPORT_ID_ENV_VAR, "").strip()
    return raw or None


__all__ = ["FROZEN_AT_ENV_VAR", "REPORT_ID_ENV_VAR", "frozen_now", "report_id_override"]
