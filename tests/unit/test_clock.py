"""Tests for the frozen-clock helper (Sprint 8 step C).

End-to-end smoke at the end of Sprint 8b found that two back-to-back
``scan iac`` runs on the same Terraform fixture produced different
report SHA-256 digests because ``datetime.now(UTC)`` populates both
``AuditReport.generated_at`` and ``CryptoAsset.discovered_at`` at
scan time. For legally reproducible audits the auditor must be able
to freeze the clock via an out-of-band knob (env var) so a regulator
re-running the same scan + canonical_json + sha256 chain produces a
bit-identical digest.

Design choice: an ENV variable rather than a CLI flag, because the
clock surfaces in multiple subcommands (every ``scan`` command, the
Auditor wrapper, the policy engine) — threading a flag through all
of them would be 9 separate diff hunks. The env var is parsed once,
in one helper, and consumed everywhere downstream.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PQC_AUDIT_FROZEN_AT", raising=False)


def test_frozen_now_returns_real_now_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    from pqc_audit.core.clock import frozen_now

    before = datetime.now(UTC) - timedelta(seconds=1)
    got = frozen_now()
    after = datetime.now(UTC) + timedelta(seconds=1)
    assert before <= got <= after
    assert got.tzinfo is not None


def test_frozen_now_respects_iso8601_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQC_AUDIT_FROZEN_AT", "2026-05-17T12:00:00+00:00")
    from pqc_audit.core.clock import frozen_now

    got = frozen_now()
    assert got == datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


def test_frozen_now_accepts_z_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    """``2026-05-17T12:00:00Z`` (RFC 3339 short form) must be accepted."""
    monkeypatch.setenv("PQC_AUDIT_FROZEN_AT", "2026-05-17T12:00:00Z")
    from pqc_audit.core.clock import frozen_now

    got = frozen_now()
    assert got == datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


def test_frozen_now_invalid_env_var_falls_back_to_real_now(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PQC_AUDIT_FROZEN_AT", "not-a-date")
    from pqc_audit.core.clock import frozen_now

    # Should still return *some* tz-aware datetime, not crash. We
    # cannot assert exact equality with now() so we only check shape.
    got = frozen_now()
    assert isinstance(got, datetime)
    assert got.tzinfo is not None


def test_frozen_now_two_calls_return_identical_value_when_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole point of freezing: two consecutive calls are bit-identical."""
    monkeypatch.setenv("PQC_AUDIT_FROZEN_AT", "2026-05-17T12:00:00Z")
    from pqc_audit.core.clock import frozen_now

    assert frozen_now() == frozen_now()


def test_frozen_now_strips_naive_input_to_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    """A naive ISO datetime in the env var must be interpreted as UTC,
    not as local time — otherwise two auditors in different timezones get
    different frozen instants."""
    monkeypatch.setenv("PQC_AUDIT_FROZEN_AT", "2026-05-17T12:00:00")
    from pqc_audit.core.clock import frozen_now

    got = frozen_now()
    assert got.tzinfo is not None
    assert got == datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


def test_frozen_now_env_var_name_is_public_constant() -> None:
    """The env-var name is part of the public contract — pin it."""
    from pqc_audit.core.clock import FROZEN_AT_ENV_VAR

    assert FROZEN_AT_ENV_VAR == "PQC_AUDIT_FROZEN_AT"


# --- report_id_override ---------------------------------------------


def test_report_id_override_returns_none_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PQC_AUDIT_REPORT_ID", raising=False)
    from pqc_audit.core.clock import report_id_override

    assert report_id_override() is None


def test_report_id_override_returns_env_value_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQC_AUDIT_REPORT_ID", "audit-001")
    from pqc_audit.core.clock import report_id_override

    assert report_id_override() == "audit-001"


def test_report_id_override_treats_empty_string_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQC_AUDIT_REPORT_ID", "")
    from pqc_audit.core.clock import report_id_override

    assert report_id_override() is None


def test_report_id_override_strips_surrounding_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQC_AUDIT_REPORT_ID", "  audit-002  ")
    from pqc_audit.core.clock import report_id_override

    assert report_id_override() == "audit-002"


def test_report_id_env_var_name_is_public_constant() -> None:
    from pqc_audit.core.clock import REPORT_ID_ENV_VAR

    assert REPORT_ID_ENV_VAR == "PQC_AUDIT_REPORT_ID"
