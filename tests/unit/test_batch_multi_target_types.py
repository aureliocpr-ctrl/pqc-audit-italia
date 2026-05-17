"""Tests for batch CLI multi-target-type support — Sprint 9l.

The original batch implementation hard-coded ``type="tls"`` in
:func:`pqc_audit.batch.run_one`. After Sprint 9j (Postgres), 9j.2
(MySQL), 9j.3 (DB scanner classes), 9k (SMTP STARTTLS), 9f
(PQC hybrid), and 9f.2 (PQC ML-DSA sig), an audit operator needs
to mix target types in a single batch run. This sprint adds:

* :class:`Target` gains a ``target_type`` field (default ``"tls"``,
  preserving backward compatibility);
* :func:`parse_inline_targets` understands the ``type://host:port``
  prefix syntax;
* :func:`parse_csv` reads an optional fourth column ``type``;
* :func:`run_one` dispatches via ``target.target_type``, building
  the right ``ScanTarget`` and the right ``Auditor`` scanner stack.

A CSV can therefore mix lines such as::

    aruba.it,443,banking,tls
    db.example.com,5432,db,postgres-ssl
    mx.example.com,25,mail,smtp-starttls
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------
# Target dataclass — new ``target_type`` field with backward-compat default
# ---------------------------------------------------------------------


def test_target_target_type_defaults_to_tls() -> None:
    from pqc_audit.batch import Target

    t = Target(host="example.com", port=443)
    assert t.target_type == "tls"


def test_target_accepts_explicit_target_type() -> None:
    from pqc_audit.batch import Target

    t = Target(host="db.example.com", port=5432, target_type="postgres-ssl")
    assert t.target_type == "postgres-ssl"


# ---------------------------------------------------------------------
# parse_inline_targets — type://host:port prefix syntax
# ---------------------------------------------------------------------


def test_parse_inline_supports_type_prefix() -> None:
    from pqc_audit.batch import parse_inline_targets

    targets = parse_inline_targets(
        "postgres-ssl://db.example.com:5432, mysql-ssl://db.example.com:3306"
    )
    assert len(targets) == 2
    assert targets[0].target_type == "postgres-ssl"
    assert targets[0].host == "db.example.com"
    assert targets[0].port == 5432
    assert targets[1].target_type == "mysql-ssl"
    assert targets[1].port == 3306


def test_parse_inline_falls_back_to_tls_without_prefix() -> None:
    """Backward compatibility: pre-Sprint 9l CSVs / arguments still work."""
    from pqc_audit.batch import parse_inline_targets

    targets = parse_inline_targets("example.com:443, other.example.it")
    assert len(targets) == 2
    assert targets[0].target_type == "tls"
    assert targets[0].port == 443
    assert targets[1].target_type == "tls"
    assert targets[1].port == 443


def test_parse_inline_understands_smtp_starttls_prefix() -> None:
    from pqc_audit.batch import parse_inline_targets

    targets = parse_inline_targets("smtp-starttls://mx.example.it:25")
    assert len(targets) == 1
    assert targets[0].target_type == "smtp-starttls"
    assert targets[0].port == 25


def test_parse_inline_rejects_unknown_type_prefix_silently_as_tls() -> None:
    """A bogus prefix is treated as part of the host name, so the
    target falls back to ``tls`` — never raise on user input."""
    from pqc_audit.batch import parse_inline_targets

    targets = parse_inline_targets("not-a-type://example.com:443")
    assert len(targets) == 1
    # The prefix is unrecognized so we treat the whole thing as host
    # with default tls type.
    assert targets[0].target_type == "tls"


# ---------------------------------------------------------------------
# parse_csv — optional 4th column ``type``
# ---------------------------------------------------------------------


def test_parse_csv_reads_optional_type_column(tmp_path: Path) -> None:
    from pqc_audit.batch import parse_csv

    csv_path = tmp_path / "mixed.csv"
    csv_path.write_text(
        "host,port,scope,type\n"
        "aruba.it,443,banking,tls\n"
        "db.example.com,5432,db,postgres-ssl\n"
        "mx.example.com,25,mail,smtp-starttls\n",
        encoding="utf-8",
    )
    targets = parse_csv(csv_path)
    assert len(targets) == 3
    assert targets[0].target_type == "tls"
    assert targets[1].target_type == "postgres-ssl"
    assert targets[1].port == 5432
    assert targets[2].target_type == "smtp-starttls"
    assert targets[2].port == 25


def test_parse_csv_backward_compat_three_columns_defaults_to_tls(tmp_path: Path) -> None:
    """Pre-Sprint 9l CSV (3 columns) must keep working."""
    from pqc_audit.batch import parse_csv

    csv_path = tmp_path / "legacy.csv"
    csv_path.write_text(
        "host,port,scope\n"
        "example.com,443,prod\n"
        "other.it,8443,staging\n",
        encoding="utf-8",
    )
    targets = parse_csv(csv_path)
    assert len(targets) == 2
    for t in targets:
        assert t.target_type == "tls"


def test_parse_csv_unknown_type_falls_back_to_tls(tmp_path: Path) -> None:
    from pqc_audit.batch import parse_csv

    csv_path = tmp_path / "unknown.csv"
    csv_path.write_text(
        "host,port,scope,type\n"
        "example.com,443,prod,bogus-type\n",
        encoding="utf-8",
    )
    targets = parse_csv(csv_path)
    assert targets[0].target_type == "tls"


# ---------------------------------------------------------------------
# run_one — dispatch to the right scanner stack by target_type
# ---------------------------------------------------------------------


def test_run_one_dispatches_postgres_ssl(monkeypatch) -> None:
    """``run_one`` must build a ScanTarget(type='postgres-ssl', ...)
    and pass an Auditor with PostgresSSLScanner so the new probe
    is actually exercised."""
    import asyncio

    from pqc_audit.batch import Target, run_one

    seen_types: list[str] = []

    class _StubReport:
        def model_dump_json(self) -> str:
            return '{"report_id": "stub", "scan_results": [], "metadata": {}}'

    class _StubAuditor:
        def __init__(self, *args, **kwargs):
            self._scanners = kwargs.get("scanners")

        async def scan(self, targets):
            for t in targets:
                seen_types.append(t.type)
            return _StubReport()

        def evaluate_against_policy(self, report):
            return _StubReport()

    monkeypatch.setattr("pqc_audit.batch.Auditor", _StubAuditor)

    target = Target(
        host="db.example.com", port=5432, target_type="postgres-ssl"
    )
    asyncio.run(run_one(target, policy="default", sensitivity=10, enforce=False))
    assert seen_types == ["postgres-ssl"]


def test_run_one_dispatches_smtp_starttls(monkeypatch) -> None:
    import asyncio

    from pqc_audit.batch import Target, run_one

    seen_types: list[str] = []

    class _StubReport:
        def model_dump_json(self) -> str:
            return '{"report_id": "stub", "scan_results": [], "metadata": {}}'

    class _StubAuditor:
        def __init__(self, *args, **kwargs):
            pass

        async def scan(self, targets):
            for t in targets:
                seen_types.append(t.type)
            return _StubReport()

        def evaluate_against_policy(self, report):
            return _StubReport()

    monkeypatch.setattr("pqc_audit.batch.Auditor", _StubAuditor)

    target = Target(
        host="mx.example.it", port=25, target_type="smtp-starttls"
    )
    asyncio.run(run_one(target, policy="default", sensitivity=10, enforce=False))
    assert seen_types == ["smtp-starttls"]


def test_every_known_target_type_is_a_valid_scantarget_literal() -> None:
    """Post-critic invariant (Sprint 9l v2): every entry in
    _KNOWN_TARGET_TYPES MUST be a member of the ScanTarget TargetType
    Literal. Otherwise pydantic would raise ValidationError when run_one
    constructs the ScanTarget, breaking the 'batch never aborts'
    contract.
    """
    from pqc_audit.batch import _KNOWN_TARGET_TYPES
    from pqc_audit.scanners.base import ScanTarget

    for t in _KNOWN_TARGET_TYPES:
        # If this raises, the Literal is out of sync with the batch set.
        ScanTarget(type=t, host="example.com", port=443)


def test_run_one_handles_validation_error_gracefully(monkeypatch) -> None:
    """Defense-in-depth: even if _KNOWN_TARGET_TYPES drifts out of sync
    with the ScanTarget Literal in some future commit, run_one must
    capture the ValidationError and surface it as a per-host error
    rather than aborting the whole batch."""
    import asyncio

    from pqc_audit.batch import Target, run_one

    # Use a Target whose target_type is NOT in the ScanTarget Literal.
    # Bypass the dataclass frozen check via object.__setattr__ since
    # the field has a default value and we need a synthetic case.
    target = Target(host="example.com", port=443, target_type="tls")
    object.__setattr__(target, "target_type", "pqc-mldsa-sig")

    payload = asyncio.run(
        run_one(target, policy="default", sensitivity=10, enforce=False)
    )
    assert "error" in payload, f"expected error payload, got {payload}"
    assert "unsupported target_type" in payload["error"]
    assert payload["target_type"] == "pqc-mldsa-sig"


def test_run_one_default_tls_unchanged(monkeypatch) -> None:
    """Backward compatibility: a Target without explicit target_type
    still scans as TLS."""
    import asyncio

    from pqc_audit.batch import Target, run_one

    seen_types: list[str] = []

    class _StubReport:
        def model_dump_json(self) -> str:
            return '{"report_id": "stub", "scan_results": [], "metadata": {}}'

    class _StubAuditor:
        def __init__(self, *args, **kwargs):
            pass

        async def scan(self, targets):
            for t in targets:
                seen_types.append(t.type)
            return _StubReport()

        def evaluate_against_policy(self, report):
            return _StubReport()

    monkeypatch.setattr("pqc_audit.batch.Auditor", _StubAuditor)

    target = Target(host="example.com", port=443)
    asyncio.run(run_one(target, policy="default", sensitivity=10, enforce=False))
    assert seen_types == ["tls"]
