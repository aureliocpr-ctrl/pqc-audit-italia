"""Tests for canonical JSON + report SHA-256 (Sprint 8 step A).

The canonical form is the foundation of the legal-value chain: every
downstream signer (RFC 3161 TSA, sigstore keyless) must consume the
*same* bytes for the hash to roundtrip from auditor to regulator.

The implementation is an *approximate* JCS-style canonical form
(json.dumps with sort_keys + compact separators), not full RFC 8785.
Edge cases around float representation are not exercised here — the
audit report does not use IEEE-754 floats in any normative field
(severity is an enum, scores are int, dates are ISO strings).
"""

from __future__ import annotations

import json

import pytest


def test_canonical_json_sorts_keys_lexicographically() -> None:
    from pqc_audit.reporters.canonical import canonical_json

    out = canonical_json({"b": 1, "a": 2, "c": 3})
    # Keys must appear in lex order, with no whitespace.
    assert out == '{"a":2,"b":1,"c":3}'


def test_canonical_json_handles_nested_dicts() -> None:
    from pqc_audit.reporters.canonical import canonical_json

    out = canonical_json({"z": {"b": 1, "a": 2}, "a": [3, 1, 2]})
    # Lists are NOT sorted (their order is semantically meaningful);
    # dict keys at every level are sorted.
    assert out == '{"a":[3,1,2],"z":{"a":2,"b":1}}'


def test_canonical_json_is_byte_stable_across_runs() -> None:
    from pqc_audit.reporters.canonical import canonical_json

    payload = {"report_id": "x", "scan_results": [{"scanner_name": "tls"}]}
    a = canonical_json(payload)
    b = canonical_json(payload)
    assert a == b
    assert a.encode("utf-8") == b.encode("utf-8")


def test_canonical_json_rejects_nan_infinity() -> None:
    from pqc_audit.reporters.canonical import canonical_json

    with pytest.raises(ValueError):
        canonical_json({"score": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"score": float("inf")})


def test_canonical_json_preserves_non_ascii_without_escaping() -> None:
    """Italian audit reports include accented characters — they must NOT be \\uXXXX-escaped.

    A regulator reading the canonical form must see ``è``, not ``\\u00e8``;
    otherwise the displayed text drifts from the hashed bytes.
    """
    from pqc_audit.reporters.canonical import canonical_json

    out = canonical_json({"description": "perché valido"})
    assert "perché" in out
    assert "\\u00e8" not in out


def test_canonical_json_is_valid_json() -> None:
    """Round-trip: parse(canonical_json(x)) must equal x for JSON-safe x."""
    from pqc_audit.reporters.canonical import canonical_json

    obj = {"a": 1, "b": [1, 2, 3], "c": {"d": True, "e": None, "f": "string"}}
    parsed = json.loads(canonical_json(obj))
    assert parsed == obj


def test_report_sha256_is_64_hex_chars() -> None:
    from pqc_audit.reporters.canonical import report_sha256

    sha = report_sha256({"report_id": "x"})
    assert isinstance(sha, str)
    assert len(sha) == 64
    assert all(c in "0123456789abcdef" for c in sha)


def test_report_sha256_changes_if_any_byte_changes() -> None:
    """A single-byte change to any field MUST change the digest."""
    from pqc_audit.reporters.canonical import report_sha256

    a = report_sha256({"report_id": "x", "policy_name": "agid_2026"})
    b = report_sha256({"report_id": "x", "policy_name": "agid_2027"})
    assert a != b


def test_report_sha256_is_stable_across_runs() -> None:
    from pqc_audit.reporters.canonical import report_sha256

    payload = {"report_id": "x", "scan_results": [{"scanner_name": "tls"}]}
    assert report_sha256(payload) == report_sha256(payload)


def test_report_sha256_invariant_under_key_reorder() -> None:
    """Two semantically identical reports with different key insertion
    order must hash the same — that's the whole point of canonicalization."""
    from pqc_audit.reporters.canonical import report_sha256

    a = report_sha256({"a": 1, "b": 2, "c": 3})
    b = report_sha256({"c": 3, "a": 1, "b": 2})
    assert a == b


def test_canonical_json_handles_audit_report_round_trip() -> None:
    """End-to-end smoke: a real AuditReport must canonicalize without raising."""
    from datetime import UTC, datetime

    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        ScanCategory,
        ScanResult,
    )
    from pqc_audit.reporters.canonical import canonical_json, report_sha256
    from pqc_audit.reporters.json_reporter import _to_jsonable

    ts = datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)
    asset = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=ts,
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=[],
        started_at=ts,
        finished_at=ts,
    )
    report = AuditReport(report_id="abc", scan_results=[sr], generated_at=ts)
    payload = _to_jsonable(report)
    canon = canonical_json(payload)
    assert canon.startswith("{")
    sha = report_sha256(payload)
    assert len(sha) == 64
