"""Canonical JSON + report SHA-256 (Sprint 8 step A).

This module is the foundation of the legal-value chain: it produces a
byte-stable serialization of an audit-report payload + a SHA-256 of
those bytes. Every downstream signer (RFC 3161 TSA, sigstore keyless)
must consume the *same* bytes so the hash round-trips from auditor to
regulator. A regulator independently recomputes
``sha256(canonical_json(parsed))`` on the report they receive and
compares to the auditor's published digest.

Implementation note:
    The form is an *approximate* JCS-style canonical: ``json.dumps``
    with ``sort_keys=True``, compact separators, ``ensure_ascii=False``
    and ``allow_nan=False``. It is NOT full RFC 8785. The audit
    report does not use IEEE-754 floats in any normative field
    (severity is an enum, risk scores are int, dates are ISO 8601
    strings), so the edge cases RFC 8785 was written to disambiguate
    do not arise here. If you need strict RFC 8785 — e.g. when
    embedding floats from a benchmark — swap this function with the
    ``rfc8785`` package on PyPI.

Security: the function does not perform I/O and does not raise on
untrusted input shapes (lists, dicts, scalars). It refuses NaN /
Infinity because RFC 8259 forbids them — leaving them in would
produce non-JSON output that downstream verifiers would reject.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(payload: Any) -> str:
    """Return a byte-stable JSON serialization of ``payload``.

    Properties guaranteed for any JSON-safe input:

    * Dict keys appear in lexicographic order at every nesting level.
    * No whitespace between tokens (``separators=(",", ":")``).
    * Non-ASCII characters are emitted verbatim (no ``\\uXXXX``
      escaping) — so the canonical form remains human-readable for
      Italian / French / German audits.
    * NaN / Infinity raise :class:`ValueError`.
    * List / tuple order is preserved — it is semantically
      meaningful for audit data (scan_results in chronological
      order, vulnerabilities in detection order).

    Raises:
        ValueError: when ``payload`` contains NaN or Infinity.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def report_sha256(payload: Any) -> str:
    """Return the lowercase hex SHA-256 of ``canonical_json(payload)``.

    The 64-char hex digest is the public commit a regulator can
    re-verify: they parse the report JSON, run
    :func:`canonical_json` on the parsed object, hash the result,
    and compare to the published digest. A single-byte difference
    anywhere — including key insertion order — produces a different
    digest, so this is the legal fingerprint of the report.
    """
    canonical = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = ["canonical_json", "report_sha256"]
