"""Integration tests — real network probe of ML-DSA TLS 1.3 sigalgs.

Sprint 9f.2 v2 follow-up: the unit tests in
``tests/unit/test_scanners_tls_pqc_sig.py`` use monkeypatched
subprocess to validate the contract. These tests validate the
*real* pipeline: subprocess invokes the system openssl binary
against a real public endpoint and the parser handles the actual
output bytes.

Skipped by default — run with ``pytest -m integration`` or in CI
with the integration mark enabled. Requires:

* ``openssl`` 3.5+ in ``PATH`` (the audit machine has 3.5.5);
* outbound TCP 443 access to ``google.com`` (the canary target);
* ~5–10 seconds wall-clock per test (three sequential probes).

Rationale: target ``google.com`` because it is the most stable
public TLS endpoint we can reach; we assert only schema and
classification range, NOT a specific verdict — Google may roll
out MLDSA at any time, and the test must remain stable when that
happens. The contract this test enforces is "the probe returns a
well-formed answer for a real endpoint", not "MLDSA is currently
unsupported globally".
"""

from __future__ import annotations

import json

import pytest


@pytest.mark.integration
def test_probe_real_endpoint_returns_stable_schema() -> None:
    """The real probe pipeline must populate every required key with a
    valid status value, regardless of whether MLDSA is actually
    supported on the target."""
    from pqc_audit.scanners.tls_pqc_sig import (
        MLDSA_CODEPOINTS,
        MLDSA_SIGALGS,
        probe_all_mldsa_sigalgs,
    )

    results = probe_all_mldsa_sigalgs("google.com", 443)
    assert set(results.keys()) == set(MLDSA_SIGALGS)
    for sigalg, result in results.items():
        assert set(result.keys()) == {"sigalg", "codepoint", "status", "host", "port"}
        assert result["sigalg"] == sigalg
        assert result["codepoint"] == MLDSA_CODEPOINTS[sigalg]
        assert result["host"] == "google.com"
        assert result["port"] == 443
        assert result["status"] in {"supported", "not_supported", "error"}


@pytest.mark.integration
def test_cli_real_endpoint_emits_valid_json() -> None:
    """The CLI subcommand against a real endpoint must emit
    well-formed JSON with the documented top-level keys."""
    from typer.testing import CliRunner

    from pqc_audit.cli import app
    from pqc_audit.scanners.tls_pqc_sig import MLDSA_SIGALGS

    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", "pqc-mldsa-sig", "--host", "google.com", "--port", "443"]
    )
    assert result.exit_code == 0, f"CLI exited {result.exit_code}: {result.stdout}"
    payload = json.loads(result.stdout)
    assert payload["host"] == "google.com"
    assert payload["port"] == 443
    assert payload["probe"] == "tls13-signature-algorithms-mldsa"
    assert payload["reference"] == "draft-ietf-tls-mldsa-03"
    assert set(payload["results"].keys()) == set(MLDSA_SIGALGS)
    for sigalg in MLDSA_SIGALGS:
        entry = payload["results"][sigalg]
        assert entry["status"] in {"supported", "not_supported", "error"}
