"""Lock-in test sullo schema JSON di ``batch_report.json``.

Customer integrano l'output JSON in dashboard / SARIF converter /
SIEM. Una rinomina silenziosa di una key (``policy_evaluation`` →
``policy_eval``, ``vulnerabilities`` → ``vulns``) rompe ogni
integrazione.

Pinniamo le key obbligatorie del payload per host.
"""

from __future__ import annotations

from pqc_audit import batch as batch_mod


def test_summarize_one_keys_stable() -> None:
    """``summarize_one`` row deve avere le chiavi documentate."""
    fake_report = {
        "scan_results": [
            {
                "assets": [{"algorithm": {"name": "RSA", "key_size_bits": 2048}}],
                "vulnerabilities": [{"title": "x"}],
            }
        ],
        "metadata": {"risk_summary": {"hndl_max": 100, "qday_max": 80}},
        "recommendations": [{"to_algorithm": "ML-DSA-65", "priority": 5}],
        "policy_evaluation": {"overall_verdict": "FAIL", "violations": [{"rule": "x"}]},
    }
    row = batch_mod.summarize_one("ok.example", fake_report)
    required = {
        "host",
        "status",
        "algorithm",
        "vulns",
        "hndl",
        "qday",
        "policy_verdict",
        "violations",
        "top_reco",
    }
    assert required <= set(row.keys()), (
        f"summarize_one ok-row deve contenere {required}, got {set(row.keys())}"
    )


def test_summarize_one_error_keys_stable() -> None:
    """Error row deve avere ``host``, ``status='error'``, ``error``."""
    err_report = {"error": "TimeoutError"}
    row = batch_mod.summarize_one("err.example", err_report)
    assert row["status"] == "error"
    assert "host" in row
    assert "error" in row


def test_summarize_one_inner_error_path_stable() -> None:
    """Inner-error path: ``status='error'`` con ``error`` populated."""
    inner_err = {
        "scan_results": [
            {
                "assets": [],
                "vulnerabilities": [],
                "errors": ["gaierror"],
            }
        ],
    }
    row = batch_mod.summarize_one("err.example", inner_err)
    assert row["status"] == "error"
    assert "gaierror" in row["error"]


def test_target_dataclass_fields_stable() -> None:
    """``Target`` dataclass: campi documentati."""
    t = batch_mod.Target(host="x.example", port=443, scope="x.example")
    assert t.host == "x.example"
    assert t.port == 443
    assert t.scope == "x.example"
    assert hasattr(t, "resolved_scope")


def test_compare_batches_buckets_stable() -> None:
    """``compare_batches`` ritorna 5 bucket nominati."""
    from pqc_audit.batch_diff import compare_batches

    out = compare_batches([], [])
    required_buckets = {"improved", "regressed", "unchanged", "added", "removed"}
    assert required_buckets == set(out.keys()), (
        f"compare_batches deve avere bucket {required_buckets}, got {set(out.keys())}"
    )
