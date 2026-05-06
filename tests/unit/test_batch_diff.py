"""Unit tests for the batch-diff helper.

The helper compares two outputs of ``pqc-audit batch`` (i.e. two
``batch_report.json`` payloads, each a list of per-host audit dicts)
and classifies each host into one of:

- ``improved``  — the host went from FAIL to PASS, or from a classical
  algorithm to a PQC-negotiated one (ML-DSA / ML-KEM / SLH-DSA / sntrup)
- ``regressed`` — the host went from PASS to FAIL, or *lost* a PQC
  algorithm it previously negotiated
- ``unchanged`` — same algorithm and same verdict
- ``added``     — host present in curr but not in prev
- ``removed``   — host present in prev but not in curr

This unlocks the "snapshot mensile" use case: re-run the same batch
every month, save ``batch_report.json`` to artefact storage, and let
the auditor diff this month against last month to surface PQC adoption
trends across a portfolio.

Heavy ergonomics deliberately stay in the CLI / reporter layer; this
module is a pure helper.
"""

from __future__ import annotations

from pqc_audit import batch_diff


def _split_algorithm(s: str) -> tuple[str, int]:
    """Split ``"RSA-2048"`` → ``("RSA", 2048)``,
    ``"ML-DSA-65"`` → ``("ML-DSA", 65)``,
    ``"ECDSA-256"`` → ``("ECDSA", 256)``.
    """
    parts = s.split("-")
    if parts[-1].isdigit():
        return ("-".join(parts[:-1]), int(parts[-1]))
    return (s, 0)


def _entry(
    host: str,
    *,
    algorithm: str = "RSA-2048",
    verdict: str = "FAIL",
    error: str | None = None,
) -> dict:
    """Build a minimal AuditReport-shaped dict for one host."""
    if error is not None:
        return {"host": host, "error": error}
    name, bits = _split_algorithm(algorithm)
    return {
        "metadata": {"target_host": host},
        "scan_results": [
            {
                "target": f"{host}:443",
                "assets": [
                    {
                        "algorithm": {
                            "name": name,
                            "key_size_bits": bits,
                        }
                    }
                ],
                "vulnerabilities": [],
            }
        ],
        "policy_evaluation": {
            "policy": "agid_2026",
            "overall_verdict": verdict,
            "violations": [],
        },
    }


def test_compare_batches_improved_fail_to_pass() -> None:
    prev = [_entry("a.it", verdict="FAIL")]
    curr = [_entry("a.it", verdict="PASS")]
    out = batch_diff.compare_batches(prev, curr)
    assert "a.it" in out["improved"]
    assert "a.it" not in out["regressed"]


def test_compare_batches_regressed_pass_to_fail() -> None:
    prev = [_entry("a.it", verdict="PASS")]
    curr = [_entry("a.it", verdict="FAIL")]
    out = batch_diff.compare_batches(prev, curr)
    assert "a.it" in out["regressed"]


def test_compare_batches_improved_classical_to_pqc() -> None:
    """Going RSA-2048 → ML-DSA-65 is an improvement even if the
    overall verdict stays the same (which it shouldn't, but we
    don't want to depend on policy semantics for this signal)."""
    prev = [_entry("a.it", algorithm="RSA-2048", verdict="FAIL")]
    curr = [_entry("a.it", algorithm="ML-DSA-65", verdict="FAIL")]
    out = batch_diff.compare_batches(prev, curr)
    assert "a.it" in out["improved"]


def test_compare_batches_regressed_pqc_lost() -> None:
    prev = [_entry("a.it", algorithm="ML-DSA-65", verdict="PASS")]
    curr = [_entry("a.it", algorithm="RSA-2048", verdict="FAIL")]
    out = batch_diff.compare_batches(prev, curr)
    # Two reasons to regress — verdict AND algorithm — but only one
    # entry in the bucket is correct.
    assert out["regressed"].count("a.it") == 1


def test_compare_batches_unchanged() -> None:
    prev = [_entry("a.it", algorithm="RSA-2048", verdict="FAIL")]
    curr = [_entry("a.it", algorithm="RSA-2048", verdict="FAIL")]
    out = batch_diff.compare_batches(prev, curr)
    assert "a.it" in out["unchanged"]
    assert "a.it" not in out["improved"]
    assert "a.it" not in out["regressed"]


def test_compare_batches_added_and_removed() -> None:
    prev = [_entry("a.it"), _entry("b.it")]
    curr = [_entry("b.it"), _entry("c.it")]
    out = batch_diff.compare_batches(prev, curr)
    assert "a.it" in out["removed"]
    assert "c.it" in out["added"]
    assert "b.it" in out["unchanged"]


def test_compare_batches_handles_error_entries() -> None:
    """An ``error`` stub on either side counts as 'unknown', not crash."""
    prev = [_entry("a.it", error="TimeoutError")]
    curr = [_entry("a.it", verdict="PASS")]
    out = batch_diff.compare_batches(prev, curr)
    # Going from error → PASS counts as improvement; the host was
    # measurable now, wasn't before.
    assert "a.it" in out["improved"]


def test_render_diff_markdown_contains_all_sections() -> None:
    prev = [_entry("a.it", verdict="FAIL"), _entry("b.it", verdict="PASS")]
    curr = [_entry("a.it", verdict="PASS"), _entry("b.it", verdict="FAIL"),
            _entry("c.it")]
    diff = batch_diff.compare_batches(prev, curr)
    md = batch_diff.render_diff_markdown(
        diff, before_label="2026-04", after_label="2026-05"
    )
    assert "improved" in md.lower() or "migliorati" in md.lower()
    assert "regressed" in md.lower() or "peggiorati" in md.lower()
    assert "a.it" in md
    assert "b.it" in md
    assert "c.it" in md
    # The two labels appear so the reader knows which snapshot is which.
    assert "2026-04" in md
    assert "2026-05" in md


def test_compare_batches_empty() -> None:
    out = batch_diff.compare_batches([], [])
    for key in ("improved", "regressed", "unchanged", "added", "removed"):
        assert out[key] == [], out
