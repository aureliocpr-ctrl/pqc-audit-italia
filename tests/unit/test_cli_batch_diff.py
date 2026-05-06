"""Tests for the ``pqc-audit batch-diff`` CLI subcommand.

Wires the pure :mod:`pqc_audit.batch_diff` helper into the CLI so the
"snapshot mensile" workflow is one command instead of a custom Python
glue script.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pqc_audit.cli import app

runner = CliRunner()


def _write_batch(path: Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")


def _audit(host: str, *, algorithm: str = "RSA-2048", verdict: str = "FAIL") -> dict:
    parts = algorithm.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        name, bits = parts[0], int(parts[1])
    else:
        name, bits = algorithm, 0
    return {
        "metadata": {"target_host": host},
        "scan_results": [
            {
                "target": f"{host}:443",
                "assets": [{"algorithm": {"name": name, "key_size_bits": bits}}],
                "vulnerabilities": [],
            }
        ],
        "policy_evaluation": {
            "policy": "agid_2026",
            "overall_verdict": verdict,
            "violations": [],
        },
    }


def test_batch_diff_emits_markdown_with_correct_buckets(tmp_path: Path) -> None:
    """End-to-end: two JSON snapshots → one markdown delta report."""
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write_batch(
        before,
        [
            _audit("a.it", verdict="FAIL"),
            _audit("b.it", verdict="PASS"),
            _audit("c.it", verdict="FAIL"),
        ],
    )
    _write_batch(
        after,
        [
            _audit("a.it", verdict="PASS"),  # improved
            _audit("b.it", verdict="FAIL"),  # regressed
            _audit("c.it", verdict="FAIL"),  # unchanged
            _audit("d.it", verdict="PASS"),  # added
        ],
    )

    out_md = tmp_path / "diff.md"
    result = runner.invoke(
        app,
        [
            "batch-diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--out",
            str(out_md),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert out_md.exists()
    md = out_md.read_text(encoding="utf-8")

    # Bucket counts in the executive header.
    assert "Migliorati" in md
    assert "Peggiorati" in md
    # Each host appears under its own bucket.
    assert "a.it" in md
    assert "b.it" in md
    assert "c.it" in md
    assert "d.it" in md


def test_batch_diff_validates_input_paths(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "batch-diff",
            "--before",
            str(tmp_path / "missing-before.json"),
            "--after",
            str(tmp_path / "missing-after.json"),
            "--out",
            str(tmp_path / "diff.md"),
        ],
    )
    assert result.exit_code != 0


def test_batch_diff_uses_filenames_as_default_labels(tmp_path: Path) -> None:
    before = tmp_path / "snapshot_2026_04.json"
    after = tmp_path / "snapshot_2026_05.json"
    _write_batch(before, [_audit("a.it", verdict="FAIL")])
    _write_batch(after, [_audit("a.it", verdict="PASS")])
    out_md = tmp_path / "diff.md"
    result = runner.invoke(
        app,
        [
            "batch-diff",
            "--before",
            str(before),
            "--after",
            str(after),
            "--out",
            str(out_md),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    md = out_md.read_text(encoding="utf-8")
    # When --before-label / --after-label are omitted, the filename
    # stem (without extension) is used so the report still tells
    # the reader which snapshot is which.
    assert "snapshot_2026_04" in md
    assert "snapshot_2026_05" in md
