"""Lock-in test on the CLI argument signature.

Customers integrate ``pqc-audit batch`` / ``batch-diff`` /
``scan tls`` in CI/CD pipelines (GitHub Actions, GitLab CI). A
silent rename of an option (``--targets`` → ``--target``,
``--out`` → ``--output``) breaks every customer pipeline at
push.

This test asserts that the documented option names appear in
``--help`` output. If you legitimately rename an option, update
both this lock-in AND the CHANGELOG MIGRATION section.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from pqc_audit.cli import app

# typer renders --help inside a Rich panel that adapts to terminal
# width. On narrow widths (default 80 cols on CI) long flag names
# get truncated like ``--data-sensitivity-ye…``. Pin a wider terminal
# so the lock-in matches the full flag name.
runner = CliRunner(env={"COLUMNS": "200"})


@pytest.mark.parametrize(
    "subcommand,required_options",
    [
        (["batch", "--help"], ["--targets", "--csv", "--policy", "--enforce",
                                "--concurrency", "--fail-on-violations", "--out"]),
        (["batch-diff", "--help"], ["--before", "--after", "--out",
                                     "--before-label", "--after-label"]),
        (["scan", "tls", "--help"], ["--host", "--port", "--policy",
                                       "--data-sensitivity-years", "--enforce"]),
        (["scan", "certs", "--help"], ["--path", "--policy",
                                         "--data-sensitivity-years"]),
        (["scan", "ssh", "--help"], ["--host", "--port", "--policy",
                                       "--data-sensitivity-years"]),
        (["report", "--help"], ["--input", "--format", "--output"]),
        (["cbom", "--help"], ["--input", "--output"]),
    ],
)
def test_cli_options_stable(subcommand: list[str], required_options: list[str]) -> None:
    """Each documented option must appear in the subcommand --help."""
    result = runner.invoke(app, subcommand)
    assert result.exit_code == 0, f"--help failed: {result.stdout + result.stderr}"
    out = result.stdout
    missing = [opt for opt in required_options if opt not in out]
    assert not missing, (
        f"CLI option(s) {missing} missing from `pqc-audit {' '.join(subcommand[:-1])}` "
        f"--help output. Renaming a flag is a breaking change for customer "
        f"CI pipelines — update the CHANGELOG MIGRATION section if intentional."
    )


def test_top_level_help_lists_all_subcommands() -> None:
    """``pqc-audit --help`` must list every subcommand customers depend on."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    out = result.stdout
    for sub in ("scan", "report", "batch", "batch-diff", "cbom", "version"):
        assert sub in out, f"subcommand {sub!r} missing from top-level --help"
