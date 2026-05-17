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
# width AND colour. Two CI/local environment differences must be
# neutralised here:
#   * NO_COLOR=1 + TERM=dumb — on Linux/macOS Rich emits ANSI
#     escapes (e.g. ``\x1b[1;36m--csv\x1b[0m``) that fragment the
#     flag name and make the in-string substring check miss. On
#     Windows Rich already auto-detects "no TTY" and doesn't colour,
#     which is why the lock-in was passing locally but failing on
#     CI ubuntu/macOS. NO_COLOR is the no-color.org standard; TERM
#     is a belt-and-braces fallback for Rich versions that ignore
#     NO_COLOR.
# COLUMNS is intentionally NOT set: typer/CliRunner runs with no TTY,
# so Rich ignores the env var and falls back to its own 80-col
# default. Pass-through long flags (``--data-sensitivity-years``) get
# truncated to ``--data-sensitivity-yea…`` in the rendered panel.
# We tolerate that via :func:`_flag_present_in_help` below rather than
# fighting the rendering layer.
runner = CliRunner(env={"NO_COLOR": "1", "TERM": "dumb"})


def _flag_present_in_help(out: str, flag: str) -> bool:
    """Return True if ``flag`` appears in ``out``, tolerating Rich truncation.

    Rich truncates long option names with a horizontal ellipsis when
    the panel is narrower than the flag (e.g. ``--data-sensitivity-yea…``
    or ``--data-sensitivity-yea...`` depending on Rich version). The
    customer-visible CLI still accepts the FULL flag — the help-panel
    truncation is just a visual artifact — so the lock-in must accept
    a prefix-plus-ellipsis form as evidence the flag exists.

    Conservative heuristic: a truncation is accepted only when the
    prefix is at least 60% of the original flag length, otherwise the
    ambiguity is too high to count as a stable lock-in.
    """
    if flag in out:
        return True
    min_prefix = max(len(flag) // 2 + 3, 8)
    for marker in ("…", "..."):
        for cut in range(len(flag) - 1, min_prefix - 1, -1):
            if (flag[:cut] + marker) in out:
                return True
    return False


@pytest.mark.parametrize(
    "subcommand,required_options",
    [
        (
            ["batch", "--help"],
            [
                "--targets",
                "--csv",
                "--policy",
                "--enforce",
                "--concurrency",
                "--fail-on-violations",
                "--out",
            ],
        ),
        (
            ["batch-diff", "--help"],
            ["--before", "--after", "--out", "--before-label", "--after-label"],
        ),
        (
            ["scan", "tls", "--help"],
            ["--host", "--port", "--policy", "--data-sensitivity-years", "--enforce"],
        ),
        (["scan", "certs", "--help"], ["--path", "--policy", "--data-sensitivity-years"]),
        (["scan", "ssh", "--help"], ["--host", "--port", "--policy", "--data-sensitivity-years"]),
        (["report", "--help"], ["--input", "--format", "--output"]),
        (["cbom", "--help"], ["--input", "--output"]),
    ],
)
def test_cli_options_stable(subcommand: list[str], required_options: list[str]) -> None:
    """Each documented option must appear in the subcommand --help."""
    result = runner.invoke(app, subcommand)
    assert result.exit_code == 0, f"--help failed: {result.stdout + result.stderr}"
    out = result.stdout
    missing = [opt for opt in required_options if not _flag_present_in_help(out, opt)]
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


def test_version_flag_long_form() -> None:
    """``pqc-audit --version`` deve stampare la versione e uscire 0."""
    from pqc_audit import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_flag_short_form() -> None:
    """``pqc-audit -V`` deve essere alias di --version."""
    from pqc_audit import __version__

    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_version_subcommand_still_works() -> None:
    """``pqc-audit version`` (subcomando legacy) resta supportato."""
    from pqc_audit import __version__

    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
