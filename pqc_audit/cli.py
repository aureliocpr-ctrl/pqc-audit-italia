"""Command-line entry point for pqc-audit-italia.

Implementation note: this module contains ONLY orchestration glue.
All real logic lives in :mod:`pqc_audit.core`, the scanners, the
classifiers, and the reporters — so it stays unit-testable without
spinning up a CLI runner.
"""

from __future__ import annotations

import typer

from pqc_audit import __version__

app = typer.Typer(
    name="pqc-audit",
    help="Crypto-discovery and crypto-agility audit toolkit (Italian market).",
    no_args_is_help=True,
)


@app.command("version")
def version_cmd() -> None:
    """Print the installed pqc-audit-italia version."""
    typer.echo(__version__)


@app.command("scan")
def scan_cmd(
    target_type: str = typer.Argument(..., help="One of: tls, certs, ssh, vpn, fs, binary, code, config, token"),
) -> None:
    """Scan a target. Phase 1 stub — concrete scanners land in 0.2.0."""
    typer.echo(f"[stub] scan {target_type} — not yet implemented")
    raise typer.Exit(code=2)


@app.command("report")
def report_cmd() -> None:
    """Generate a report from a previous scan result. Phase 4 feature."""
    typer.echo("[stub] report — not yet implemented")
    raise typer.Exit(code=2)


@app.command("cbom")
def cbom_cmd() -> None:
    """Export findings as a CycloneDX 1.6 Cryptography Bill of Materials. Phase 4 feature."""
    typer.echo("[stub] cbom — not yet implemented")
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
