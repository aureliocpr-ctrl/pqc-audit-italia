"""Command-line entry point for pqc-audit-italia.

Implementation note: this module contains ONLY orchestration glue.
All real logic lives in :mod:`pqc_audit.core`, the scanners, the
classifiers, and the reporters — so it stays unit-testable without
spinning up a CLI runner.
"""

from __future__ import annotations

import asyncio

import typer

from pqc_audit import Auditor, ScanTarget, __version__
from pqc_audit.reporters.json_reporter import render as render_json

app = typer.Typer(
    name="pqc-audit",
    help="Crypto-discovery and crypto-agility audit toolkit (Italian market).",
    no_args_is_help=True,
)
scan_app = typer.Typer(name="scan", help="Run a scanner against one or more targets.")
app.add_typer(scan_app, name="scan")


@app.command("version")
def version_cmd() -> None:
    """Print the installed pqc-audit-italia version."""
    typer.echo(__version__)


@scan_app.command("tls")
def scan_tls_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP to connect to."),
    port: int = typer.Option(443, "--port", help="TCP port (default: 443)."),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a single TLS endpoint and print a JSON audit report."""
    auditor = Auditor(policy=policy)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("certs")
def scan_certs_cmd() -> None:
    """Scan a directory of certificate files. Phase 1.e feature — coming soon."""
    typer.echo("[stub] scan certs — implemented in Phase 1.e")
    raise typer.Exit(code=2)


@scan_app.command("ssh")
def scan_ssh_cmd() -> None:
    """Scan an SSH endpoint. Phase 1.e feature — coming soon."""
    typer.echo("[stub] scan ssh — implemented in Phase 1.e")
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
