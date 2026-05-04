"""Command-line entry point for pqc-audit-italia.

Implementation note: this module contains ONLY orchestration glue.
All real logic lives in :mod:`pqc_audit.core`, the scanners, the
classifiers, and the reporters — so it stays unit-testable without
spinning up a CLI runner.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path

import typer

from pqc_audit import Auditor, ScanTarget, __version__
from pqc_audit.core.models import AuditReport, RiskLevel
from pqc_audit.reporters.cbom_reporter import render as render_cbom
from pqc_audit.reporters.json_reporter import render as render_json
from pqc_audit.reporters.markdown_reporter import render as render_markdown
from pqc_audit.reporters.pdf_reporter import render as render_pdf
from pqc_audit.reporters.sarif_reporter import render as render_sarif
from pqc_audit.scanners.cert_scanner import CertificateScanner
from pqc_audit.scanners.ssh_scanner import SSHScanner

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
    enforce: bool = typer.Option(
        False,
        "--enforce",
        help="Evaluate the report against --policy and embed policy_evaluation in JSON.",
    ),
) -> None:
    """Scan a single TLS endpoint and print a JSON audit report."""
    auditor = Auditor(policy=policy)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    rendered = render_json(report, pretty=pretty)
    if enforce:
        evaluation = auditor.evaluate_against_policy(report)
        payload = json.loads(rendered)
        payload["policy_evaluation"] = json.loads(evaluation.model_dump_json())
        indent = 2 if pretty else None
        separators = None if pretty else (",", ":")
        rendered = json.dumps(
            payload, indent=indent, separators=separators, sort_keys=False, ensure_ascii=False
        )
    typer.echo(rendered)


@scan_app.command("certs")
def scan_certs_cmd(
    path: str = typer.Option(
        ..., "--path", help="Certificate file or directory to scan recursively."
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan one or more X.509 certificate files (PEM/DER) and emit a JSON report."""
    auditor = Auditor(policy=policy, scanners=[CertificateScanner()])
    target = ScanTarget(type="certs", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("ssh")
def scan_ssh_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP of the SSH server."),
    port: int = typer.Option(22, "--port", help="TCP port (default: 22)."),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a single SSH endpoint (KEXINIT enumeration) and emit a JSON report."""
    auditor = Auditor(policy=policy, scanners=[SSHScanner()])
    target = ScanTarget(type="ssh", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


_REPORT_FORMATS: tuple[str, ...] = ("json", "markdown", "sarif", "cbom", "pdf")


def _normalize_severity_in_payload(node: object) -> None:
    """Recursively rewrite ``severity`` fields from name strings to int.

    The JSON reporter serializes :class:`RiskLevel` as its uppercase name
    (HIGH, CRITICAL, ...) for diff readability. Pydantic v2 expects the
    underlying integer value when re-loading. We coerce here so that the
    JSON reporter output is always a valid input for the report command.
    """
    if isinstance(node, dict):
        sev = node.get("severity")
        if isinstance(sev, str):
            with contextlib.suppress(KeyError, ValueError):
                node["severity"] = RiskLevel.parse(sev).value
        for v in node.values():
            _normalize_severity_in_payload(v)
    elif isinstance(node, list):
        for v in node:
            _normalize_severity_in_payload(v)


def _load_audit_report(input_path: str) -> AuditReport:
    """Load an :class:`AuditReport` from a JSON file or ``-`` for stdin."""
    raw = sys.stdin.read() if input_path == "-" else Path(input_path).read_text(encoding="utf-8")
    payload = json.loads(raw)
    # Tolerate JSON-reporter convention of emitting RiskLevel as name.
    _normalize_severity_in_payload(payload)
    # ``summary`` and ``policy_evaluation`` are reporter-side decoration —
    # AuditReport doesn't accept them. Drop them silently.
    if isinstance(payload, dict):
        payload.pop("summary", None)
        payload.pop("policy_evaluation", None)
    return AuditReport.model_validate(payload)


def _render_text_format(fmt: str, report: AuditReport) -> str:
    if fmt == "json":
        return render_json(report, pretty=True)
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "sarif":
        return render_sarif(report)
    if fmt == "cbom":
        return render_cbom(report)
    raise ValueError(f"Unsupported text format: {fmt}")


@app.command("report")
def report_cmd(
    input_path: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON scan report (output of `scan tls/certs/ssh`). Use '-' for stdin.",
    ),
    fmt: str = typer.Option(
        "json",
        "--format",
        "-f",
        help=f"Output format. One of: {', '.join(_REPORT_FORMATS)}.",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file. Required for --format pdf. Defaults to stdout otherwise.",
    ),
) -> None:
    """Re-render a scan report in the requested format."""
    if fmt not in _REPORT_FORMATS:
        typer.echo(
            f"error: unsupported format '{fmt}'. Choose from: {', '.join(_REPORT_FORMATS)}.",
            err=True,
        )
        raise typer.Exit(code=2)
    if fmt == "pdf" and not output:
        typer.echo(
            "error: --format pdf requires --output FILE (binary content cannot stream to stdout).",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        report = _load_audit_report(input_path)
    except FileNotFoundError as e:
        typer.echo(f"error: cannot read --input: {e}", err=True)
        raise typer.Exit(code=1) from e
    except (ValueError, json.JSONDecodeError) as e:
        # pydantic raises ValidationError (subclass of ValueError) for shape
        # mismatches; json.JSONDecodeError for raw parse failures.
        typer.echo(f"error: invalid scan report payload: {e}", err=True)
        raise typer.Exit(code=2) from e

    if fmt == "pdf":
        try:
            pdf_bytes = render_pdf(report)
        except RuntimeError as e:
            typer.echo(f"error: {e}", err=True)
            raise typer.Exit(code=2) from e
        assert output is not None  # guarded above
        Path(output).write_bytes(pdf_bytes)
        return

    text = _render_text_format(fmt, report)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


@app.command("cbom")
def cbom_cmd(
    input_path: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON scan report (output of `scan tls/certs/ssh`). Use '-' for stdin.",
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Output file. Defaults to stdout."
    ),
) -> None:
    """Export findings as a CycloneDX 1.6 Cryptography Bill of Materials.

    Convenience alias for ``report --format cbom``.
    """
    try:
        report = _load_audit_report(input_path)
    except FileNotFoundError as e:
        typer.echo(f"error: cannot read --input: {e}", err=True)
        raise typer.Exit(code=1) from e
    except (ValueError, json.JSONDecodeError) as e:
        typer.echo(f"error: invalid scan report payload: {e}", err=True)
        raise typer.Exit(code=2) from e

    text = render_cbom(report)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


if __name__ == "__main__":
    app()
