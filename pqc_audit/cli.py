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
from pqc_audit.batch import (
    parse_csv,
    parse_inline_targets,
    run_batch,
    summarize_one,
)
from pqc_audit.batch import (
    render_markdown as render_batch_markdown,
)
from pqc_audit.batch_diff import compare_batches, render_diff_markdown
from pqc_audit.core.models import AuditReport, RiskLevel
from pqc_audit.reporters.cbom_reporter import render as render_cbom
from pqc_audit.reporters.html_batch_reporter import render as render_html_batch
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
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
    enforce: bool = typer.Option(
        False,
        "--enforce",
        help="Evaluate the report against --policy and embed policy_evaluation in JSON.",
    ),
) -> None:
    """Scan a single TLS endpoint and print a JSON audit report."""
    auditor = Auditor(policy=policy, data_sensitivity_years=data_sensitivity_years)
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
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan one or more X.509 certificate files (PEM/DER) and emit a JSON report."""
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[CertificateScanner()],
    )
    target = ScanTarget(type="certs", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("ssh")
def scan_ssh_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP of the SSH server."),
    port: int = typer.Option(22, "--port", help="TCP port (default: 22)."),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a single SSH endpoint (KEXINIT enumeration) and emit a JSON report."""
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[SSHScanner()],
    )
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
        # Already guarded above (--format pdf requires --output) but
        # we make the invariant explicit at runtime so the type
        # narrowing survives ``python -O``.
        if output is None:  # pragma: no cover — guard above already exits
            raise typer.Exit(code=2)
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


@app.command("batch")
def batch_cmd(
    targets: str | None = typer.Option(
        None,
        "--targets",
        help='Comma-separated host[:port] list, e.g. "a.example,b.example:8443".',
    ),
    csv_path: str | None = typer.Option(
        None,
        "--csv",
        help="CSV file with one host per row (host[,port[,scope]]).",
    ),
    policy: str = typer.Option(
        "agid_2026",
        "--policy",
        help="Audit policy name applied to every target.",
    ),
    data_sensitivity_years: int = typer.Option(
        15,
        "--data-sensitivity-years",
        help="HNDL sensitivity window in years (default: 15).",
    ),
    enforce: bool = typer.Option(
        False,
        "--enforce",
        help="Embed policy_evaluation in each per-host report.",
    ),
    concurrency: int = typer.Option(
        1,
        "--concurrency",
        "-j",
        help=(
            "Max scans in flight at once. ``1`` (default) is strict "
            "sequential. Higher values speed up large portfolios but "
            "stress shared rate limits and DNS resolvers."
        ),
        min=1,
        max=32,
    ),
    fail_on_violations: bool = typer.Option(
        False,
        "--fail-on-violations",
        help=(
            "CI gate: exit with code 3 if at least one host fails the "
            "policy (verdict FAIL or scan error). Reports are still "
            "written so the build can publish them."
        ),
    ),
    out_dir: str = typer.Option(
        ...,
        "--out",
        "-o",
        help="Output directory (created if missing).",
    ),
) -> None:
    """Run a TLS PQC audit across many hosts in one shot.

    Emits two files in ``--out``:

    - ``batch_report.md``   — Italian executive summary table
    - ``batch_report.json`` — list of full per-host audit dicts
    """
    if not targets and not csv_path:
        typer.echo(
            "error: either --targets or --csv is required.",
            err=True,
        )
        raise typer.Exit(code=2)
    if targets and csv_path:
        typer.echo(
            "error: --targets and --csv are mutually exclusive.",
            err=True,
        )
        raise typer.Exit(code=2)

    if targets:
        target_list = parse_inline_targets(targets)
    else:
        # csv_path is non-None here: the mutex check above ensures
        # exactly one of --targets / --csv is supplied. Make the
        # invariant survive ``python -O``.
        if csv_path is None:  # pragma: no cover — mutex above
            raise typer.Exit(code=2)
        target_list = parse_csv(Path(csv_path))

    if not target_list:
        typer.echo("error: no targets parsed from input.", err=True)
        raise typer.Exit(code=2)

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    pairs = asyncio.run(
        run_batch(
            target_list,
            policy=policy,
            sensitivity=data_sensitivity_years,
            enforce=enforce,
            concurrency=concurrency,
        )
    )
    rows = [summarize_one(t.host, r) for t, r in pairs]
    md = render_batch_markdown(
        rows,
        policy=policy,
        sensitivity=data_sensitivity_years,
        enforce=enforce,
    )
    html = render_html_batch(
        rows,
        policy=policy,
        sensitivity=data_sensitivity_years,
        enforce=enforce,
    )
    (out_path / "batch_report.md").write_text(md, encoding="utf-8")
    (out_path / "batch_report.json").write_text(
        json.dumps([r for _, r in pairs], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_path / "batch_report.html").write_text(html, encoding="utf-8")
    typer.echo(f"wrote {out_path / 'batch_report.md'}")
    typer.echo(f"wrote {out_path / 'batch_report.json'}")
    typer.echo(f"wrote {out_path / 'batch_report.html'}")

    if fail_on_violations:
        # Trip the CI gate when ANY row reports an error or a FAIL verdict.
        bad = sum(
            1 for r in rows if r.get("status") == "error" or r.get("policy_verdict") == "FAIL"
        )
        if bad:
            typer.echo(
                f"--fail-on-violations: {bad} host(s) failed — exiting 3.",
                err=True,
            )
            raise typer.Exit(code=3)


@app.command("batch-diff")
def batch_diff_cmd(
    before: str = typer.Option(
        ...,
        "--before",
        help="Previous batch_report.json snapshot (the older one).",
    ),
    after: str = typer.Option(
        ...,
        "--after",
        help="Current batch_report.json snapshot (the newer one).",
    ),
    out: str = typer.Option(
        ...,
        "--out",
        "-o",
        help="Destination Markdown file for the delta report.",
    ),
    before_label: str | None = typer.Option(
        None,
        "--before-label",
        help="Label for the BEFORE snapshot (default: filename stem).",
    ),
    after_label: str | None = typer.Option(
        None,
        "--after-label",
        help="Label for the AFTER snapshot (default: filename stem).",
    ),
) -> None:
    """Compare two ``batch_report.json`` snapshots and emit a delta report.

    Use case: re-run the same ``pqc-audit batch`` every month, save
    the resulting JSON, and feed two of those into this command to
    surface adoption trends — what improved, what regressed, what
    hosts entered or left the portfolio.
    """
    before_path = Path(before)
    after_path = Path(after)
    if not before_path.is_file():
        typer.echo(f"error: --before file not found: {before_path}", err=True)
        raise typer.Exit(code=2)
    if not after_path.is_file():
        typer.echo(f"error: --after file not found: {after_path}", err=True)
        raise typer.Exit(code=2)

    prev = json.loads(before_path.read_text(encoding="utf-8"))
    curr = json.loads(after_path.read_text(encoding="utf-8"))
    if not isinstance(prev, list) or not isinstance(curr, list):
        typer.echo(
            "error: each input must be a JSON list (output of `pqc-audit batch`).",
            err=True,
        )
        raise typer.Exit(code=2)

    diff = compare_batches(prev, curr)
    md = render_diff_markdown(
        diff,
        before_label=before_label or before_path.stem,
        after_label=after_label or after_path.stem,
    )

    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    typer.echo(f"wrote {out_path}")


if __name__ == "__main__":
    app()
