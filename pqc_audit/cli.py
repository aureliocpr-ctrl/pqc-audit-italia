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
from pqc_audit.compliance.nis2 import (
    SANCTION_ESSENTIAL_FINE_CAP_EUR,
    SANCTION_ESSENTIAL_TURNOVER_PCT,
    SANCTION_IMPORTANT_FINE_CAP_EUR,
    SANCTION_IMPORTANT_TURNOVER_PCT,
    apply_nis2_mapping,
    summarize_articles,
)
from pqc_audit.core.models import AuditReport, RiskLevel
from pqc_audit.reporters.cbom_reporter import render as render_cbom
from pqc_audit.reporters.html_batch_reporter import render as render_html_batch
from pqc_audit.reporters.json_reporter import render as render_json
from pqc_audit.reporters.markdown_reporter import render as render_markdown
from pqc_audit.reporters.pdf_reporter import render as render_pdf
from pqc_audit.reporters.sarif_reporter import render as render_sarif
from pqc_audit.scanners.cert_scanner import CertificateScanner
from pqc_audit.scanners.dnssec_scanner import DNSSECScanner
from pqc_audit.scanners.iac_scanner import IaCScanner
from pqc_audit.scanners.jwks_scanner import JWKSScanner
from pqc_audit.scanners.jwt_scanner import JWTScanner
from pqc_audit.scanners.mtls_scanner import MTLSScanner
from pqc_audit.scanners.saml_scanner import SAMLScanner
from pqc_audit.scanners.ssh_scanner import SSHScanner

app = typer.Typer(
    name="pqc-audit",
    help="Crypto-discovery and crypto-agility audit toolkit (Italian market).",
    no_args_is_help=True,
)
scan_app = typer.Typer(name="scan", help="Run a scanner against one or more targets.")
app.add_typer(scan_app, name="scan")


def _version_callback(value: bool) -> None:
    """Print version and exit, matching the conventional ``--version`` flag."""
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print the installed pqc-audit-italia version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Crypto-discovery and crypto-agility audit toolkit (Italian market)."""


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
    agid_tsl: bool = typer.Option(
        False,
        "--agid-tsl",
        help=(
            "Fetch the live AgID Trusted List (eIDAS) and cross-check the resolved "
            "trust anchor. Upgrades pedigree to 'qualified_it_tsp_verified_via_tsl' "
            "when the root is in the TSL; downgrades pattern-only matches when not."
        ),
    ),
) -> None:
    """Scan a single TLS endpoint and print a JSON audit report."""
    tls_scanner_kwargs: dict = {}
    if agid_tsl:
        from pqc_audit.compliance.agid_tsl import (  # noqa: PLC0415
            AgIDTSLFetchError,
            AgIDTSLParseError,
            fetch_agid_tsl,
            parse_agid_tsl,
        )
        from pqc_audit.scanners.tls_scanner import TLSScanner  # noqa: PLC0415

        try:
            xml_bytes = fetch_agid_tsl(timeout=30.0)
            tls_scanner_kwargs["agid_tsl_data"] = parse_agid_tsl(xml_bytes)
        except (AgIDTSLFetchError, AgIDTSLParseError) as exc:
            typer.echo(
                f"warning: --agid-tsl fetch/parse failed ({exc}); "
                "continuing without TSL enrichment",
                err=True,
            )
        auditor = Auditor(
            policy=policy,
            data_sensitivity_years=data_sensitivity_years,
            scanners=[TLSScanner(**tls_scanner_kwargs)],
        )
    else:
        auditor = Auditor(policy=policy, data_sensitivity_years=data_sensitivity_years)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    rendered = render_json(report, pretty=pretty)
    if enforce:
        evaluation = auditor.evaluate_against_policy(report)
        evaluation_dict = json.loads(evaluation.model_dump_json())
        payload = json.loads(rendered)
        # Emit the evaluation at the TOP level (JSON convention) AND
        # inside metadata.policy_evaluation so a downstream Markdown
        # render finds it without needing the CLI roundtrip transpose.
        payload["policy_evaluation"] = evaluation_dict
        payload.setdefault("metadata", {})["policy_evaluation"] = evaluation_dict
        indent = 2 if pretty else None
        separators = None if pretty else (",", ":")
        rendered = json.dumps(
            payload, indent=indent, separators=separators, sort_keys=False, ensure_ascii=False
        )
    typer.echo(rendered)


@scan_app.command("pqc-hybrid")
def scan_pqc_hybrid_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP to connect to."),
    port: int = typer.Option(443, "--port", help="TCP port (default: 443)."),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Probe a TLS endpoint for PQC hybrid key-exchange support.

    Runs three ``openssl s_client`` handshakes — one per IETF
    draft-ietf-tls-ecdhe-mlkem-04 hybrid named group
    (SecP256r1MLKEM768 0x11EB, X25519MLKEM768 0x11EC,
    SecP384r1MLKEM1024 0x11ED) — and reports which (if any) the
    server accepts. Requires ``openssl`` 3.5+ in PATH.
    """
    auditor = Auditor(policy=policy, data_sensitivity_years=data_sensitivity_years)
    target = ScanTarget(type="pqc-hybrid", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("pqc-mldsa-sig")
def scan_pqc_mldsa_sig_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP to connect to."),
    port: int = typer.Option(443, "--port", help="TCP port (default: 443)."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Probe a TLS 1.3 endpoint for ML-DSA signature_algorithms support.

    Runs three ``openssl s_client -sigalgs <MLDSA*>`` handshakes — one per
    draft-ietf-tls-mldsa-03 codepoint (MLDSA44 0x0904, MLDSA65 0x0905,
    MLDSA87 0x0906) — and reports the per-codepoint status
    (``supported`` / ``not_supported`` / ``error``). Requires
    ``openssl`` 3.5+ in PATH.

    SLH-DSA is intentionally NOT probed: no TLS 1.3 SignatureScheme
    codepoint is registered for SLH-DSA as of 2026-05-17 (only X.509
    via RFC 9909 and CMS via RFC 9814).
    """
    # Lazy import keeps openssl subprocess cost out of the top-level
    # CLI import — also reduces module-import time for users that
    # never invoke this subcommand.
    from pqc_audit.scanners.tls_pqc_sig import (  # noqa: PLC0415
        probe_all_mldsa_sigalgs,
    )

    results = probe_all_mldsa_sigalgs(host, port)
    payload: dict = {
        "host": host,
        "port": port,
        "probe": "tls13-signature-algorithms-mldsa",
        "reference": "draft-ietf-tls-mldsa-03",
        "results": results,
    }
    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, ensure_ascii=False))


@scan_app.command("postgres-ssl")
def scan_postgres_ssl_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP of the PostgreSQL server."),
    port: int = typer.Option(5432, "--port", help="TCP port (default: 5432)."),
    timeout: float = typer.Option(5.0, "--timeout", help="Socket timeout in seconds."),
    raw: bool = typer.Option(
        False, "--raw", help="Emit raw probe dict instead of full AuditReport."
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Probe PostgreSQL for SSL and emit a full AuditReport (Sprint 9j.3).

    PostgreSQL servers do NOT begin with a TLS ClientHello — a client
    must first send the 8-byte SSLRequest message. The server replies
    'S' (SSL supported) or 'N' (plaintext only).

    Default: the probe runs via PostgresSSLScanner inside the standard
    Auditor pipeline, so output is a full AuditReport JSON with a HIGH
    CWE-319 Vulnerability auto-mapped to D.Lgs. 138/2024 art. 24(2)(h)+(j)
    when SSL is not supported. Pass ``--raw`` for the probe dict only.
    """
    if raw:
        from pqc_audit.scanners.postgres_ssl import probe_postgres_ssl  # noqa: PLC0415

        result = probe_postgres_ssl(host, port, timeout=timeout)
        payload: dict = {
            "host": host,
            "port": port,
            "probe": "postgres-sslrequest",
            "reference": "https://www.postgresql.org/docs/current/protocol-message-formats.html",
            "result": result,
        }
        indent = 2 if pretty else None
        typer.echo(json.dumps(payload, indent=indent, ensure_ascii=False))
        return

    from pqc_audit.scanners.postgres_ssl import PostgresSSLScanner  # noqa: PLC0415

    auditor = Auditor(scanners=[PostgresSSLScanner()])
    target = ScanTarget(type="postgres-ssl", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("mysql-ssl")
def scan_mysql_ssl_cmd(
    host: str = typer.Option(..., "--host", help="Hostname or IP of the MySQL/MariaDB server."),
    port: int = typer.Option(3306, "--port", help="TCP port (default: 3306)."),
    timeout: float = typer.Option(5.0, "--timeout", help="Socket timeout in seconds."),
    raw: bool = typer.Option(
        False, "--raw", help="Emit raw probe dict instead of full AuditReport."
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Probe MySQL/MariaDB for SSL and emit a full AuditReport (Sprint 9j.3).

    MySQL servers speak first: on TCP connect they send the Initial
    Handshake Packet (Protocol::HandshakeV10) which advertises server
    capabilities. The CLIENT_SSL bit (0x0800, bit 11) inside
    capability_flags_1 indicates SSL support. Probe is purely
    passive — no perturbation.

    Default: probe runs via MySQLSSLScanner inside Auditor pipeline,
    output is a full AuditReport with HIGH CWE-319 Vulnerability
    auto-mapped to D.Lgs. 138/2024 art. 24(2)(h)+(j) when SSL is not
    supported. Pass ``--raw`` for the probe dict only.
    """
    if raw:
        from pqc_audit.scanners.mysql_ssl import probe_mysql_ssl  # noqa: PLC0415

        result = probe_mysql_ssl(host, port, timeout=timeout)
        payload: dict = {
            "host": host,
            "port": port,
            "probe": "mysql-handshake-v10-capability-flags",
            "reference": (
                "https://dev.mysql.com/doc/dev/mysql-server/latest/"
                "page_protocol_connection_phase_packets_protocol_handshake_v10.html"
            ),
            "result": result,
        }
        indent = 2 if pretty else None
        typer.echo(json.dumps(payload, indent=indent, ensure_ascii=False))
        return

    from pqc_audit.scanners.mysql_ssl import MySQLSSLScanner  # noqa: PLC0415

    auditor = Auditor(scanners=[MySQLSSLScanner()])
    target = ScanTarget(type="mysql-ssl", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


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


@scan_app.command("jwt")
def scan_jwt_cmd(
    path: str = typer.Option(
        ..., "--path", help="File containing JWT compact-form tokens (one per line)."
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a file of JWT / JOSE tokens and emit a JSON report.

    Each non-blank, non-comment line is parsed as a compact-form JWT.
    Signature verification and JWKS fetch are out of scope: this is a
    crypto-discovery pass focused on the declared JOSE ``alg``.
    """
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[JWTScanner()],
    )
    target = ScanTarget(type="token", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("dnssec")
def scan_dnssec_cmd(
    path: str = typer.Option(
        ...,
        "--path",
        help="DNS zone file or `dig +dnssec` output containing DNSKEY records.",
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a DNSSEC zone (DNSKEY records) and emit a JSON report.

    Algorithm numbers are mapped against the IANA DNSSEC registry and
    RFC 8624 implementation status. RRSIG/NSEC/CDS records covering
    DNSKEY are correctly ignored (regression target).
    """
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[DNSSECScanner()],
    )
    target = ScanTarget(type="config", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("saml")
def scan_saml_cmd(
    path: str = typer.Option(
        ..., "--path", help="SAML XML file (Response / Assertion / IdP metadata)."
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a SAML XML payload and emit a JSON report.

    The parser is XXE-safe (defusedxml). Each ``ds:SignatureMethod``,
    ``ds:DigestMethod`` and ``xenc:EncryptionMethod`` URI is mapped
    against the XMLDSig / XMLEnc registries (W3C, RFC 6931).
    """
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[SAMLScanner()],
    )
    target = ScanTarget(type="config", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("mtls")
def scan_mtls_cmd(
    path: str = typer.Option(
        ...,
        "--path",
        help="PEM-bundled client certificate chain (leaf first, then intermediates, root).",
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a mutual-TLS client certificate chain and emit a JSON report.

    Adds the structural mTLS checks on top of the shared TLS assessor:
    leaf ``digitalSignature`` Key Usage, leaf ``clientAuth`` Extended
    Key Usage, intermediate CA constraints, and chain consistency.
    """
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[MTLSScanner()],
    )
    target = ScanTarget(type="certs", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("iac")
def scan_iac_cmd(
    path: str = typer.Option(
        ...,
        "--path",
        help="Directory or single file containing IaC manifests (Terraform .tf, "
        "CloudFormation JSON/YAML, Kubernetes YAML).",
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan Infrastructure-as-Code manifests for quantum-vulnerable primitives.

    Walks the directory looking for ``*.tf``, ``*.yaml``, ``*.yml`` and
    ``*.json`` files and flags declarations of RSA-1024/2048/3072, ECC
    P-256/P-384, RC4, 3DES, MD5, SHA-1, TLS 1.0/1.1, etc. Scope is
    intentionally regex-based — see ``pqc_audit.scanners.iac_scanner``
    for the pattern catalog and v2 roadmap notes.
    """
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[IaCScanner()],
    )
    target = ScanTarget(type="iac", path=path)
    report = asyncio.run(auditor.scan([target]))
    typer.echo(render_json(report, pretty=pretty))


@scan_app.command("jwks")
def scan_jwks_cmd(
    url: str = typer.Option(
        None,
        "--url",
        help="HTTPS URL of a JWKS endpoint (e.g. https://example.com/.well-known/jwks.json).",
    ),
    path: str = typer.Option(
        None,
        "--path",
        help="Local JWKS JSON file (alternative to --url for airgapped audits).",
    ),
    policy: str = typer.Option("default", "--policy", help="Audit policy name."),
    data_sensitivity_years: int = typer.Option(
        10,
        "--data-sensitivity-years",
        help="Assumed lifetime of confidential data, drives HNDL scoring (default: 10).",
    ),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Scan a JSON Web Key Set (RFC 7517) and classify every key.

    Live fetches an HTTPS JWKS endpoint OR reads a local JSON file
    (one or the other, not both). HTTPS only; SSRF guard refuses any
    host that resolves to a private / loopback / link-local address;
    response is capped at 1 MiB. Each key's algorithm is classified
    and quantum-vulnerable primitives (RSA-2048/3072, ECDSA-P256/P384)
    are surfaced as HIGH findings per NIST IR 8547.
    """
    if not url and not path:
        raise typer.BadParameter("provide --url or --path")
    if url and path:
        raise typer.BadParameter("provide either --url or --path, not both")
    auditor = Auditor(
        policy=policy,
        data_sensitivity_years=data_sensitivity_years,
        scanners=[JWKSScanner()],
    )
    target = ScanTarget(type="jwks", host=url or None, path=path or None)
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
    """Load an :class:`AuditReport` from a JSON file or ``-`` for stdin.

    ``summary`` is a JSON-reporter-side decoration and gets dropped —
    AuditReport does not accept it.

    ``policy_evaluation`` is emitted at the top level by ``scan ...
    --enforce`` (CLI convention). It is *not* a field of AuditReport,
    but the Markdown reporter expects to find it inside
    ``report.metadata["policy_evaluation"]`` to render the compliance
    section. Without this transposition the Markdown ``## Compliance``
    block silently disappears when re-rendering an enforced JSON
    report (cycle 06/05 audit MAJOR finding).
    """
    raw = sys.stdin.read() if input_path == "-" else Path(input_path).read_text(encoding="utf-8")
    payload = json.loads(raw)
    # Tolerate JSON-reporter convention of emitting RiskLevel as name.
    _normalize_severity_in_payload(payload)
    extracted_policy_eval: object | None = None
    if isinstance(payload, dict):
        payload.pop("summary", None)
        extracted_policy_eval = payload.pop("policy_evaluation", None)
    report = AuditReport.model_validate(payload)
    if extracted_policy_eval is not None:
        new_metadata = dict(report.metadata)
        # If somebody already set metadata['policy_evaluation'] in the
        # source JSON, the top-level field wins — it represents the
        # most recent CLI ``--enforce`` evaluation.
        new_metadata["policy_evaluation"] = extracted_policy_eval
        report = report.model_copy(update={"metadata": new_metadata})
    return report


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


compliance_app = typer.Typer(
    name="compliance",
    help="Map audit findings to specific regulatory articles.",
)
app.add_typer(compliance_app, name="compliance")


@compliance_app.command("nis2")
def compliance_nis2_cmd(
    input_path: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON scan report (output of `scan tls/certs/ssh`). Use '-' for stdin.",
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Output Markdown file. Defaults to stdout."
    ),
) -> None:
    """Map every vulnerability in a scan report to NIS2 / D.Lgs. 138/2024
    art. 24(2) articles. Output is a Markdown table citing the Italian
    legal reference + the EU directive mirror.

    Unmapped findings are surfaced explicitly (no fabricated citation).
    """
    try:
        report = _load_audit_report(input_path)
    except FileNotFoundError as e:
        typer.echo(f"error: cannot read --input: {e}", err=True)
        raise typer.Exit(code=1) from e
    except (ValueError, json.JSONDecodeError) as e:
        typer.echo(f"error: invalid scan report payload: {e}", err=True)
        raise typer.Exit(code=2) from e

    mapping = apply_nis2_mapping(report)
    all_articles = [art for arts in mapping.values() for art in arts]
    summary = summarize_articles(all_articles)

    lines: list[str] = []
    lines.append(f"# NIS2 compliance mapping — report `{report.report_id}`")
    lines.append("")
    lines.append(
        "Mapping di ogni finding al **D.Lgs. 4 settembre 2024, n. 138** "
        "(recepimento NIS 2), articolo 24, comma 2, lettere (a)-(j). "
        "Le citazioni accanto rinviano alla Direttiva (UE) 2022/2555."
    )
    lines.append("")
    lines.append("## Articoli toccati dal report")
    lines.append("")
    if not summary:
        lines.append(
            "_Nessun finding mappato a un articolo NIS2 (controllare titoli "
            "delle vulnerability vs. le pattern in `pqc_audit.compliance.nis2`)._"
        )
    else:
        lines.append("| Articolo (Italia) | Tema | EU directive |")
        lines.append("|---|---|---|")
        for art in summary:
            lines.append(
                f"| **{art.legal_reference}** | {art.topic} "
                f"| {art.eu_directive_reference} |"
            )
    lines.append("")
    lines.append("## Mappatura per finding")
    lines.append("")
    lines.append("| Finding (titolo) | Articoli NIS2 |")
    lines.append("|---|---|")
    for title, arts in mapping.items():
        if not arts:
            cell = "_(unmapped — rivedere il titolo o aggiornare la mappatura)_"
        else:
            cell = "<br>".join(a.legal_reference for a in arts)
        lines.append(f"| {title} | {cell} |")
    lines.append("")
    lines.append("## Sanzioni")
    lines.append("")
    lines.append(
        f"- **Soggetti essenziali**: art. 38 D.Lgs. 138/2024 — fino a "
        f"**{SANCTION_ESSENTIAL_FINE_CAP_EUR:,} EUR** o "
        f"**{SANCTION_ESSENTIAL_TURNOVER_PCT}%** del fatturato mondiale annuo "
        "(si applica il valore più alto)."
    )
    lines.append(
        f"- **Soggetti importanti**: fino a "
        f"**{SANCTION_IMPORTANT_FINE_CAP_EUR:,} EUR** o "
        f"**{SANCTION_IMPORTANT_TURNOVER_PCT}%** del fatturato."
    )
    lines.append("")
    text = "\n".join(lines)
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        typer.echo(text)


@compliance_app.command("agid-tsl")
def compliance_agid_tsl_cmd(
    fetch: bool = typer.Option(
        True,
        "--fetch/--no-fetch",
        help="Fetch the live AgID TSL XML. Use --no-fetch with --input for offline parsing.",
    ),
    input_path: str | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Path to a pre-fetched AgID TSL XML file. Implies --no-fetch.",
    ),
    subject: str | None = typer.Option(
        None,
        "--check-subject",
        help="If set, verify this RFC 4514 subject DN against the qualified-CA list "
        "and emit a single 'in_tsl' boolean.",
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout in seconds."),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty-print JSON output."),
) -> None:
    """Fetch and inspect the AgID Trusted List (ETSI TS 119 612).

    The AgID TSL (https://eidas.agid.gov.it/TL/TSL-IT.xml) is the
    authoritative roster of qualified Trust Service Providers in
    Italy under eIDAS Regulation (EU) 910/2014.

    Default: HTTPS GET the live TSL, parse, and emit JSON with the
    full TSP name list + count of qualified-CA certificates.

    With ``--check-subject "CN=...,O=...,C=IT"``: cross-check the
    DN against the qualified-CA subjects in the TSL and report a
    binary verdict (canonical Name match, RDN-order / case /
    whitespace insensitive).

    For offline use (no network), pass ``--input /path/to/tsl.xml``.
    """
    from pqc_audit.compliance.agid_tsl import (  # noqa: PLC0415
        AGID_TSL_URL,
        AgIDTSLFetchError,
        AgIDTSLParseError,
        fetch_agid_tsl,
        is_subject_in_tsl,
        parse_agid_tsl,
    )

    if input_path:
        try:
            xml_bytes = Path(input_path).read_bytes()
        except OSError as exc:
            typer.echo(f"error: cannot read --input: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        source = input_path
    elif fetch:
        try:
            xml_bytes = fetch_agid_tsl(timeout=timeout)
        except AgIDTSLFetchError as exc:
            typer.echo(f"error: AgID TSL fetch failed: {exc}", err=True)
            raise typer.Exit(code=3) from exc
        source = AGID_TSL_URL
    else:
        typer.echo("error: pass --input <path> or --fetch", err=True)
        raise typer.Exit(code=2)

    try:
        tsl_data = parse_agid_tsl(xml_bytes)
    except AgIDTSLParseError as exc:
        typer.echo(f"error: AgID TSL parse failed: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    payload: dict = {
        "source": source,
        "tsp_count": len(tsl_data["tsps"]),
        "qualified_ca_count": len(tsl_data["qualified_certs"]),
        "tsps": tsl_data["tsps"],
    }
    if subject:
        payload["check_subject"] = subject
        payload["in_tsl"] = is_subject_in_tsl(subject, tsl_data)

    indent = 2 if pretty else None
    typer.echo(json.dumps(payload, indent=indent, ensure_ascii=False))



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


@app.command("hash")
def hash_cmd(
    input_path: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to a JSON scan report (output of `scan tls/certs/ssh/...`). Use '-' for stdin.",
    ),
) -> None:
    """Recompute the legal SHA-256 fingerprint of a report (Sprint 8 step A).

    A regulator or PA procurement reviewer reads the auditor's
    published digest, parses the report's JSON, then invokes::

        pqc-audit hash --input report.json

    and compares the printed digest to the published one. The 64-hex
    output is the SHA-256 of the byte-stable canonical JSON form of
    the parsed report — see ``pqc_audit.reporters.canonical`` for the
    canonicalization contract. Stdin is supported via ``-i -``.
    """
    from pqc_audit.reporters.canonical import report_sha256  # noqa: PLC0415

    if input_path == "-":
        payload_text = sys.stdin.read()
    else:
        try:
            payload_text = Path(input_path).read_text(encoding="utf-8")
        except FileNotFoundError as e:
            typer.echo(f"error: cannot read --input: {e}", err=True)
            raise typer.Exit(code=1) from e
    try:
        parsed = json.loads(payload_text)
    except json.JSONDecodeError as e:
        typer.echo(f"error: invalid JSON: {e}", err=True)
        raise typer.Exit(code=2) from e
    typer.echo(report_sha256(parsed))


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
