"""End-to-end integration test — ``pqc-audit batch`` against a local TLS server.

Coverage gap closed: the unit tests in ``tests/unit/test_cli_batch.py``
exercise the typer runner against ``127.0.0.1:1`` (transport refused) so
they validate parsing and error-row rendering, but they never see the
auditor produce a *real* finding. This test stands up an honest TLS
listener with an RSA-2048 cert, runs the CLI in-process, and asserts on
the resulting Markdown / JSON / HTML triplet — including the new HTML
reporter introduced in Phase 6.5.

The point isn't another scanner test — the unit-level scanner tests
already cover RSA detection. The point is to lock the *wiring* between
the CLI, the batch runner, the summarizer, the policy engine, and the
HTML/Markdown reporters. A regression in any one of those would slip
past unit tests.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pqc_audit.cli import app


def _generate_self_signed_rsa(out_dir: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    out_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path = out_dir / "key.pem"
    cert_path = out_dir / "cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def _serve_one_handshake(
    cert_path: Path, key_path: Path
) -> tuple[str, int, threading.Event]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    host, port = sock.getsockname()
    served = threading.Event()

    def _runner() -> None:
        try:
            sock.settimeout(5.0)
            client, _ = sock.accept()
            try:
                with ctx.wrap_socket(client, server_side=True):
                    served.set()
            finally:
                client.close()
        except Exception:  # noqa: BLE001 — test harness, swallow
            served.set()
        finally:
            sock.close()

    threading.Thread(target=_runner, daemon=True).start()
    return host, port, served


@pytest.mark.integration
def test_batch_cli_against_local_server_emits_all_three(tmp_path: Path) -> None:
    """End-to-end: server up → CLI scan → md+json+html written, host
    visible in all three, RSA-2048 surfaced as classical-vulnerable."""
    runner = CliRunner()

    key_path, cert_path = _generate_self_signed_rsa(tmp_path / "tls")
    host, port, served = _serve_one_handshake(cert_path, key_path)

    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "batch",
            "--targets", f"{host}:{port}",
            "--policy", "agid_2026",
            "--enforce",
            "--out", str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout + result.stderr

    # All three artefacts present.
    md_path = out / "batch_report.md"
    json_path = out / "batch_report.json"
    html_path = out / "batch_report.html"
    assert md_path.exists()
    assert json_path.exists()
    assert html_path.exists()

    # JSON: one host with the actual scan_results, not an error stub.
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and len(payload) == 1
    entry = payload[0]
    assert "scan_results" in entry, entry
    assert "policy_evaluation" in entry, entry  # --enforce was on

    # The auditor saw an RSA-2048 asset against agid_2026 → must FAIL.
    pe = entry["policy_evaluation"]
    assert pe["overall_verdict"] == "FAIL", pe

    # Markdown: contains the host and the FAIL verdict cell.
    md = md_path.read_text(encoding="utf-8")
    assert host in md
    assert "FAIL" in md

    # HTML: contains the host (escaped or raw, both are acceptable for
    # a numeric IP) and a verdict-fail CSS hook.
    html = html_path.read_text(encoding="utf-8")
    assert host in html
    assert "verdict-fail" in html
    assert "<!doctype html>" in html or "<!DOCTYPE html>" in html

    served.wait(timeout=2.0)


@pytest.mark.integration
def test_batch_cli_fail_on_violations_exits_3(tmp_path: Path) -> None:
    """``--fail-on-violations`` against a host that fails the policy
    must trip exit code 3, while the artefacts must still be written
    so the CI build can publish them."""
    runner = CliRunner()

    key_path, cert_path = _generate_self_signed_rsa(tmp_path / "tls")
    host, port, served = _serve_one_handshake(cert_path, key_path)

    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "batch",
            "--targets", f"{host}:{port}",
            "--policy", "agid_2026",
            "--enforce",
            "--fail-on-violations",
            "--out", str(out),
        ],
    )
    assert result.exit_code == 3, (
        f"expected exit 3 on FAIL host with --fail-on-violations; "
        f"got {result.exit_code}\n{result.stdout}\n{result.stderr}"
    )
    # Artefacts written even on gate trip — that's the whole point.
    assert (out / "batch_report.md").exists()
    assert (out / "batch_report.json").exists()
    assert (out / "batch_report.html").exists()

    served.wait(timeout=2.0)
