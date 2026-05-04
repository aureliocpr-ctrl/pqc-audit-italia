"""Integration test — TLSScanner end-to-end against a local SSL server.

This test spins a tiny stdlib SSL listener on 127.0.0.1, presents a
freshly minted RSA-2048 certificate, lets ``TLSScanner.scan`` connect
and parse it, and verifies the resulting AuditReport contains the
expected risk classification and recommendation.

It is offline (no DNS, no internet) and runs in <1s, but it is the
only test exercising the real socket + ssl path of the scanner. Kept
under ``tests/integration`` so unit-only runs (``pytest tests/unit``)
stay fast.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


def _generate_self_signed_rsa(out_dir: Path) -> tuple[Path, Path]:
    """Write key.pem + cert.pem (RSA-2048 / SHA-256) to ``out_dir``.

    Returns the (key_path, cert_path) pair.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
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


def _serve_one_handshake(cert_path: Path, key_path: Path) -> tuple[str, int, threading.Event]:
    """Start a one-shot TLS listener on a free port. Returns host/port + a
    threading event that fires once the handshake has been served.
    """
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
def test_tls_scanner_against_local_server(tmp_path: Path) -> None:
    """End-to-end: build cert, serve TLS, scan it, verify enriched report."""
    from pqc_audit import Auditor, ScanTarget

    key_path, cert_path = _generate_self_signed_rsa(tmp_path)
    host, port, served = _serve_one_handshake(cert_path, key_path)

    auditor = Auditor(policy="agid_2026", data_sensitivity_years=15)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))

    # The single scan_result should have one asset (the local cert) and
    # no fatal errors.
    assert len(report.scan_results) == 1
    sr = report.scan_results[0]
    assert sr.scanner_name == "tls"
    assert len(sr.assets) == 1, f"unexpected errors: {sr.errors}"

    asset = sr.assets[0]
    assert asset.algorithm.name == "RSA"
    assert asset.algorithm.key_size_bits == 2048
    assert asset.metadata.get("tls_version", "").startswith("TLSv1.")
    assert asset.metadata.get("signature_hash") == "SHA-256"

    # Vulnerability assessment fired.
    titles = [v.title.lower() for v in sr.vulnerabilities]
    assert any("quantum" in t for t in titles)
    assert any("self-signed" in t for t in titles)

    # Risk enrichment populated.
    risk = report.metadata["risk_summary"]
    assert risk["asset_count"] == 1
    assert risk["vulnerable_count"] == 1
    assert risk["hndl_max"] >= 70
    assert risk["qday_max"] >= 70

    # At least one migration recommendation for the RSA finding.
    recs_from = {r.from_algorithm for r in report.recommendations}
    assert "RSA-2048" in recs_from

    # Wait so the daemon thread is allowed to finish cleanly.
    served.wait(timeout=2.0)
