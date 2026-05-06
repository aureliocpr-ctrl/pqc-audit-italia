"""Integration test — TLSScanner end-to-end with an ECDSA-P256 cert.

The PA italiana surface tends to favour ECDSA-P256 over RSA-2048 (see
``docs/pentest/pqc_audit_2026_05_05/pa_vs_bigtech_pqc_readiness.md``).
The original local-server integration test only exercises RSA, which
left a blind spot: the auditor's recommendation pipeline (P5 ML-DSA-65
hybrid intermediate) for ECDSA-256 had no end-to-end coverage. This
test plugs that gap.

Stays offline (no DNS, no internet), runs in <1s, and asserts on
algorithm classification, vulnerability surfacing, and the migration
recommendation that drives the executive deliverable.
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


def _generate_self_signed_ecdsa(out_dir: Path) -> tuple[Path, Path]:
    """Write key.pem + cert.pem (ECDSA P-256 / SHA-256) to ``out_dir``."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
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
def test_tls_scanner_ecdsa_p256_against_local_server(tmp_path: Path) -> None:
    """ECDSA P-256 → algorithm class identified, P5 reco materialises."""
    from pqc_audit import Auditor, ScanTarget

    key_path, cert_path = _generate_self_signed_ecdsa(tmp_path)
    host, port, served = _serve_one_handshake(cert_path, key_path)

    auditor = Auditor(policy="agid_2026", data_sensitivity_years=15)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))

    assert len(report.scan_results) == 1
    sr = report.scan_results[0]
    assert sr.scanner_name == "tls"
    assert len(sr.assets) == 1, f"unexpected errors: {sr.errors}"

    asset = sr.assets[0]
    assert asset.algorithm.name == "ECDSA"
    assert asset.algorithm.key_size_bits == 256
    assert asset.algorithm.curve == "secp256r1"

    # Quantum-vulnerability fires regardless of the classical-strength
    # of secp256r1 — Shor breaks ECDSA the same as RSA.
    titles = [v.title.lower() for v in sr.vulnerabilities]
    assert any("quantum" in t for t in titles), titles

    # Risk enrichment: HNDL/Q-Day populated for the ECDSA finding.
    risk = report.metadata["risk_summary"]
    assert risk["asset_count"] == 1
    assert risk["vulnerable_count"] == 1
    assert risk["hndl_max"] >= 60, risk

    # The migration recommendation must propose a NIST PQC signature
    # algorithm (ML-DSA family). Hybrid intermediate is acceptable.
    assert report.recommendations, "expected at least one P5 recommendation"
    recs_to = " ".join(r.to_algorithm.upper() for r in report.recommendations)
    assert "ML-DSA" in recs_to or "MLDSA" in recs_to, recs_to

    # Source side reflects the actual ECDSA-256 finding.
    recs_from = {r.from_algorithm.upper() for r in report.recommendations}
    assert any(("ECDSA" in s) for s in recs_from), recs_from

    served.wait(timeout=2.0)
