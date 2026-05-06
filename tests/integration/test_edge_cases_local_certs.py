"""Integration tests — real-world edge cases via local TLS server.

Closes gaps the existing local-server tests didn't cover:

1. **Expired certificate**: ``not_valid_after`` in the past — the
   auditor must surface it as a finding even though the handshake
   *would* fail in a strict client. Our scanner uses the
   handshake-with-no-verify path so it can still inspect a cert that
   real browsers reject; that's a feature for triage, not a bug.

2. **SHA-1 signature**: still occasionally seen in legacy PA
   environments (especially internal CAs). NIST has deprecated
   SHA-1 since 2011 and AgID forbids it from 2026. The audit
   must surface it as a vulnerability.

3. **RSA-1024 key**: classic deprecated key size — way below the
   AgID 2048-bit floor. Must be flagged as a high-severity
   classical-cryptography vulnerability, separately from the
   quantum-vulnerability flag.

The fixture is a self-signed server in each case. We don't try to
mimic chain validation — that's a different layer.
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


def _make_cert(
    out_dir: Path,
    *,
    key_alg: str = "rsa2048",
    sig_hash: str = "sha256",
    valid_from_offset_days: int = -1,
    valid_to_offset_days: int = 30,
) -> tuple[Path, Path]:
    """Build a self-signed cert with the given knobs.

    ``key_alg``:
        ``"rsa2048"`` (default) | ``"rsa1024"``
    ``sig_hash``:
        ``"sha256"`` (default) | ``"sha1"``
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    out_dir.mkdir(parents=True, exist_ok=True)

    if key_alg == "rsa2048":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_alg == "rsa1024":
        # Deliberately weak — we need a vulnerable target to exercise
        # the auditor's classical-strength path. Real production code
        # MUST NOT generate 1024-bit keys.
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    else:
        raise ValueError(f"unsupported key_alg: {key_alg}")

    if sig_hash == "sha256":
        hasher: hashes.HashAlgorithm = hashes.SHA256()
    elif sig_hash == "sha1":
        hasher = hashes.SHA1()  # noqa: S303 — intentional, we test detection
    else:
        raise ValueError(f"unsupported sig_hash: {sig_hash}")

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
        .not_valid_before(datetime.now(UTC) + timedelta(days=valid_from_offset_days))
        .not_valid_after(datetime.now(UTC) + timedelta(days=valid_to_offset_days))
        .add_extension(san, critical=False)
        .sign(key, hasher)
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
    # Accept SHA-1-signed certs the modern stdlib would otherwise
    # refuse on the *server* side — we want to surface them, not
    # block them at the listener.
    ctx.set_ciphers("DEFAULT")

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
def test_scanner_flags_expired_certificate(tmp_path: Path) -> None:
    """Cert with ``not_valid_after`` 30 days in the past surfaces a finding."""
    from pqc_audit import Auditor, ScanTarget

    key_path, cert_path = _make_cert(
        tmp_path / "expired",
        valid_from_offset_days=-60,
        valid_to_offset_days=-30,  # expired
    )
    host, port, served = _serve_one_handshake(cert_path, key_path)

    auditor = Auditor(policy="agid_2026", data_sensitivity_years=15)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))

    # The handshake may or may not complete depending on stdlib
    # validation; what matters is that we surface SOMETHING actionable.
    sr = report.scan_results[0]
    titles = " ".join(v.title.lower() for v in sr.vulnerabilities)
    descriptions = " ".join((v.description or "").lower() for v in sr.vulnerabilities)
    msg = " ".join(sr.errors).lower() + " " + titles + " " + descriptions
    # At least one signal of "expiry" must be present in either a
    # vulnerability title/description or a scan error.
    expiry_signal = (
        "expired" in msg or "not_valid_after" in msg or "validity" in msg or "scaduto" in msg
    )
    assert expiry_signal, (
        f"expected an expiry signal; got titles={titles!r}, "
        f"descriptions={descriptions!r}, errors={sr.errors!r}"
    )

    served.wait(timeout=2.0)


@pytest.mark.integration
def test_scanner_flags_sha1_signature(tmp_path: Path) -> None:
    """Cert signed with SHA-1 surfaces a weak-hash finding."""
    from pqc_audit import Auditor, ScanTarget

    try:
        key_path, cert_path = _make_cert(tmp_path / "sha1", sig_hash="sha1")
    except Exception as exc:  # pragma: no cover — cryptography may refuse
        pytest.skip(f"SHA-1 cert generation unsupported by cryptography: {exc}")
    host, port, served = _serve_one_handshake(cert_path, key_path)

    auditor = Auditor(policy="agid_2026", data_sensitivity_years=15)
    target = ScanTarget(type="tls", host=host, port=port)
    report = asyncio.run(auditor.scan([target]))

    sr = report.scan_results[0]
    if not sr.assets:
        pytest.skip(
            "Stdlib refused SHA-1 cert at handshake time — "
            f"errors={sr.errors!r}; the offline cert_scanner path covers SHA-1."
        )

    # Either the asset metadata reflects SHA-1 or one of the
    # vulnerabilities specifically calls out a weak hash.
    asset = sr.assets[0]
    sig_hash = asset.metadata.get("signature_hash", "").upper()
    titles = " ".join(v.title.lower() for v in sr.vulnerabilities)
    descriptions = " ".join((v.description or "").lower() for v in sr.vulnerabilities)
    assert (
        ("SHA-1" in sig_hash)
        or ("sha-1" in titles)
        or ("weak" in titles)
        or ("hash" in descriptions and "deprecated" in descriptions)
    ), (
        f"expected SHA-1 signal; got sig_hash={sig_hash!r}, "
        f"titles={titles!r}, descriptions={descriptions!r}"
    )

    served.wait(timeout=2.0)


@pytest.mark.integration
def test_scanner_flags_rsa_1024_key_offline(tmp_path: Path) -> None:
    """RSA-1024 cert surfaces classical-strength findings via cert_scanner.

    Stdlib SSL refuses RSA-1024 server certs (``EE_KEY_TOO_SMALL``)
    so we can't drive this through the live TLS path. The offline
    file-based path (``CertificateScanner``) doesn't have that
    constraint and is the realistic deployment scenario anyway:
    customers frequently bulk-audit cert directories on the
    filesystem (PKI exports, ACM dumps, Vault PKI snapshots).
    """
    from pqc_audit import Auditor, ScanTarget
    from pqc_audit.scanners.cert_scanner import CertificateScanner

    try:
        _key_path, cert_path = _make_cert(tmp_path / "rsa1024", key_alg="rsa1024")
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"RSA-1024 unsupported: {exc}")

    # Auditor's default is the TLS scanner only — for a file-based
    # cert target we have to register the CertificateScanner.
    auditor = Auditor(
        policy="agid_2026",
        data_sensitivity_years=15,
        scanners=[CertificateScanner()],
    )
    target = ScanTarget(type="certs", path=str(cert_path))
    report = asyncio.run(auditor.scan([target]))

    sr = report.scan_results[0]
    assert sr.assets, f"expected one asset; got errors={sr.errors!r}"
    asset = sr.assets[0]
    assert asset.algorithm.name == "RSA"
    assert asset.algorithm.key_size_bits == 1024

    # At minimum: undersized classical signal AND quantum-vulnerable.
    titles = " ".join(v.title.lower() for v in sr.vulnerabilities)
    descriptions = " ".join((v.description or "").lower() for v in sr.vulnerabilities)
    full_text = titles + " " + descriptions
    assert "1024" in full_text or "undersized" in full_text, (
        f"expected RSA-1024 undersized signal; got titles={titles!r}, descriptions={descriptions!r}"
    )
    assert "quantum" in titles, f"expected quantum signal; got {titles!r}"

    # Policy verdict must FAIL on agid_2026 (RSA-1024 < 2048 floor).
    evaluation = auditor.evaluate_against_policy(report)
    assert evaluation.overall_verdict == "FAIL", evaluation
