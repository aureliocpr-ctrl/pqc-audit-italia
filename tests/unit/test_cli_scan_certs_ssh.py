"""CLI tests for ``pqc-audit scan certs`` and ``pqc-audit scan ssh``."""

from __future__ import annotations

import contextlib
import json
import socket
import struct
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from pqc_audit.cli import app

runner = CliRunner()


def _write_self_signed_rsa(out_path: Path, *, key_size: int = 2048) -> Path:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cli.example.it")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    out_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return out_path


def test_scan_certs_against_pem_file_returns_valid_json(tmp_path: Path) -> None:
    cert_path = _write_self_signed_rsa(tmp_path / "rsa2048.pem", key_size=2048)
    result = runner.invoke(app, ["scan", "certs", "--path", str(cert_path), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    assert parsed["report_id"]
    assert parsed["scan_results"]
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "certs"
    assert len(sr["assets"]) == 1
    assert sr["assets"][0]["algorithm"]["name"] == "RSA"


def test_scan_certs_against_directory_walks_files(tmp_path: Path) -> None:
    _write_self_signed_rsa(tmp_path / "a.pem", key_size=2048)
    _write_self_signed_rsa(tmp_path / "b.pem", key_size=4096)
    result = runner.invoke(app, ["scan", "certs", "--path", str(tmp_path), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert len(sr["assets"]) == 2


def test_scan_certs_missing_path_records_error(tmp_path: Path) -> None:
    """Missing path should not crash — exit 0 with errors in the JSON."""
    result = runner.invoke(
        app, ["scan", "certs", "--path", str(tmp_path / "nope.pem"), "--compact"]
    )
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["assets"] == []
    assert sr["errors"]


def test_scan_ssh_against_unreachable_host_returns_valid_json() -> None:
    """`scan ssh` always emits JSON even on connection error."""
    result = runner.invoke(app, ["scan", "ssh", "--host", "127.0.0.1", "--port", "1", "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "ssh"
    assert sr["assets"] == [] or sr["errors"]


def _name_list(items: list[str]) -> bytes:
    payload = ",".join(items).encode("ascii")
    return struct.pack(">I", len(payload)) + payload


def _build_kexinit_payload() -> bytes:
    out = bytearray()
    out.append(20)
    out.extend(b"\x00" * 16)
    out.extend(_name_list(["curve25519-sha256"]))
    out.extend(_name_list(["ssh-ed25519"]))
    out.extend(_name_list(["chacha20-poly1305@openssh.com"]))
    out.extend(_name_list(["chacha20-poly1305@openssh.com"]))
    out.extend(_name_list(["hmac-sha2-256-etm@openssh.com"]))
    out.extend(_name_list(["hmac-sha2-256-etm@openssh.com"]))
    out.extend(_name_list(["none"]))
    out.extend(_name_list(["none"]))
    out.extend(_name_list([]))
    out.extend(_name_list([]))
    out.append(0)
    out.extend(b"\x00" * 4)
    return bytes(out)


def _frame_packet(payload: bytes) -> bytes:
    pad_len = 8 - ((4 + 1 + len(payload)) % 8)
    if pad_len < 4:
        pad_len += 8
    return (
        struct.pack(">I", 1 + len(payload) + pad_len)
        + bytes([pad_len])
        + payload
        + (b"\x00" * pad_len)
    )


def _serve_one_kexinit() -> tuple[str, int, threading.Event]:
    """Bind a one-shot TCP listener that fakes a SSH KEXINIT exchange."""
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
                client.sendall(b"SSH-2.0-pqc-audit-mini\r\n")
                client.settimeout(2.0)
                with contextlib.suppress(OSError):
                    client.recv(256)
                client.sendall(_frame_packet(_build_kexinit_payload()))
            finally:
                served.set()
                client.close()
        except OSError:
            served.set()
        finally:
            sock.close()

    threading.Thread(target=_runner, daemon=True).start()
    return host, port, served


def test_scan_ssh_with_local_mini_server() -> None:
    """End-to-end CLI: spin a fake SSH server in a thread, scan via the CLI."""
    host, port, served = _serve_one_kexinit()
    try:
        result = runner.invoke(
            app,
            ["scan", "ssh", "--host", host, "--port", str(port), "--compact"],
        )
        assert result.exit_code == 0, result.stdout
        parsed = json.loads(result.stdout)
        sr = parsed["scan_results"][0]
        assert sr["scanner_name"] == "ssh"
        assert sr["assets"], f"expected assets, errors={sr['errors']}"
    finally:
        served.wait(timeout=5.0)
