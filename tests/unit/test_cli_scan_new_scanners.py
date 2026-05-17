"""CLI tests for the Sprint 1 scanners exposed via subcommands.

Covers ``pqc-audit scan {jwt,dnssec,saml,mtls}``. These tests pin the
contract before the implementation lands and serve as the regression
floor for end-to-end CLI behaviour.

Each test builds its input file in-process (no committed fixtures)
and invokes the typer app through ``CliRunner`` so we exercise the
real argument parsing, the real Auditor, and the real reporter — no
mocks.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from typer.testing import CliRunner

from pqc_audit.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


def _make_jwt(alg: str) -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(b'{"sub":"x"}').rstrip(b"=").decode()
    s = base64.urlsafe_b64encode(b"sig").rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


def test_scan_jwt_against_alg_none_token_produces_critical(tmp_path: Path) -> None:
    f = tmp_path / "tokens.jwt"
    f.write_text(_make_jwt("none") + "\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "jwt", "--path", str(f), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "jwt"
    assert len(sr["assets"]) == 1
    assert sr["assets"][0]["algorithm"]["name"] == "none"
    # RiskLevel.CRITICAL = 4 (JSON reporter emits the name "CRITICAL").
    severities = {v["severity"] for v in sr["vulnerabilities"]}
    assert "CRITICAL" in severities


def test_scan_jwt_missing_path_records_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", "jwt", "--path", str(tmp_path / "nope.jwt"), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["assets"] == []
    assert sr["errors"]


# ---------------------------------------------------------------------------
# DNSSEC
# ---------------------------------------------------------------------------


def test_scan_dnssec_against_dnskey_zone_returns_assets(tmp_path: Path) -> None:
    f = tmp_path / "zone.txt"
    f.write_text(
        "example.com.   3600    IN  DNSKEY  256 3 8 AwEAAdummy...\n"
        "example.com.   3600    IN  DNSKEY  257 3 13 AwEAAdummyECDSA...\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", "dnssec", "--path", str(f), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "dnssec"
    assert len(sr["assets"]) == 2
    names = {a["algorithm"]["name"] for a in sr["assets"]}
    assert "RSA-SHA-256" in names
    assert any(n.startswith("ECDSA-P-256") for n in names)


def test_scan_dnssec_ignores_rrsig_in_real_dig_output(tmp_path: Path) -> None:
    f = tmp_path / "dig.txt"
    f.write_text(
        "example.com.   3600    IN  DNSKEY  256 3 8 AwEAA...\n"
        "example.com.   3600    IN  RRSIG   DNSKEY 8 2 3600 20260601000000 "
        "20260501000000 12345 example.com. sig==\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", "dnssec", "--path", str(f), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    # The RRSIG row must not be misread as a DNSKEY record (regression
    # against the bug surfaced by critic-orchestrator job 6294dc47).
    assert len(sr["assets"]) == 1


# ---------------------------------------------------------------------------
# SAML
# ---------------------------------------------------------------------------


def test_scan_saml_against_sha1_signature_flags_high(tmp_path: Path) -> None:
    f = tmp_path / "saml.xml"
    f.write_text(
        '<?xml version="1.0"?>'
        '<r xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        "</r>",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", "saml", "--path", str(f), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "saml"
    assert len(sr["assets"]) == 1
    severities = {v["severity"] for v in sr["vulnerabilities"]}
    assert "HIGH" in severities or "CRITICAL" in severities


# ---------------------------------------------------------------------------
# mTLS
# ---------------------------------------------------------------------------


def _build_chain_pem(tmp_path: Path) -> Path:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.cli.example")])
    now = datetime.now(UTC)
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    chain = tmp_path / "chain.pem"
    chain.write_bytes(
        leaf.public_bytes(serialization.Encoding.PEM)
        + root.public_bytes(serialization.Encoding.PEM)
    )
    return chain


def test_scan_mtls_against_valid_chain_returns_two_assets(tmp_path: Path) -> None:
    chain = _build_chain_pem(tmp_path)
    result = runner.invoke(app, ["scan", "mtls", "--path", str(chain), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "mtls"
    assert len(sr["assets"]) == 2
    roles = {a["metadata"]["role"] for a in sr["assets"]}
    assert "leaf" in roles
    assert "root" in roles


def test_scan_mtls_missing_path_records_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", "mtls", "--path", str(tmp_path / "nope.pem"), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["errors"]


# ---------------------------------------------------------------------------
# IaC (Sprint 4 #3)
# ---------------------------------------------------------------------------


def test_scan_iac_against_terraform_rsa_2048_flags_high(tmp_path: Path) -> None:
    tf = tmp_path / "kms.tf"
    tf.write_text(
        'resource "aws_kms_key" "x" {\n  customer_master_key_spec = "RSA_2048"\n}\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", "iac", "--path", str(tmp_path), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["scanner_name"] == "iac"
    assert sr["assets"]
    severities = {v["severity"] for v in sr["vulnerabilities"]}
    assert "HIGH" in severities


def test_scan_iac_missing_path_records_error(tmp_path: Path) -> None:
    bogus = tmp_path / "does_not_exist"
    result = runner.invoke(app, ["scan", "iac", "--path", str(bogus), "--compact"])
    assert result.exit_code == 0, result.stdout
    parsed = json.loads(result.stdout)
    sr = parsed["scan_results"][0]
    assert sr["assets"] == []
    assert sr["errors"]
