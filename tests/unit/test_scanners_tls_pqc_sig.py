"""Tests for ML-DSA signature_algorithms TLS 1.3 probe — Sprint 9f.2.

Companion to Sprint 9f (PQC hybrid handshake KEM probe). 9f detects
post-quantum *key exchange* readiness via the ``key_share`` extension;
9f.2 detects post-quantum *signature* readiness via the
``signature_algorithms`` extension.

Codepoints (draft-ietf-tls-mldsa-03, IETF TLS WG, Informational, exp
2026-11-07 — https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa):

* ML-DSA-44 → 0x0904
* ML-DSA-65 → 0x0905
* ML-DSA-87 → 0x0906

SLH-DSA is intentionally NOT probed in this sprint: as of 2026-05-17,
no TLS 1.3 SignatureScheme codepoint is registered (only X.509 OIDs
in RFC 9909, and CMS-only in RFC 9814). Probing SLH-DSA in TLS 1.3
would require inventing codepoints — fuffa, declined.

OpenSSL 3.5.5 (default on Aurelio's box) supports MLDSA44/65/87
natively in TLS 1.3 via the ``-sigalgs`` CLI flag, validated
empirically on agid.gov.it (returns ``Negotiated TLS1.3 group:
<NULL>`` when no MLDSA-signed cert is available, confirming the
server has no PQC signature support).
"""

from __future__ import annotations

# ---------------------------------------------------------------------
# Codepoint constants
# ---------------------------------------------------------------------


def test_mldsa_sigalgs_lists_three_codepoints() -> None:
    from pqc_audit.scanners.tls_pqc_sig import MLDSA_SIGALGS

    assert MLDSA_SIGALGS == ("MLDSA44", "MLDSA65", "MLDSA87")


def test_mldsa_codepoint_mapping_matches_draft() -> None:
    """Codepoints from draft-ietf-tls-mldsa-03."""
    from pqc_audit.scanners.tls_pqc_sig import MLDSA_CODEPOINTS

    assert MLDSA_CODEPOINTS["MLDSA44"] == 0x0904
    assert MLDSA_CODEPOINTS["MLDSA65"] == 0x0905
    assert MLDSA_CODEPOINTS["MLDSA87"] == 0x0906


# ---------------------------------------------------------------------
# parse_negotiated_signature_status
# ---------------------------------------------------------------------


def test_parse_status_supported_when_negotiated_group_present_and_cert_chain() -> None:
    from pqc_audit.scanners.tls_pqc_sig import parse_negotiated_signature_status

    stdout = (
        "CONNECTED(00000003)\n"
        "---\n"
        "Certificate chain\n"
        " 0 s:CN = example.com\n"
        "---\n"
        "Server certificate\n"
        "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n"
        "subject=CN = example.com\n"
        "issuer=CN = Test CA\n"
        "---\n"
        "Negotiated TLS1.3 group: X25519\n"
        "Verify return code: 0 (ok)\n"
    )
    status = parse_negotiated_signature_status(stdout=stdout, stderr="")
    assert status == "supported"


def test_parse_status_not_supported_when_negotiated_group_is_null() -> None:
    """The canonical empirical signal: AGID + MLDSA-only sigalgs."""
    from pqc_audit.scanners.tls_pqc_sig import parse_negotiated_signature_status

    stdout = (
        "CONNECTED(00000003)\n"
        "no peer certificate available\n"
        "---\n"
        "No client certificate CA names sent\n"
        "Negotiated TLS1.3 group: <NULL>\n"
        "No ALPN negotiated\n"
        "Verify return code: 0 (ok)\n"
    )
    status = parse_negotiated_signature_status(stdout=stdout, stderr="")
    assert status == "not_supported"


def test_parse_status_not_supported_when_handshake_alert() -> None:
    from pqc_audit.scanners.tls_pqc_sig import parse_negotiated_signature_status

    stderr = (
        "C4D10000:error:0A000410:SSL routines:ssl3_read_bytes:"
        "ssl/tls alert handshake failure:../openssl-3.5.5/ssl/record/"
        "rec_layer_s3.c:918:SSL alert number 40\n"
    )
    status = parse_negotiated_signature_status(stdout="", stderr=stderr)
    assert status == "not_supported"


def test_parse_status_error_when_dns_failure() -> None:
    from pqc_audit.scanners.tls_pqc_sig import parse_negotiated_signature_status

    stderr = "getaddrinfo: Name or service not known\n"
    status = parse_negotiated_signature_status(stdout="", stderr=stderr)
    assert status == "error"


def test_parse_status_error_when_connect_refused() -> None:
    from pqc_audit.scanners.tls_pqc_sig import parse_negotiated_signature_status

    stderr = "connect:errno=111\n"
    status = parse_negotiated_signature_status(stdout="", stderr=stderr)
    assert status == "error"


def test_parse_status_empty_inputs_returns_error() -> None:
    from pqc_audit.scanners.tls_pqc_sig import parse_negotiated_signature_status

    status = parse_negotiated_signature_status(stdout="", stderr="")
    assert status == "error"


# ---------------------------------------------------------------------
# probe_mldsa_sigalg — subprocess invocation contract
# ---------------------------------------------------------------------


def test_probe_returns_dict_with_required_keys(monkeypatch) -> None:
    """Caller-stable contract: callers depend on these keys."""
    from pqc_audit.scanners import tls_pqc_sig

    class FakeCP:
        stdout = (
            "Negotiated TLS1.3 group: <NULL>\nVerify return code: 0 (ok)\n"
        )
        stderr = ""
        returncode = 0

    def fake_run(*args, **kwargs):
        return FakeCP()

    monkeypatch.setattr(tls_pqc_sig.subprocess, "run", fake_run)

    out = tls_pqc_sig.probe_mldsa_sigalg("example.com", 443, "MLDSA65")
    assert set(out.keys()) == {"sigalg", "codepoint", "status", "host", "port"}
    assert out["sigalg"] == "MLDSA65"
    assert out["codepoint"] == 0x0905
    assert out["host"] == "example.com"
    assert out["port"] == 443
    assert out["status"] == "not_supported"


def test_probe_handles_subprocess_timeout(monkeypatch) -> None:
    import subprocess

    from pqc_audit.scanners import tls_pqc_sig

    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="openssl", timeout=5)

    monkeypatch.setattr(tls_pqc_sig.subprocess, "run", raise_timeout)

    out = tls_pqc_sig.probe_mldsa_sigalg("slow.example.com", 443, "MLDSA44")
    assert out["status"] == "error"


def test_probe_handles_openssl_not_installed(monkeypatch) -> None:
    from pqc_audit.scanners import tls_pqc_sig

    def raise_filenotfound(*args, **kwargs):
        raise FileNotFoundError("openssl: command not found")

    monkeypatch.setattr(tls_pqc_sig.subprocess, "run", raise_filenotfound)

    out = tls_pqc_sig.probe_mldsa_sigalg("example.com", 443, "MLDSA44")
    assert out["status"] == "error"


# ---------------------------------------------------------------------
# probe_all_mldsa_sigalgs — aggregator
# ---------------------------------------------------------------------


def test_probe_all_returns_dict_keyed_by_sigalg(monkeypatch) -> None:
    from pqc_audit.scanners import tls_pqc_sig

    def fake_probe(host, port, sigalg):
        return {
            "sigalg": sigalg,
            "codepoint": tls_pqc_sig.MLDSA_CODEPOINTS[sigalg],
            "status": "not_supported",
            "host": host,
            "port": port,
        }

    monkeypatch.setattr(tls_pqc_sig, "probe_mldsa_sigalg", fake_probe)

    out = tls_pqc_sig.probe_all_mldsa_sigalgs("example.com", 443)
    assert set(out.keys()) == set(tls_pqc_sig.MLDSA_SIGALGS)
    for name, result in out.items():
        assert result["sigalg"] == name
        assert result["status"] == "not_supported"


def test_cli_scan_pqc_mldsa_sig_subcommand_wires_probe(monkeypatch) -> None:
    """Sprint 9f.2 wiring: the CLI subcommand `pqc-audit scan
    pqc-mldsa-sig` must invoke probe_all_mldsa_sigalgs and emit
    valid JSON. Closes the caller_verification gap from critic gate."""
    import json

    from typer.testing import CliRunner

    from pqc_audit.cli import app
    from pqc_audit.scanners import tls_pqc_sig

    def fake_probe_all(host, port):
        return {
            name: {
                "sigalg": name,
                "codepoint": tls_pqc_sig.MLDSA_CODEPOINTS[name],
                "status": "not_supported",
                "host": host,
                "port": port,
            }
            for name in tls_pqc_sig.MLDSA_SIGALGS
        }

    monkeypatch.setattr(tls_pqc_sig, "probe_all_mldsa_sigalgs", fake_probe_all)

    runner = CliRunner()
    result = runner.invoke(
        app, ["scan", "pqc-mldsa-sig", "--host", "example.com", "--port", "443"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["host"] == "example.com"
    assert payload["port"] == 443
    assert payload["probe"] == "tls13-signature-algorithms-mldsa"
    assert payload["reference"] == "draft-ietf-tls-mldsa-03"
    assert set(payload["results"].keys()) == set(tls_pqc_sig.MLDSA_SIGALGS)
    for name in tls_pqc_sig.MLDSA_SIGALGS:
        assert payload["results"][name]["status"] == "not_supported"


def test_probe_all_propagates_mixed_status(monkeypatch) -> None:
    """If one of three sigalgs supported, that one shows 'supported'."""
    from pqc_audit.scanners import tls_pqc_sig

    def fake_probe(host, port, sigalg):
        status = "supported" if sigalg == "MLDSA65" else "not_supported"
        return {
            "sigalg": sigalg,
            "codepoint": tls_pqc_sig.MLDSA_CODEPOINTS[sigalg],
            "status": status,
            "host": host,
            "port": port,
        }

    monkeypatch.setattr(tls_pqc_sig, "probe_mldsa_sigalg", fake_probe)

    out = tls_pqc_sig.probe_all_mldsa_sigalgs("future-pqc-server.example.com", 443)
    assert out["MLDSA44"]["status"] == "not_supported"
    assert out["MLDSA65"]["status"] == "supported"
    assert out["MLDSA87"]["status"] == "not_supported"
