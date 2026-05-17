"""Tests for the PQC hybrid handshake probe scanner (Sprint 9f).

The scanner uses the ``openssl s_client`` CLI (OpenSSL 3.5+) to drive
THREE probe handshakes against ``host:port``, one per codepoint in
``draft-ietf-tls-ecdhe-mlkem-04`` (Feb 2026, in RFC Ed Queue):

* ``SecP256r1MLKEM768`` (IANA 0x11EB)
* ``X25519MLKEM768`` (IANA 0x11EC)
* ``SecP384r1MLKEM1024`` (IANA 0x11ED)

A server accepting at least one is post-quantum-ready at the TLS
key-exchange layer. A server accepting none is on a 2030 NIST timer.

Real measurements that ground these tests (2026-05-17):

* ``www.agid.gov.it:443`` — handshake_failure alert 40 on all 3 hybrid
  groups, classical X25519 negotiates fine.
* ``www.cloudflare.com:443`` — ``Negotiated TLS1.3 group: X25519MLKEM768``
  returned on probe.
"""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import patch

# -------------------- parse_negotiated_group --------------------


def test_parse_negotiated_group_happy_path() -> None:
    from pqc_audit.scanners.pqc_hybrid_scanner import parse_negotiated_group

    sample = (
        "depth=2 C=US, O=Cloudflare\n"
        "verify return:1\n"
        "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        "Negotiated TLS1.3 group: X25519MLKEM768\n"
        "Server public key is 256 bit\n"
    )
    assert parse_negotiated_group(sample) == "X25519MLKEM768"


def test_parse_negotiated_group_handshake_failure() -> None:
    """Handshake failure ⇒ ``Negotiated TLS1.3 group: <NULL>`` or absent."""
    from pqc_audit.scanners.pqc_hybrid_scanner import parse_negotiated_group

    sample = (
        "F02C0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert "
        "handshake failure:../openssl-3.5.5/ssl/record/rec_layer_s3.c:918:"
        "SSL alert number 40\n"
        "Negotiated TLS1.3 group: <NULL>\n"
        "New, (NONE), Cipher is (NONE)\n"
    )
    assert parse_negotiated_group(sample) is None


def test_parse_negotiated_group_absent_returns_none() -> None:
    from pqc_audit.scanners.pqc_hybrid_scanner import parse_negotiated_group

    sample = "some unrelated openssl chatter\n"
    assert parse_negotiated_group(sample) is None


def test_parse_negotiated_group_strips_whitespace() -> None:
    from pqc_audit.scanners.pqc_hybrid_scanner import parse_negotiated_group

    sample = "Negotiated TLS1.3 group:   X25519MLKEM768   \n"
    assert parse_negotiated_group(sample) == "X25519MLKEM768"


# -------------------- probe_group --------------------


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_probe_group_invokes_openssl_with_expected_args() -> None:
    from pqc_audit.scanners.pqc_hybrid_scanner import probe_group

    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env") or {}
        return _FakeCompleted(
            stdout="Negotiated TLS1.3 group: X25519MLKEM768\n", returncode=0
        )

    with patch("pqc_audit.scanners.pqc_hybrid_scanner.subprocess.run", new=fake_run):
        out = probe_group("example.it", 443, "X25519MLKEM768", openssl_bin="openssl")

    assert out == "X25519MLKEM768"
    cmd = captured["cmd"]
    assert "openssl" in cmd[0] or cmd[0].endswith("openssl")
    assert "s_client" in cmd
    assert "-connect" in cmd and "example.it:443" in cmd
    assert "-servername" in cmd and "example.it" in cmd
    assert "-groups" in cmd and "X25519MLKEM768" in cmd
    assert "-tls1_3" in cmd


def test_probe_group_handshake_failure_returns_none() -> None:
    from pqc_audit.scanners.pqc_hybrid_scanner import probe_group

    failure_stdout = (
        "ssl3_read_bytes:ssl/tls alert handshake failure\n"
        "Negotiated TLS1.3 group: <NULL>\n"
    )

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        return _FakeCompleted(stdout=failure_stdout, returncode=1)

    with patch("pqc_audit.scanners.pqc_hybrid_scanner.subprocess.run", new=fake_run):
        out = probe_group("example.it", 443, "X25519MLKEM768", openssl_bin="openssl")
    assert out is None


def test_probe_group_subprocess_timeout_returns_none() -> None:
    from pqc_audit.scanners.pqc_hybrid_scanner import probe_group

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5)

    with patch("pqc_audit.scanners.pqc_hybrid_scanner.subprocess.run", new=fake_run):
        out = probe_group("example.it", 443, "X25519MLKEM768", openssl_bin="openssl")
    assert out is None


# -------------------- probe_all_hybrid_groups --------------------


def test_probe_all_hybrid_groups_returns_dict_of_three_iana_codepoints() -> None:
    """The probe matrix must match exactly the THREE IANA codepoints from
    draft-ietf-tls-ecdhe-mlkem-04. Including X448MLKEM1024 here would be
    fake coverage — that group has no IANA codepoint and cannot appear
    on the wire."""
    from pqc_audit.scanners.pqc_hybrid_scanner import (
        HYBRID_GROUPS,
        probe_all_hybrid_groups,
    )

    assert len(HYBRID_GROUPS) == 3
    assert set(HYBRID_GROUPS) == {
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024",
    }
    # X448MLKEM1024 explicitly NOT in the probe list (no IANA codepoint).
    assert "X448MLKEM1024" not in HYBRID_GROUPS

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        # Only X25519MLKEM768 succeeds — simulates Cloudflare-style server.
        for g in HYBRID_GROUPS:
            if g in cmd and g == "X25519MLKEM768":
                return _FakeCompleted(
                    stdout=f"Negotiated TLS1.3 group: {g}\n", returncode=0
                )
        return _FakeCompleted(stdout="Negotiated TLS1.3 group: <NULL>\n", returncode=1)

    with patch("pqc_audit.scanners.pqc_hybrid_scanner.subprocess.run", new=fake_run):
        out = probe_all_hybrid_groups("example.it", 443, openssl_bin="openssl")

    assert len(out) == 3
    assert out["X25519MLKEM768"] == "X25519MLKEM768"
    assert out["SecP256r1MLKEM768"] is None
    assert out["SecP384r1MLKEM1024"] is None


# -------------------- PQCHybridScanner.scan --------------------


def test_scanner_emits_medium_finding_when_no_hybrid_supported() -> None:
    """All 3 probes fail ⇒ server is on the 2030 NIST timer."""
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.pqc_hybrid_scanner import HYBRID_GROUPS, PQCHybridScanner

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        return _FakeCompleted(
            stdout="ssl/tls alert handshake failure\nNegotiated TLS1.3 group: <NULL>\n",
            returncode=1,
        )

    target = ScanTarget(type="pqc-hybrid", host="agid-like.it", port=443)
    with patch(
        "pqc_audit.scanners.pqc_hybrid_scanner.subprocess.run", new=fake_run
    ), patch(
        "pqc_audit.scanners.pqc_hybrid_scanner.shutil.which",
        new=lambda _: "/usr/bin/openssl",
    ):
        result = asyncio.run(PQCHybridScanner().scan(target))

    # One CryptoAsset for the endpoint
    assert len(result.assets) == 1
    asset = result.assets[0]
    assert asset.asset_id == "pqc-hybrid://agid-like.it:443"
    md = asset.metadata
    assert md["hybrid_supported"] == []
    # 3 probes recorded (matches IETF draft-ietf-tls-ecdhe-mlkem-04)
    assert set(md["probes"].keys()) == set(HYBRID_GROUPS)
    assert all(v is None for v in md["probes"].values())
    # MEDIUM finding for no hybrid support
    titles = [v.title.lower() for v in result.vulnerabilities]
    assert any("hybrid" in t and ("no" in t or "absent" in t or "not supported" in t)
               for t in titles)


def test_scanner_emits_info_finding_when_hybrid_active() -> None:
    """At least one probe negotiates ⇒ PQC migration started (positive finding)."""
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.pqc_hybrid_scanner import HYBRID_GROUPS, PQCHybridScanner

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        if "X25519MLKEM768" in cmd:
            return _FakeCompleted(
                stdout="Negotiated TLS1.3 group: X25519MLKEM768\n", returncode=0
            )
        return _FakeCompleted(stdout="Negotiated TLS1.3 group: <NULL>\n", returncode=1)

    target = ScanTarget(type="pqc-hybrid", host="cloudflare-like.com", port=443)
    with patch(
        "pqc_audit.scanners.pqc_hybrid_scanner.subprocess.run", new=fake_run
    ), patch(
        "pqc_audit.scanners.pqc_hybrid_scanner.shutil.which",
        new=lambda _: "/usr/bin/openssl",
    ):
        result = asyncio.run(PQCHybridScanner().scan(target))

    assert len(result.assets) == 1
    asset = result.assets[0]
    md = asset.metadata
    assert md["hybrid_supported"] == ["X25519MLKEM768"]
    assert md["probes"]["X25519MLKEM768"] == "X25519MLKEM768"
    # No NEGATIVE high/medium finding for missing hybrid
    titles = [v.title.lower() for v in result.vulnerabilities]
    assert not any("no pqc hybrid" in t for t in titles)
    # Positive INFO finding announcing the migration is in-flight
    assert any("hybrid" in t and ("active" in t or "supported" in t or "migration" in t)
               for t in titles)
    # And the 4-probe inventory is intact even with success
    assert set(md["probes"].keys()) == set(HYBRID_GROUPS)


def test_scanner_records_error_when_openssl_unavailable() -> None:
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.pqc_hybrid_scanner import PQCHybridScanner

    target = ScanTarget(type="pqc-hybrid", host="agid.gov.it", port=443)
    with patch("pqc_audit.scanners.pqc_hybrid_scanner.shutil.which", new=lambda _: None):
        result = asyncio.run(PQCHybridScanner().scan(target))

    # No assets; soft error surfaced — scanner does NOT crash
    assert result.assets == []
    assert any("openssl" in e.lower() for e in result.errors), (
        f"expected openssl-unavailable error, got: {result.errors}"
    )


def test_scanner_is_applicable_only_for_pqc_hybrid_type() -> None:
    import asyncio

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.pqc_hybrid_scanner import PQCHybridScanner

    tls_target = ScanTarget(type="tls", host="example.it", port=443)
    pqc_target = ScanTarget(type="pqc-hybrid", host="example.it", port=443)

    sc = PQCHybridScanner()
    assert asyncio.run(sc.is_applicable(tls_target)) is False
    assert asyncio.run(sc.is_applicable(pqc_target)) is True
