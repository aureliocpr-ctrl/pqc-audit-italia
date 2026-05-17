"""Tests for TLS chain validation (Sprint 9d).

Real-world TLS handshakes return a *chain* of certificates: leaf →
intermediate(s) → (rarely) root. Auditing only the leaf misses
material risks: an RSA-1024 intermediate, a SHA-1 root, or a chain
missing intermediates entirely.

These tests cover the pure helpers (offline, with in-memory certs):

* ``classify_chain_positions`` — label each cert by position
* ``extract_chain_summary`` — produce CBOM/SARIF-ready dict
* ``assess_chain`` — per-cert findings against the chain context
* ``TLSScanner.scan`` integration — emit one ``CryptoAsset`` per cert

Real network behaviour against ``www.agid.gov.it:443`` was empirically
verified (Let's Encrypt E7 intermediate, no root sent) and shapes the
expected data model below.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any


def _make_cert(
    *,
    subject_cn: str,
    issuer_cn: str | None = None,
    issuer_key: Any = None,
    key_alg: str = "ecdsa-p256",
    key_size: int = 2048,
    sig_hash: str = "sha256",
    is_ca: bool = False,
    path_length: int | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> tuple[Any, Any]:
    """Build a fresh (cert, private_key) pair. Self-signed if no issuer_key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    if key_alg == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_alg == "ecdsa-p256":
        priv = ec.generate_private_key(ec.SECP256R1())
    elif key_alg == "ecdsa-p384":
        priv = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError(f"unknown key_alg {key_alg}")

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = (
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        if issuer_cn
        else subject
    )
    signing_key = issuer_key if issuer_key is not None else priv
    nb = not_before or (datetime.now(UTC) - timedelta(days=1))
    na = not_after or (datetime.now(UTC) + timedelta(days=30))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )

    hash_map = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha1": hashes.SHA1(),  # noqa: S303 — intentional, test weak chain
    }
    cert = builder.sign(signing_key, hash_map[sig_hash])
    return cert, priv


def _build_two_cert_chain() -> list[Any]:
    """Build [leaf, intermediate]: leaf signed by intermediate (CA).

    Standard TLS practice — server sends leaf + intermediate, NOT the
    root. The intermediate must therefore have a non-self-signed
    issuer (a Root that lives only in the client trust store). Without
    this distinction the intermediate would look self-signed and
    ``classify_chain_positions`` would mis-label it as "root".
    """
    _root, root_key = _make_cert(
        subject_cn="External Root CA",
        key_alg="rsa",
        key_size=4096,
        sig_hash="sha256",
        is_ca=True,
    )
    intermediate, int_key = _make_cert(
        subject_cn="Test Intermediate CA",
        issuer_cn="External Root CA",
        issuer_key=root_key,
        key_alg="ecdsa-p256",
        sig_hash="sha256",
        is_ca=True,
        path_length=0,
    )
    leaf, _ = _make_cert(
        subject_cn="leaf.example.it",
        issuer_cn="Test Intermediate CA",
        issuer_key=int_key,
        key_alg="ecdsa-p256",
        sig_hash="sha384",
    )
    return [leaf, intermediate]


def _build_three_cert_chain_with_root() -> list[Any]:
    """Build [leaf, intermediate, self-signed root]."""
    root, root_key = _make_cert(
        subject_cn="Test Root CA",
        key_alg="rsa",
        key_size=4096,
        sig_hash="sha256",
        is_ca=True,
    )
    intermediate, int_key = _make_cert(
        subject_cn="Test Intermediate CA",
        issuer_cn="Test Root CA",
        issuer_key=root_key,
        key_alg="rsa",
        key_size=2048,
        sig_hash="sha256",
        is_ca=True,
        path_length=0,
    )
    leaf, _ = _make_cert(
        subject_cn="leaf.example.it",
        issuer_cn="Test Intermediate CA",
        issuer_key=int_key,
        key_alg="ecdsa-p256",
        sig_hash="sha256",
    )
    return [leaf, intermediate, root]


# -------------------- classify_chain_positions --------------------


def test_classify_empty_chain() -> None:
    from pqc_audit.scanners.tls_scanner import classify_chain_positions

    assert classify_chain_positions([]) == []


def test_classify_single_leaf() -> None:
    from pqc_audit.scanners.tls_scanner import classify_chain_positions

    chain = [_make_cert(subject_cn="lonely.it")[0]]
    assert classify_chain_positions(chain) == ["leaf"]


def test_classify_leaf_plus_intermediate() -> None:
    from pqc_audit.scanners.tls_scanner import classify_chain_positions

    chain = _build_two_cert_chain()
    labels = classify_chain_positions(chain)
    assert labels == ["leaf", "intermediate-1"]


def test_classify_leaf_intermediate_root() -> None:
    from pqc_audit.scanners.tls_scanner import classify_chain_positions

    chain = _build_three_cert_chain_with_root()
    labels = classify_chain_positions(chain)
    assert labels == ["leaf", "intermediate-1", "root"]


def test_classify_recognizes_root_via_self_issuance() -> None:
    """Last cert with subject==issuer is the trust anchor."""
    from pqc_audit.scanners.tls_scanner import classify_chain_positions

    # Three certs, last is self-signed (root).
    root, _ = _make_cert(subject_cn="Root", key_alg="rsa", is_ca=True)
    inter, _ = _make_cert(subject_cn="Inter", is_ca=True)
    leaf, _ = _make_cert(subject_cn="leaf.it")
    labels = classify_chain_positions([leaf, inter, root])
    assert labels[-1] == "root"


# -------------------- extract_chain_summary --------------------


def test_chain_summary_basic_fields() -> None:
    from pqc_audit.scanners.tls_scanner import extract_chain_summary

    chain = _build_two_cert_chain()
    summary = extract_chain_summary(chain)
    assert summary["chain_length"] == 2
    # CBOM/SARIF need to know if the chain terminates at a self-signed root
    assert summary["terminates_at_root"] is False
    # Subjects/issuers preserved in order
    assert len(summary["subjects"]) == 2
    assert "leaf.example.it" in summary["subjects"][0]
    assert "Test Intermediate CA" in summary["subjects"][1]
    # Algorithms inventoried for inventory-style reports
    assert "algorithms" in summary
    assert len(summary["algorithms"]) == 2
    # Each entry should expose the canonical algorithm name + key size
    first = summary["algorithms"][0]
    assert isinstance(first, dict)
    assert "name" in first


def test_chain_summary_terminates_at_root_true_when_self_signed_top() -> None:
    from pqc_audit.scanners.tls_scanner import extract_chain_summary

    chain = _build_three_cert_chain_with_root()
    summary = extract_chain_summary(chain)
    assert summary["chain_length"] == 3
    assert summary["terminates_at_root"] is True


def test_chain_summary_signature_hashes_listed() -> None:
    from pqc_audit.scanners.tls_scanner import extract_chain_summary

    chain = _build_three_cert_chain_with_root()
    summary = extract_chain_summary(chain)
    hashes_ = summary["signature_hashes"]
    assert isinstance(hashes_, list)
    assert len(hashes_) == 3
    # All three signed with SHA-256 in this fixture
    assert all(h == "SHA-256" for h in hashes_)


# -------------------- assess_chain --------------------


def test_assess_chain_flags_incomplete_chain_when_only_leaf() -> None:
    """A TLS server presenting only the leaf, with no intermediate at all,
    is an audit finding (legacy / misconfigured)."""
    from pqc_audit.scanners.tls_scanner import assess_chain

    leaf, _ = _make_cert(
        subject_cn="leaf.it",
        issuer_cn="Some Issuer Not Self",  # not self-signed
    )
    findings = assess_chain([leaf], leaf_asset_id="tls://leaf.it:443")
    titles = [v.title.lower() for v in findings]
    assert any("incomplete chain" in t or "intermediate" in t for t in titles)


def test_assess_chain_does_not_flag_when_leaf_is_self_signed() -> None:
    """Self-signed leaves are flagged by ``assess_certificate``, not
    ``assess_chain`` — avoid double-reporting."""
    from pqc_audit.scanners.tls_scanner import assess_chain

    self_signed_leaf, _ = _make_cert(subject_cn="lonely.it")  # subject == issuer
    findings = assess_chain([self_signed_leaf], leaf_asset_id="tls://lonely.it:443")
    titles = [v.title.lower() for v in findings]
    # Self-signed leaf shouldn't generate an extra "incomplete chain" finding;
    # the self-signed check in assess_certificate already covers it.
    assert not any("incomplete chain" in t for t in titles)


def test_assess_chain_flags_rsa_1024_intermediate() -> None:
    """An RSA-1024 intermediate is a chain-wide weakness, not a leaf issue."""
    from pqc_audit.scanners.tls_scanner import assess_chain

    _parent, parent_key = _make_cert(
        subject_cn="External Root",
        key_alg="rsa",
        key_size=4096,
        is_ca=True,
    )
    weak_inter, weak_key = _make_cert(
        subject_cn="Weak Intermediate",
        issuer_cn="External Root",
        issuer_key=parent_key,
        key_alg="rsa",
        key_size=1024,
        sig_hash="sha256",
        is_ca=True,
    )
    leaf, _ = _make_cert(
        subject_cn="leaf.it",
        issuer_cn="Weak Intermediate",
        issuer_key=weak_key,
    )
    findings = assess_chain([leaf, weak_inter], leaf_asset_id="tls://leaf.it:443")
    titles = [v.title.lower() for v in findings]
    # The undersized RSA-1024 intermediate must be surfaced.
    assert any("under" in t or "1024" in t for t in titles), (
        f"expected RSA-1024 intermediate finding, got: {titles}"
    )


def test_assess_chain_flags_sha1_intermediate(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """SHA-1 anywhere in the chain is HIGH severity.

    ``cryptography>=46`` no longer signs SHA-1 (correctly — the algorithm
    is collision-broken). To exercise this assess path we materialize a
    real SHA-1-signed cert via the OpenSSL CLI, which still emits SHA-1
    on demand. If OpenSSL is unavailable or refuses, the test is
    skipped — but coverage of the parse path remains real (we parse a
    bona-fide DER produced by OpenSSL).
    """
    import os
    import shutil
    import subprocess  # noqa: S404 — used with a fully-controlled command + tempdir

    import pytest
    from cryptography import x509

    from pqc_audit.scanners.tls_scanner import assess_chain

    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        pytest.skip("openssl CLI not available")

    key_path = tmp_path / "sha1.key"
    crt_path = tmp_path / "sha1.crt"
    env = os.environ.copy()
    # On stripped-down installs OPENSSL_CONF may point at a missing
    # file. Force it to the platform null device so ``openssl req``
    # bootstraps with built-in defaults.
    env["OPENSSL_CONF"] = os.devnull
    proc = subprocess.run(  # noqa: S603 — fully-controlled args, no shell
        [
            openssl_bin,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(crt_path),
            "-sha1",
            "-days",
            "30",
            "-nodes",
            "-subj",
            "/CN=SHA1 Test CA",
        ],
        env=env,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0 or not crt_path.exists():
        pytest.skip(f"openssl refused SHA-1 signing: {proc.stderr.decode(errors='ignore')[:200]}")

    sha1_cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    # Use the SHA-1 cert as a fake "intermediate" in our chain. The leaf
    # we keep modern (SHA-256) so the only deprecated-hash hit is the
    # intermediate one.
    leaf, _ = _make_cert(subject_cn="leaf.it", issuer_cn="SHA1 Test CA")

    findings = assess_chain([leaf, sha1_cert], leaf_asset_id="tls://leaf.it:443")
    titles = [v.title.lower() for v in findings]
    assert any("sha-1" in t or "deprecated hash" in t for t in titles), (
        f"expected SHA-1 finding on intermediate, got: {titles}"
    )


def test_assess_chain_findings_reference_position_specific_asset_id() -> None:
    """Findings must point at the *specific* cert in the chain, not just leaf."""
    from pqc_audit.scanners.tls_scanner import assess_chain

    _parent, parent_key = _make_cert(
        subject_cn="External Root",
        key_alg="rsa",
        key_size=4096,
        is_ca=True,
    )
    weak_inter, weak_key = _make_cert(
        subject_cn="Weak Intermediate",
        issuer_cn="External Root",
        issuer_key=parent_key,
        key_alg="rsa",
        key_size=1024,
        sig_hash="sha256",
        is_ca=True,
    )
    leaf, _ = _make_cert(
        subject_cn="leaf.it",
        issuer_cn="Weak Intermediate",
        issuer_key=weak_key,
    )
    findings = assess_chain([leaf, weak_inter], leaf_asset_id="tls://leaf.it:443")
    # The weak-intermediate finding must reference "intermediate-1", not leaf
    relevant = [v for v in findings if "under" in v.title.lower() or "1024" in v.title.lower()]
    assert relevant, "expected at least one RSA-1024 finding"
    affected = relevant[0].affected_asset_ids
    assert any("intermediate-1" in a for a in affected), (
        f"intermediate finding must reference intermediate-1, got: {affected}"
    )


# -------------------- TLSScanner.scan integration --------------------


def test_scan_emits_asset_per_chain_certificate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """``TLSScanner.scan`` must emit one CryptoAsset per cert in the chain."""
    import asyncio

    from cryptography.hazmat.primitives.serialization import Encoding

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.tls_scanner import TLSScanner

    chain_certs = _build_three_cert_chain_with_root()
    chain_der = [c.public_bytes(Encoding.DER) for c in chain_certs]

    async def fake_handshake(host: str, port: int, *, timeout_s: float = 8.0) -> dict[str, Any]:
        return {
            "der": chain_der[0],
            "chain_der": chain_der,
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    monkeypatch.setattr("pqc_audit.scanners.tls_scanner._handshake", fake_handshake)

    target = ScanTarget(type="tls", host="leaf.example.it", port=443)
    result = asyncio.run(TLSScanner().scan(target))

    assert len(result.assets) == 3, (
        f"expected 3 assets (leaf+intermediate+root), got {len(result.assets)}: "
        f"{[a.asset_id for a in result.assets]}"
    )
    # The leaf must be the primary asset (first), with the canonical id.
    assert result.assets[0].asset_id == "tls://leaf.example.it:443"
    # Subsequent certs get suffixed ids
    suffixed = [a.asset_id for a in result.assets[1:]]
    assert any("intermediate-1" in s for s in suffixed)
    assert any("root" in s for s in suffixed)


def test_scan_leaf_asset_carries_chain_summary_in_metadata(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The leaf asset must expose ``chain_length`` and ``terminates_at_root``
    in its metadata so CBOM / SARIF reporters can surface them downstream.
    """
    import asyncio

    from cryptography.hazmat.primitives.serialization import Encoding

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.tls_scanner import TLSScanner

    chain_certs = _build_two_cert_chain()
    chain_der = [c.public_bytes(Encoding.DER) for c in chain_certs]

    async def fake_handshake(host: str, port: int, *, timeout_s: float = 8.0) -> dict[str, Any]:
        return {
            "der": chain_der[0],
            "chain_der": chain_der,
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    monkeypatch.setattr("pqc_audit.scanners.tls_scanner._handshake", fake_handshake)

    target = ScanTarget(type="tls", host="leaf.example.it", port=443)
    result = asyncio.run(TLSScanner().scan(target))

    leaf_asset = result.assets[0]
    assert leaf_asset.metadata.get("chain_length") == 2
    assert leaf_asset.metadata.get("terminates_at_root") is False


def test_scan_emits_finding_for_weak_intermediate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """End-to-end: weak intermediate must produce a vulnerability in
    ``ScanResult.vulnerabilities`` pointing at ``#intermediate-1``."""
    import asyncio

    from cryptography.hazmat.primitives.serialization import Encoding

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.tls_scanner import TLSScanner

    _parent, parent_key = _make_cert(
        subject_cn="External Root",
        key_alg="rsa",
        key_size=4096,
        is_ca=True,
    )
    weak_inter, weak_key = _make_cert(
        subject_cn="Weak Intermediate",
        issuer_cn="External Root",
        issuer_key=parent_key,
        key_alg="rsa",
        key_size=1024,
        sig_hash="sha256",
        is_ca=True,
    )
    leaf, _ = _make_cert(
        subject_cn="leaf.example.it",
        issuer_cn="Weak Intermediate",
        issuer_key=weak_key,
    )
    chain_der = [
        leaf.public_bytes(Encoding.DER),
        weak_inter.public_bytes(Encoding.DER),
    ]

    async def fake_handshake(host: str, port: int, *, timeout_s: float = 8.0) -> dict[str, Any]:
        return {
            "der": chain_der[0],
            "chain_der": chain_der,
            "version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

    monkeypatch.setattr("pqc_audit.scanners.tls_scanner._handshake", fake_handshake)

    target = ScanTarget(type="tls", host="leaf.example.it", port=443)
    result = asyncio.run(TLSScanner().scan(target))

    weak_findings = [
        v for v in result.vulnerabilities
        if "1024" in v.title or "under" in v.title.lower()
    ]
    assert weak_findings, (
        f"expected RSA-1024 intermediate finding, got: "
        f"{[v.title for v in result.vulnerabilities]}"
    )
    affected = weak_findings[0].affected_asset_ids
    assert any("intermediate-1" in a for a in affected)
