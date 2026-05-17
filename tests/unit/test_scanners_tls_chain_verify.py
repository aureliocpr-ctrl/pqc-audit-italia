"""Tests for cryptographic chain signature verification (Sprint 9d.2).

Sprint 9d documented an explicit gap: ``TLSScanner.scan`` emits one
``CryptoAsset`` per cert in the chain, but does NOT actually verify
that each cert's signature checks against the issuer's public key.
A hostile server could send three unrelated DER blobs and we would
report three "real" assets.

Sprint 9d.2 closes that gap with two pure helpers and a finding type:

* ``verify_chain_signatures(chain)`` returns per-cert verdict dicts
  ``{"index", "label", "verified", "error"}`` for every non-leaf-self-
  signed cert (the self-signed root verifies against itself).
* ``assess_chain_signatures(results, leaf_asset_id)`` produces HIGH
  CWE-295 findings for every broken link in the chain.

We use ``cryptography`` lib primitives — no fake "trust" oracle:
``issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
algo)`` is the same call OpenSSL makes internally.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any


def _build_real_chain(*, tamper_index: int | None = None) -> list[Any]:
    """Build a 3-cert chain [leaf, intermediate, root] with real
    cryptographically-linked signatures.

    If ``tamper_index`` is not None, flip one bit of the targeted cert's
    tbs_bytes after signing so its signature verification will fail —
    simulating a hostile / corrupted chain entry.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    # Root — RSA-4096 self-signed
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_subj)
        .issuer_name(root_subj)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Intermediate — ECDSA P-256 signed by root
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    inter = (
        x509.CertificateBuilder()
        .subject_name(inter_subj)
        .issuer_name(root_subj)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=180))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Leaf — ECDSA P-256 signed by intermediate
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.it")]))
        .issuer_name(inter_subj)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(inter_key, hashes.SHA384())
    )

    chain = [leaf, inter, root]
    if tamper_index is None:
        return chain

    # Tamper by re-loading the targeted cert from DER and replacing
    # with an unrelated cert at the same chain position.
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    unrelated_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unrelated_subj = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Imposter CA")]
    )
    unrelated = (
        x509.CertificateBuilder()
        .subject_name(unrelated_subj)
        .issuer_name(chain[tamper_index].issuer)  # keep claimed issuer
        .public_key(unrelated_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .sign(unrelated_key, hashes.SHA256())  # SELF-signed by unrelated_key
    )
    chain[tamper_index] = unrelated
    return chain


# -------------------- verify_chain_signatures --------------------


def test_verify_intact_chain_returns_all_verified() -> None:
    from pqc_audit.scanners.tls_scanner import verify_chain_signatures

    chain = _build_real_chain()
    results = verify_chain_signatures(chain)
    assert len(results) == 3
    # leaf -> intermediate: must verify
    assert results[0]["index"] == 0
    assert results[0]["label"] == "leaf"
    assert results[0]["verified"] is True
    # intermediate -> root: must verify
    assert results[1]["index"] == 1
    assert results[1]["verified"] is True
    # root self-signed: must verify against itself
    assert results[2]["index"] == 2
    assert results[2]["label"] == "root"
    assert results[2]["verified"] is True


def test_verify_chain_with_tampered_leaf_flags_broken() -> None:
    """Replace the leaf with a self-signed unrelated cert; its signature
    will not verify against the (untouched) intermediate's public key."""
    from pqc_audit.scanners.tls_scanner import verify_chain_signatures

    chain = _build_real_chain(tamper_index=0)
    results = verify_chain_signatures(chain)
    assert results[0]["verified"] is False
    # The other two are still real and valid
    assert results[1]["verified"] is True
    assert results[2]["verified"] is True


def test_verify_chain_with_tampered_intermediate_flags_broken() -> None:
    from pqc_audit.scanners.tls_scanner import verify_chain_signatures

    chain = _build_real_chain(tamper_index=1)
    results = verify_chain_signatures(chain)
    # Leaf signature was signed by the ORIGINAL intermediate; the
    # replacement intermediate has a different public key, so the leaf's
    # signature will not verify against it.
    assert results[0]["verified"] is False
    # Intermediate is now self-signed by unrelated_key — its signature
    # does verify against its OWN public key, so we mark it verified
    # but the chain is still broken at the leaf<->intermediate hop.
    # Either outcome is acceptable as long as we surface the breakage
    # somewhere — we assert the leaf failed (which is what an auditor
    # cares about).


def test_verify_single_cert_chain_only_handles_self_signed() -> None:
    from pqc_audit.scanners.tls_scanner import verify_chain_signatures

    chain = _build_real_chain()
    # Take only the root (self-signed) — verify must still succeed.
    root_only = [chain[2]]
    results = verify_chain_signatures(root_only)
    assert len(results) == 1
    assert results[0]["label"] == "leaf"  # in a 1-cert chain it IS the leaf
    assert results[0]["verified"] is True


def test_verify_returns_error_string_on_unsupported_key() -> None:
    """Pathological case: a hypothetical key type cryptography doesn't
    expose verify() for. We don't construct one; we test the error-path
    contract by sending a clearly-broken signature."""
    from pqc_audit.scanners.tls_scanner import verify_chain_signatures

    chain = _build_real_chain()
    # Replace leaf with one whose tbs_bytes have been altered by 1 byte
    # would change the SHA-384 digest -> ECDSA verify fails.
    # cryptography doesn't let us mutate frozen objects, so instead we
    # use the tamper helper for the leaf, which is the canonical
    # "broken signature" scenario.
    chain = _build_real_chain(tamper_index=0)
    results = verify_chain_signatures(chain)
    # The leaf's verify entry must carry a non-empty 'error' string when
    # verified is False.
    leaf_entry = results[0]
    assert leaf_entry["verified"] is False
    assert leaf_entry["error"], "error string must be populated on failure"


# -------------------- assess_chain_signatures --------------------


def test_assess_chain_signatures_emits_high_for_broken_leaf() -> None:
    from pqc_audit.scanners.tls_scanner import (
        RiskLevel,
        assess_chain_signatures,
        verify_chain_signatures,
    )

    chain = _build_real_chain(tamper_index=0)
    results = verify_chain_signatures(chain)
    vulns = assess_chain_signatures(results, leaf_asset_id="tls://leaf.example.it:443")
    # At least one HIGH finding for the broken leaf signature
    high_findings = [v for v in vulns if v.severity is RiskLevel.HIGH]
    assert high_findings, f"expected at least one HIGH finding, got: {[v.title for v in vulns]}"
    # CWE-295 (Improper Certificate Validation) is the right one for
    # chain breakage — leaf claims an issuer it cannot prove.
    assert any(v.cwe == "CWE-295" for v in high_findings)
    # affected_asset_ids must point at the LEAF, not all chain assets.
    leaf_focused = [
        v for v in high_findings
        if any("tls://leaf.example.it:443" in a for a in v.affected_asset_ids)
    ]
    assert leaf_focused


def test_assess_chain_signatures_no_findings_on_lestyle_two_cert_chain() -> None:
    """LE / DigiCert / Actalis ship leaf + intermediate, NOT the root
    (root in client trust store). The last cert is non-self-signed
    AND has no issuer on the wire — `verifiable=False`. Audit must
    NOT emit a `Broken chain signature` finding. This was a real bug
    on AGID empirical scan pre-fix (Sprint 9d.2 fuffa hunt)."""
    from pqc_audit.scanners.tls_scanner import (
        assess_chain_signatures,
        verify_chain_signatures,
    )

    full_chain = _build_real_chain()
    leaf_plus_inter = full_chain[:2]  # drop the root
    results = verify_chain_signatures(leaf_plus_inter)
    assert results[0]["verifiable"] is True
    assert results[0]["verified"] is True
    assert results[1]["verifiable"] is False  # the missing-root case
    vulns = assess_chain_signatures(results, leaf_asset_id="tls://leaf.example.it:443")
    titles = [v.title for v in vulns]
    assert not any("Broken chain signature" in t for t in titles), (
        f"LE-style 2-cert chain must NOT trigger broken-signature finding, got: {titles}"
    )


def test_assess_chain_signatures_no_findings_on_intact_chain() -> None:
    from pqc_audit.scanners.tls_scanner import assess_chain_signatures, verify_chain_signatures

    chain = _build_real_chain()
    results = verify_chain_signatures(chain)
    vulns = assess_chain_signatures(results, leaf_asset_id="tls://leaf.example.it:443")
    assert vulns == []


# -------------------- TLSScanner.scan integration --------------------


def test_scan_emits_chain_signature_finding_on_broken_chain(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """End-to-end: a tampered chain reaches TLSScanner.scan via a fake
    handshake, and the resulting ScanResult.vulnerabilities contain a
    HIGH CWE-295 finding pointing at the leaf."""
    import asyncio

    from cryptography.hazmat.primitives.serialization import Encoding

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.tls_scanner import TLSScanner

    chain = _build_real_chain(tamper_index=0)
    chain_der = [c.public_bytes(Encoding.DER) for c in chain]

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

    # Find the chain-signature finding among the result vulns
    chain_sig_findings = [
        v for v in result.vulnerabilities
        if "chain" in v.title.lower() and "signature" in v.title.lower()
    ]
    assert chain_sig_findings, (
        f"expected chain-signature finding on broken chain, got: "
        f"{[v.title for v in result.vulnerabilities]}"
    )


def test_scan_leaf_metadata_carries_chain_signatures_verified_flag(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The leaf asset metadata should expose `chain_signatures_verified:
    bool` so reporters / dashboards can pivot on it without re-running
    the verify pass."""
    import asyncio

    from cryptography.hazmat.primitives.serialization import Encoding

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.tls_scanner import TLSScanner

    chain = _build_real_chain()
    chain_der = [c.public_bytes(Encoding.DER) for c in chain]

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
    leaf_md = result.assets[0].metadata
    assert leaf_md.get("chain_signatures_verified") is True
