"""Tests for TLS leaf-cert revocation introspection (Sprint 9g.1, passive).

What "revocation introspection" means here:

* `Authority Information Access` extension (RFC 5280, OID
  ``1.3.6.1.5.5.7.1.1``) — extract OCSP responder URLs
  (id-ad-ocsp, `1.3.6.1.5.5.7.48.1`) and CA Issuers URLs
  (id-ad-caIssuers, `1.3.6.1.5.5.7.48.2`).
* `CRL Distribution Points` extension (RFC 5280, OID ``2.5.29.31``).
* `TLS Feature / OCSP Must-Staple` extension (RFC 7633, OID
  ``1.3.6.1.5.5.7.1.24``, feature value 5 = `status_request`).

This is a PASSIVE introspection — we do NOT fetch OCSP responses
nor download CRLs. Network probing of revocation endpoints is a
separate sprint (9g.2) because it raises operational concerns
(extra HTTP calls per audit, OCSP responder rate limits, etc.).

Real measurement that grounds these tests (2026-05-17):

* ``www.agid.gov.it:443`` leaf — AIA caIssuers only (Let's Encrypt
  retired OCSP in 2024), CRL DP ``http://e7.c.lencr.org/76.crl``,
  NO Must-Staple, NO OCSP responder URL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any


def _make_cert_with_extensions(
    *,
    ocsp_urls: list[str] | None = None,
    ca_issuers_urls: list[str] | None = None,
    crl_urls: list[str] | None = None,
    must_staple: bool = False,
) -> Any:
    """Build a self-signed cert with the requested revocation extensions."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import (
        AuthorityInformationAccessOID,
        NameOID,
    )

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.it")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
    )

    aia_descriptions: list[x509.AccessDescription] = []
    if ocsp_urls:
        for u in ocsp_urls:
            aia_descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.OCSP,
                    access_location=x509.UniformResourceIdentifier(u),
                )
            )
    if ca_issuers_urls:
        for u in ca_issuers_urls:
            aia_descriptions.append(
                x509.AccessDescription(
                    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                    access_location=x509.UniformResourceIdentifier(u),
                )
            )
    if aia_descriptions:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(aia_descriptions), critical=False
        )

    if crl_urls:
        dps = [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(u)],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
            for u in crl_urls
        ]
        builder = builder.add_extension(x509.CRLDistributionPoints(dps), critical=False)

    if must_staple:
        # TLS feature value 5 (status_request) per RFC 7633
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    return builder.sign(key, hashes.SHA256())


# -------------------- extract_revocation_info --------------------


def test_extract_revocation_info_empty_cert() -> None:
    """A cert with no AIA / CRL / TLSFeature ext returns empty lists."""
    from pqc_audit.scanners.tls_scanner import extract_revocation_info

    cert = _make_cert_with_extensions()  # no extensions
    info = extract_revocation_info(cert)
    assert info["ocsp_responder_urls"] == []
    assert info["ca_issuers_urls"] == []
    assert info["crl_distribution_points"] == []
    assert info["must_staple"] is False
    assert info["has_revocation_mechanism"] is False


def test_extract_revocation_info_full_cert() -> None:
    from pqc_audit.scanners.tls_scanner import extract_revocation_info

    cert = _make_cert_with_extensions(
        ocsp_urls=["http://ocsp.example.it/"],
        ca_issuers_urls=["http://ca.example.it/issuer.cer"],
        crl_urls=["http://crl.example.it/leaf.crl"],
        must_staple=True,
    )
    info = extract_revocation_info(cert)
    assert info["ocsp_responder_urls"] == ["http://ocsp.example.it/"]
    assert info["ca_issuers_urls"] == ["http://ca.example.it/issuer.cer"]
    assert info["crl_distribution_points"] == ["http://crl.example.it/leaf.crl"]
    assert info["must_staple"] is True
    assert info["has_revocation_mechanism"] is True


def test_extract_revocation_info_only_crl_no_ocsp() -> None:
    """Matches the post-2024 Let's Encrypt pattern (OCSP retired)."""
    from pqc_audit.scanners.tls_scanner import extract_revocation_info

    cert = _make_cert_with_extensions(
        ca_issuers_urls=["http://e7.i.lencr.org/"],
        crl_urls=["http://e7.c.lencr.org/76.crl"],
    )
    info = extract_revocation_info(cert)
    assert info["ocsp_responder_urls"] == []
    assert info["crl_distribution_points"] == ["http://e7.c.lencr.org/76.crl"]
    assert info["must_staple"] is False
    assert info["has_revocation_mechanism"] is True  # CRL counts


def test_extract_revocation_info_must_staple_only() -> None:
    from pqc_audit.scanners.tls_scanner import extract_revocation_info

    cert = _make_cert_with_extensions(must_staple=True)
    info = extract_revocation_info(cert)
    assert info["must_staple"] is True
    # has_revocation_mechanism is about CRL/OCSP URL presence, NOT Must-Staple
    assert info["has_revocation_mechanism"] is False


# -------------------- assess_revocation --------------------


def test_assess_no_revocation_mechanism_flags_low() -> None:
    """Cert with no AIA-OCSP and no CRL DP gets LOW finding."""
    from pqc_audit.scanners.tls_scanner import assess_revocation, extract_revocation_info

    cert = _make_cert_with_extensions()
    info = extract_revocation_info(cert)
    vulns = assess_revocation(info, asset_id="tls://example.it:443")
    titles = [v.title.lower() for v in vulns]
    assert any("no revocation" in t or "no ocsp" in t for t in titles)


def test_assess_must_staple_flags_info_positive() -> None:
    from pqc_audit.scanners.tls_scanner import (
        RiskLevel,
        assess_revocation,
        extract_revocation_info,
    )

    cert = _make_cert_with_extensions(
        ocsp_urls=["http://ocsp.example.it/"],
        must_staple=True,
    )
    info = extract_revocation_info(cert)
    vulns = assess_revocation(info, asset_id="tls://example.it:443")
    # Must-Staple is a POSITIVE finding (operational hygiene).
    must_staple_findings = [
        v for v in vulns if "must-staple" in v.title.lower() or "must_staple" in v.title.lower()
    ]
    assert must_staple_findings, f"expected Must-Staple finding, got: {[v.title for v in vulns]}"
    assert must_staple_findings[0].severity is RiskLevel.INFO


def test_assess_only_crl_no_ocsp_does_not_flag_missing_revocation() -> None:
    """Let's-Encrypt-style cert (CRL only) must NOT trigger 'no revocation'."""
    from pqc_audit.scanners.tls_scanner import assess_revocation, extract_revocation_info

    cert = _make_cert_with_extensions(
        ca_issuers_urls=["http://e7.i.lencr.org/"],
        crl_urls=["http://e7.c.lencr.org/76.crl"],
    )
    info = extract_revocation_info(cert)
    vulns = assess_revocation(info, asset_id="tls://www.agid.gov.it:443")
    titles = [v.title.lower() for v in vulns]
    assert not any("no revocation" in t or "no ocsp" in t for t in titles), (
        f"Cert with CRL should not be flagged 'no revocation', got: {titles}"
    )


# -------------------- TLSScanner.scan integration --------------------


def test_scan_leaf_metadata_carries_revocation_fields(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`TLSScanner.scan` must expose ocsp_responder_urls / crl_distribution_points
    / must_staple in the leaf asset metadata for downstream reporters.
    """
    import asyncio

    from cryptography.hazmat.primitives.serialization import Encoding

    from pqc_audit.scanners.base import ScanTarget
    from pqc_audit.scanners.tls_scanner import TLSScanner

    leaf = _make_cert_with_extensions(
        ca_issuers_urls=["http://e7.i.lencr.org/"],
        crl_urls=["http://e7.c.lencr.org/76.crl"],
    )
    chain_der = [leaf.public_bytes(Encoding.DER)]

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
    md = leaf_asset.metadata
    assert md.get("ocsp_responder_urls") == []
    assert md.get("crl_distribution_points") == ["http://e7.c.lencr.org/76.crl"]
    assert md.get("must_staple") is False
