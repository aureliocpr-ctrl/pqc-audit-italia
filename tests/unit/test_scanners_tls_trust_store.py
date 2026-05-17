"""Tests for the cross-platform trust-store resolver — Sprint 9d.3.

Goal: distinguish "Let's Encrypt → ISRG Root X1 (commercial global CA)"
from "Aruba S.p.A. NG CA 3 (AgID-accredited qualified TSP)". eIDAS /
NIS2 audits care about CA pedigree because a qualified IT TSP confers
legal effects (eIDAS art. 25) that a commercial CA does not.

The resolver must:

* probe the local trust store with documented fallback order
  (Linux system bundle → certifi Mozilla bundle → none);
* honestly label the trust source as such (we never call certifi
  "the Windows trust store" because it is not);
* return ``resolved=False`` cleanly when the trust source is absent or
  the issuer is not in it, rather than crashing or guessing;
* skip lookup when the last chain element is self-signed (the server
  already shipped the root);
* classify the resolved root's pedigree as ``qualified_it_tsp`` /
  ``commercial_global`` / ``unknown`` using only stable RFC 4514
  subject substrings — anything else risks confabulating accreditation.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _make_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_self_signed(cn: str, key=None) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Build a self-signed cert (acts as root)."""
    key = key or _make_keypair()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn),
        ]
    )
    now = dt.datetime.now(tz=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_signed_by(
    cn: str, issuer_cert: x509.Certificate, issuer_key: rsa.RSAPrivateKey, *, is_ca: bool = False
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _make_keypair()
    now = dt.datetime.now(tz=dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn),
                ]
            )
        )
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def _write_pem_bundle(tmp_path: Path, certs: list[x509.Certificate]) -> Path:
    bundle = tmp_path / "trust.pem"
    blocks: list[bytes] = []
    for c in certs:
        blocks.append(c.public_bytes(serialization.Encoding.PEM))
    bundle.write_bytes(b"".join(blocks))
    return bundle


# ---------------------------------------------------------------------
# discover_trust_store_source
# ---------------------------------------------------------------------


def test_discover_returns_tuple_of_source_and_path() -> None:
    from pqc_audit.scanners.tls_trust_store import discover_trust_store_source

    src, path = discover_trust_store_source()
    assert src in {"system_ca_bundle", "certifi", "none"}
    if src == "none":
        assert path is None
    else:
        assert isinstance(path, str)
        assert Path(path).is_file()


def test_discover_picks_explicit_override_first(tmp_path: Path) -> None:
    """Sprint 9d.3 contract: callers may pass an explicit trust store
    path (e.g. for tests or for honoring SSL_CERT_FILE-style override)."""
    from pqc_audit.scanners.tls_trust_store import discover_trust_store_source

    cert, _ = _make_self_signed("ISRG Root X1")
    p = _write_pem_bundle(tmp_path, [cert])
    src, path = discover_trust_store_source(override=str(p))
    assert src == "override"
    assert path == str(p)


# ---------------------------------------------------------------------
# load_trust_store_subjects
# ---------------------------------------------------------------------


def test_load_indexes_certs_by_subject_dn(tmp_path: Path) -> None:
    from pqc_audit.scanners.tls_trust_store import load_trust_store_subjects

    isrg, _ = _make_self_signed("ISRG Root X1")
    aruba, _ = _make_self_signed("ArubaPEC S.p.A. NG CA 3")
    bundle = _write_pem_bundle(tmp_path, [isrg, aruba])

    idx = load_trust_store_subjects(str(bundle))
    # Keys are canonical (lowercase) — substring match against folded form.
    all_keys = "|".join(idx.keys())
    assert "isrg root x1" in all_keys
    assert "arubapec" in all_keys
    assert len(idx) == 2


def test_load_handles_garbage_in_bundle(tmp_path: Path) -> None:
    """Malformed bytes between PEM blocks must not abort the load."""
    from pqc_audit.scanners.tls_trust_store import load_trust_store_subjects

    cert, _ = _make_self_signed("Good CA")
    pem = cert.public_bytes(serialization.Encoding.PEM)
    bundle = tmp_path / "messy.pem"
    bundle.write_bytes(b"# comment\nnot a pem block\n" + pem + b"\nXXX garbage\n")
    idx = load_trust_store_subjects(str(bundle))
    assert len(idx) == 1


def test_load_returns_empty_on_missing_file(tmp_path: Path) -> None:
    from pqc_audit.scanners.tls_trust_store import load_trust_store_subjects

    idx = load_trust_store_subjects(str(tmp_path / "absent.pem"))
    assert idx == {}


# ---------------------------------------------------------------------
# classify_ca_pedigree
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "subject_dn",
    [
        "CN=ArubaPEC S.p.A. NG CA 3, O=Aruba PEC S.p.A., C=IT",
        "CN=InfoCert Certification Services CA 3, O=InfoCert S.p.A., C=IT",
        "CN=Namirial CA Standard Multi-usage, O=Namirial S.p.A., C=IT",
        "CN=PosteCert CA, O=Poste Italiane S.p.A., C=IT",
        "CN=Actalis Authentication Root CA, O=Actalis S.p.A., C=IT",
    ],
)
def test_classify_pedigree_qualified_it_tsp(subject_dn: str) -> None:
    from pqc_audit.scanners.tls_trust_store import classify_ca_pedigree

    assert classify_ca_pedigree(subject_dn) == "qualified_it_tsp"


@pytest.mark.parametrize(
    "subject_dn",
    [
        "CN=ISRG Root X1, O=Internet Security Research Group, C=US",
        "CN=DigiCert Global Root G2, O=DigiCert Inc, C=US",
        "CN=GlobalSign Root CA, O=GlobalSign nv-sa, C=BE",
        "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, C=GB",
        "CN=Let's Encrypt R3, O=Let's Encrypt, C=US",
    ],
)
def test_classify_pedigree_commercial_global(subject_dn: str) -> None:
    from pqc_audit.scanners.tls_trust_store import classify_ca_pedigree

    assert classify_ca_pedigree(subject_dn) == "commercial_global"


def test_classify_pedigree_unknown() -> None:
    from pqc_audit.scanners.tls_trust_store import classify_ca_pedigree

    assert classify_ca_pedigree("CN=Some Tiny Lab Internal Root, O=Tiny Lab, C=ZZ") == "unknown"


# ---------------------------------------------------------------------
# resolve_root_from_chain
# ---------------------------------------------------------------------


def test_resolve_root_finds_in_trust_store(tmp_path: Path) -> None:
    from pqc_audit.scanners.tls_trust_store import (
        load_trust_store_subjects,
        resolve_root_from_chain,
    )

    root, root_key = _make_self_signed("ArubaPEC S.p.A. NG CA 3")
    intermediate, intermediate_key = _make_signed_by(
        "ArubaPEC TLS CA", root, root_key, is_ca=True
    )
    leaf, _ = _make_signed_by("example.it", intermediate, intermediate_key)
    bundle = _write_pem_bundle(tmp_path, [root])
    idx = load_trust_store_subjects(str(bundle))

    out = resolve_root_from_chain([leaf, intermediate], idx)
    assert out["resolved"] is True
    assert out["source"] == "trust_store"
    assert "ArubaPEC" in out["root_subject"]
    assert out["pedigree"] == "qualified_it_tsp"
    assert out["root_signature_hash"]  # populated
    assert out["root_key_size"] == 2048
    assert out["root_algorithm"] == "RSA"


def test_resolve_root_when_last_cert_is_self_signed_uses_on_wire() -> None:
    """If the server shipped the root on the wire, skip trust store lookup."""
    from pqc_audit.scanners.tls_trust_store import resolve_root_from_chain

    root, root_key = _make_self_signed("ISRG Root X1")
    intermediate, intermediate_key = _make_signed_by("R3", root, root_key, is_ca=True)
    leaf, _ = _make_signed_by("example.com", intermediate, intermediate_key)

    out = resolve_root_from_chain([leaf, intermediate, root], trust_store={})
    assert out["resolved"] is True
    assert out["source"] == "on_wire"
    assert "ISRG" in out["root_subject"]
    assert out["pedigree"] == "commercial_global"


def test_resolve_root_not_found_in_trust_store_returns_unresolved() -> None:
    from pqc_audit.scanners.tls_trust_store import resolve_root_from_chain

    root, root_key = _make_self_signed("Some Tiny Lab Root")
    intermediate, intermediate_key = _make_signed_by(
        "Tiny Lab Intermediate", root, root_key, is_ca=True
    )
    leaf, _ = _make_signed_by("example.test", intermediate, intermediate_key)

    out = resolve_root_from_chain([leaf, intermediate], trust_store={})
    assert out["resolved"] is False
    assert out["source"] == "unknown"
    assert out["root_subject"] is None
    assert out["pedigree"] == "unknown"


def test_resolve_root_on_empty_chain_returns_unresolved() -> None:
    from pqc_audit.scanners.tls_trust_store import resolve_root_from_chain

    out = resolve_root_from_chain([], trust_store={})
    assert out["resolved"] is False
    assert out["source"] == "unknown"


def test_resolve_root_matches_across_rdn_order_and_case_and_whitespace(
    tmp_path: Path,
) -> None:
    """Real-world cross-sign case (e.g. GTS Root R4 cross-signed by
    GlobalSign Root CA) often presents the parent Name with a different
    RDN order than the bundle's stored copy. The canonical key must
    treat both forms as equivalent."""
    from pqc_audit.scanners.tls_trust_store import (
        load_trust_store_subjects,
        resolve_root_from_chain,
    )

    # Build a "trust-store" root whose stored subject differs from the
    # intermediate's issuer reference only in RDN order, case, and a
    # stray leading space — yet they must match.
    root_key = _make_keypair()
    root_subject_in_bundle = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Bar Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Foo Bar Root CA"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = dt.datetime.now(tz=dt.UTC)
    root = (
        x509.CertificateBuilder()
        .subject_name(root_subject_in_bundle)
        .issuer_name(root_subject_in_bundle)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    # Different attribute order, mixed case, extra whitespace.
    intermediate_issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, " foo bar root ca "),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FOO BAR INC"),
        ]
    )
    intermediate_key = _make_keypair()
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "Foo Bar Sub CA"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Foo Bar Inc"),
                ]
            )
        )
        .issuer_name(intermediate_issuer)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf, _ = _make_signed_by("example.test", intermediate, intermediate_key)
    bundle = _write_pem_bundle(tmp_path, [root])
    idx = load_trust_store_subjects(str(bundle))

    out = resolve_root_from_chain([leaf, intermediate], idx)
    assert out["resolved"] is True, "canonical Name match must succeed cross-encoding"
    assert out["source"] == "trust_store"
    assert "Foo Bar Root CA" in out["root_subject"]


def test_resolve_root_metadata_contains_required_keys(tmp_path: Path) -> None:
    """Stable schema: callers (markdown reporter) depend on these keys."""
    from pqc_audit.scanners.tls_trust_store import (
        load_trust_store_subjects,
        resolve_root_from_chain,
    )

    root, root_key = _make_self_signed("DigiCert Global Root G2")
    intermediate, intermediate_key = _make_signed_by(
        "DigiCert SHA2 Server CA", root, root_key, is_ca=True
    )
    leaf, _ = _make_signed_by("example.org", intermediate, intermediate_key)
    bundle = _write_pem_bundle(tmp_path, [root])
    idx = load_trust_store_subjects(str(bundle))

    out = resolve_root_from_chain([leaf, intermediate], idx)
    expected_keys = {
        "resolved",
        "source",
        "root_subject",
        "root_signature_hash",
        "root_key_size",
        "root_algorithm",
        "pedigree",
    }
    assert set(out.keys()) == expected_keys
