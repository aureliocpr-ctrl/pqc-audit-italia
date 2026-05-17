"""Cross-platform root-CA trust-store resolver — Sprint 9d.3.

A TLS audit that emits only the leaf + intermediates the server sent on
the wire is missing the most important question for an Italian PA
audit: *who is the trust anchor, and is it an AgID-accredited qualified
TSP?* The answer changes the legal effect (eIDAS art. 25) of every
signature the CA underwrites.

This module resolves the last chain element's issuer to a root cert
stored locally:

* :func:`discover_trust_store_source` — probes the local environment
  with documented fallback order:

    1. explicit ``override`` argument (caller-supplied path);
    2. Linux/macOS system CA bundle via
       :func:`ssl.get_default_verify_paths`;
    3. Mozilla CA bundle via ``certifi.where()`` (Windows and any
       portable Python install);
    4. ``("none", None)`` — caller must surface "trust store
       unavailable" rather than guessing.

  We never call certifi "the Windows trust store" because it isn't —
  certifi is the Mozilla bundle. The returned label says ``certifi``,
  not ``system_ca_bundle``, so the reporter can disclose the source
  honestly.

* :func:`load_trust_store_subjects` — parses a PEM bundle and returns
  ``{subject_rfc4514_string: x509.Certificate}``. Garbage between
  blocks is skipped silently (most distros ship comments and source
  attributions in ``/etc/ssl/certs/ca-certificates.crt``).

* :func:`classify_ca_pedigree` — labels the resolved root as
  ``qualified_it_tsp``, ``commercial_global``, or ``unknown`` based on
  stable subject substrings. The pattern lists are intentionally small
  and audit-trail-friendly: anything outside them is ``unknown``, not
  silently bucketed as commercial.

* :func:`resolve_root_from_chain` — the public entry point. Accepts the
  chain as it came from the server and the loaded trust store, and
  returns a 7-key dict that callers (markdown reporter, JSON reporter)
  consume.

Pedigree pattern sources:

* AgID Trusted List, https://eidas.agid.gov.it/TL/TSL-IT.xml — the
  official roster of Italian qualified TSPs.
* EU LOTL, https://ec.europa.eu/tools/lotl/eu-lotl.xml — the EU master
  Trusted List that aggregates all member states.

The pattern lists below are a hand-curated *subset* validated against
the AgID TSL on 2026-05-17. They are NOT a full catalogue. A root
matching no pattern is ``unknown`` — never ``commercial_global`` by
default, because the audit-trail cost of mislabeling a qualified TSP
as commercial would be high.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

# ---------------------------------------------------------------------
# Pedigree pattern tables (case-insensitive substring match).
# ---------------------------------------------------------------------

_QUALIFIED_IT_TSP_PATTERNS: tuple[str, ...] = (
    "aruba",
    "infocert",
    "namirial",
    "poste",
    "actalis",
    "trust italia",
    "incertum",
    "agid",
    "buffetti",
)

_COMMERCIAL_GLOBAL_PATTERNS: tuple[str, ...] = (
    "isrg",
    "let's encrypt",
    "digicert",
    "globalsign",
    "sectigo",
    "comodo",
    "godaddy",
    "geotrust",
    "thawte",
    "verisign",
    "entrust",
    "identrust",
    "amazon",
    "google trust services",
    "microsoft",
    "buypass",
    "starfield",
    "quovadis",
)


def classify_ca_pedigree(subject_dn: str) -> str:
    """Classify a CA subject DN as Italian qualified TSP, commercial
    global, or unknown. Italian patterns win over commercial in case
    of ambiguity — we err on the side of audit-trail safety.
    """
    s = subject_dn.lower()
    for p in _QUALIFIED_IT_TSP_PATTERNS:
        if p in s:
            return "qualified_it_tsp"
    for p in _COMMERCIAL_GLOBAL_PATTERNS:
        if p in s:
            return "commercial_global"
    return "unknown"


# ---------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------


def discover_trust_store_source(
    override: str | None = None,
) -> tuple[str, str | None]:
    """Return ``(source_name, path)`` for the local trust store.

    See module docstring for the full fallback chain. The returned
    label honestly distinguishes ``system_ca_bundle`` from
    ``certifi`` — they are different trust anchors with different
    governance.
    """
    if override:
        return ("override", override)

    paths = ssl.get_default_verify_paths()
    if paths.cafile and os.path.isfile(paths.cafile):
        return ("system_ca_bundle", paths.cafile)

    try:
        import certifi  # noqa: PLC0415 — lazy import: optional fallback dep
    except ImportError:
        return ("none", None)

    path = certifi.where()
    if os.path.isfile(path):
        return ("certifi", path)
    return ("none", None)


# ---------------------------------------------------------------------
# PEM bundle parser
# ---------------------------------------------------------------------


def _name_to_key(name: x509.Name) -> str:
    """Stable, hashable canonical form for an x509.Name.

    Two Names are considered equal when they have the same RDN attribute
    OIDs and values modulo:

    * attribute ordering (RDN order does NOT matter for equality);
    * leading/trailing whitespace within each attribute value;
    * letter case.

    This matches OpenSSL's normalized X509_NAME comparison far better
    than ``rfc4514_string()``, which preserves the on-cert encoding
    order. Cross-signed chains (e.g. GTS Root R4 issued under
    GlobalSign Root CA) typically encode the parent name with a
    different RDN order than the bundle's stored copy, so a literal
    rfc4514_string match silently fails — and we end up reporting
    ``resolved=False`` on widely-deployed CAs. The canonical key
    closes that gap.
    """
    attrs = sorted(
        f"{attr.oid.dotted_string}={str(attr.value).strip().lower()}"
        for rdn in name.rdns
        for attr in rdn
    )
    return "|".join(attrs)


def _split_pem_blocks(data: bytes) -> list[bytes]:
    """Extract individual CERTIFICATE PEM blocks, skipping any garbage."""
    out: list[bytes] = []
    start = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    i = 0
    while True:
        s = data.find(start, i)
        if s < 0:
            break
        e = data.find(end, s)
        if e < 0:
            break
        e_end = e + len(end)
        out.append(data[s:e_end])
        i = e_end
    return out


def load_trust_store_subjects(source_path: str) -> dict[str, x509.Certificate]:
    """Load ``source_path`` as a PEM bundle and index by RFC 4514 subject.

    Missing file / unreadable file / malformed blocks all return
    empty dict or skip silently — never raise. The caller already has
    a graceful "trust store unavailable" path.
    """
    if not source_path or not os.path.isfile(source_path):
        return {}
    try:
        data = Path(source_path).read_bytes()
    except OSError:
        return {}

    out: dict[str, x509.Certificate] = {}
    for block in _split_pem_blocks(data):
        try:
            cert = x509.load_pem_x509_certificate(block)
        except (ValueError, TypeError):
            continue
        key = _name_to_key(cert.subject)
        out[key] = cert
    return out


# ---------------------------------------------------------------------
# Root resolution
# ---------------------------------------------------------------------


def _algorithm_name(pk: Any) -> str:
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA"
    return "Unknown"


def _key_size_bits(pk: Any) -> int | None:
    if isinstance(pk, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        return pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return pk.curve.key_size
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return 256
    if isinstance(pk, ed448.Ed448PublicKey):
        return 456
    return None


def _build_root_metadata(cert: x509.Certificate, *, source: str) -> dict:
    subj = cert.subject.rfc4514_string()
    pk = cert.public_key()
    sig_hash = (
        cert.signature_hash_algorithm.name.upper()
        if cert.signature_hash_algorithm is not None
        else None
    )
    return {
        "resolved": True,
        "source": source,
        "root_subject": subj,
        "root_signature_hash": sig_hash,
        "root_key_size": _key_size_bits(pk),
        "root_algorithm": _algorithm_name(pk),
        "pedigree": classify_ca_pedigree(subj),
    }


_EMPTY_RESOLUTION: dict = {
    "resolved": False,
    "source": "unknown",
    "root_subject": None,
    "root_signature_hash": None,
    "root_key_size": None,
    "root_algorithm": None,
    "pedigree": "unknown",
}


def resolve_root_from_chain(
    chain: list[x509.Certificate],
    trust_store: dict[str, x509.Certificate],
) -> dict:
    """Resolve the trust anchor for ``chain``.

    Three outcomes:

    * **on_wire** — last cert is self-signed (subject == issuer); the
      server already shipped the root.
    * **trust_store** — last cert is non-self-signed, but its issuer
      subject is present in ``trust_store``.
    * **unknown** — neither of the above; ``resolved=False`` and the
      caller must surface "trust anchor not resolvable".
    """
    if not chain:
        return dict(_EMPTY_RESOLUTION)
    last = chain[-1]
    if last.subject == last.issuer:
        return _build_root_metadata(last, source="on_wire")
    issuer_key = _name_to_key(last.issuer)
    candidate = trust_store.get(issuer_key)
    if candidate is None:
        return dict(_EMPTY_RESOLUTION)
    return _build_root_metadata(candidate, source="trust_store")
