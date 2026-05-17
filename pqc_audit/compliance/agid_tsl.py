"""AgID Trusted List (ETSI TS 119 612) parser — Sprint 9d.5.

The AgID Trusted List (TSL) is the AUTHORITATIVE roster of qualified
Trust Service Providers in Italy under eIDAS Regulation (EU)
910/2014. Published at https://eidas.agid.gov.it/TL/TSL-IT.xml as
an XML signed document conformant to ETSI TS 119 612 v2.1.1.

Cross-checking a resolved root CA against the live TSL — not just
against a hand-curated pattern list — is what makes the pedigree
classification *legal-grade*: a cert whose subject is named in the
TSL today is, by definition, on the qualified register.

This module ships:

* :data:`AGID_TSL_URL` — the official endpoint.
* :data:`SERVICE_TYPE_QUALIFIED_CA` — the ETSI URI for qualified
  CAs (``http://uri.etsi.org/TrstSvc/Svctype/CA/QC``).
* :func:`fetch_agid_tsl` — HTTPS GET via :mod:`httpx`, wrapped to
  surface a typed :class:`AgIDTSLFetchError` on network failure.
* :func:`parse_agid_tsl` — XML walker, returns
  ``{"tsps": list[str], "qualified_certs": list[bytes]}``.
* :func:`is_subject_in_tsl` — canonical-name cross-check, reuses
  the RDN-order / case / whitespace insensitive key from
  :mod:`pqc_audit.scanners.tls_trust_store`.

We deliberately do NOT verify the TSL's XML signature in this
sprint — that requires the EU LOTL signer pin + XMLDSig path
which is a multi-day project on its own. Honest gap documented
below; the cross-check still has audit value because the parser
exercises the same XML structure a downstream signature verifier
would.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET  # noqa: S405 — AgID TSL is trusted-source XML, no XXE risk via httpx GET over HTTPS
from typing import Any

import httpx
from cryptography import x509

from pqc_audit.scanners.tls_trust_store import _name_to_key

AGID_TSL_URL: str = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
SERVICE_TYPE_QUALIFIED_CA: str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"

_TSL_NS = "http://uri.etsi.org/02231/v2#"
_XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

# Default HTTP timeout when fetching the live TSL.
_DEFAULT_FETCH_TIMEOUT_SECONDS: float = 30.0


class AgIDTSLFetchError(RuntimeError):
    """Raised when the AgID TSL endpoint cannot be reached."""


class AgIDTSLParseError(ValueError):
    """Raised when the AgID TSL XML cannot be parsed."""


def fetch_agid_tsl(
    url: str = AGID_TSL_URL,
    *,
    timeout: float = _DEFAULT_FETCH_TIMEOUT_SECONDS,
) -> bytes:
    """Fetch the published AgID Trusted List XML over HTTPS.

    Returns the raw bytes. Raises :class:`AgIDTSLFetchError` on any
    network or HTTP-status failure — the caller decides how to
    degrade (typically: log warning, continue without TSL).
    """
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise AgIDTSLFetchError(f"failed to fetch AgID TSL: {exc}") from exc
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise AgIDTSLFetchError(f"AgID TSL HTTP error: {exc}") from exc
    return response.content


def _local_name(tag: str) -> str:
    """Strip the ``{namespace}`` prefix from an ElementTree tag."""
    return tag.split("}", 1)[1] if "}" in tag else tag


def _findall_local(root: ET.Element, local_tag: str) -> list[ET.Element]:
    """Find all descendants whose local name matches ``local_tag``, ignoring NS."""
    out: list[ET.Element] = []
    for el in root.iter():
        if _local_name(el.tag) == local_tag:
            out.append(el)
    return out


def parse_agid_tsl(xml_bytes: bytes) -> dict[str, Any]:  # noqa: PLR0912
    """Parse the TSL XML and extract TSP names + qualified-CA cert DER blobs.

    The walker is **namespace-tolerant**: it matches by local element
    name, so a small re-namespace by AgID would not break the parser.

    Returns ``{"tsps": [...], "qualified_certs": [DER_bytes, ...]}``.
    Both lists are de-duplicated. Raises :class:`AgIDTSLParseError`
    on malformed XML.
    """
    try:
        root = ET.fromstring(xml_bytes)  # noqa: S314 — AgID HTTPS source
    except ET.ParseError as exc:
        raise AgIDTSLParseError(f"malformed TSL XML: {exc}") from exc

    if _local_name(root.tag) != "TrustServiceStatusList":
        raise AgIDTSLParseError(
            f"unexpected root element: {_local_name(root.tag)!r} "
            f"(expected TrustServiceStatusList)"
        )

    tsps: list[str] = []
    seen_tsp: set[str] = set()
    qualified_certs: list[bytes] = []
    seen_cert: set[bytes] = set()

    for tsp in _findall_local(root, "TrustServiceProvider"):
        # TSP name(s) — there may be multiple localizations; we take
        # the first non-empty one and dedup by exact string.
        for name_el in _findall_local(tsp, "TSPName"):
            for child in name_el:
                if _local_name(child.tag) == "Name":
                    text = (child.text or "").strip()
                    if text and text not in seen_tsp:
                        tsps.append(text)
                        seen_tsp.add(text)
                    break
            break  # only first TSPName per TSP

        # For each service, only QC CA services contribute certs.
        for service in _findall_local(tsp, "TSPService"):
            stype_els = _findall_local(service, "ServiceTypeIdentifier")
            if not stype_els:
                continue
            stype = (stype_els[0].text or "").strip()
            if stype != SERVICE_TYPE_QUALIFIED_CA:
                continue
            for cert_el in _findall_local(service, "X509Certificate"):
                raw = (cert_el.text or "").strip()
                if not raw:
                    continue
                try:
                    der = _b64decode_loose(raw)
                except ValueError:
                    continue
                if der not in seen_cert:
                    qualified_certs.append(der)
                    seen_cert.add(der)

    return {"tsps": tsps, "qualified_certs": qualified_certs}


def _b64decode_loose(s: str) -> bytes:
    """Decode base64 tolerating whitespace and PEM-style line wraps."""
    cleaned = "".join(s.split())
    return base64.b64decode(cleaned)


def _qualified_subject_keys(tsl_data: dict[str, Any]) -> set[str]:
    """Return canonical-Name keys for every qualified-CA cert in the TSL."""
    out: set[str] = set()
    for der in tsl_data.get("qualified_certs", []):
        try:
            cert = x509.load_der_x509_certificate(der)
        except (ValueError, TypeError):
            continue
        out.add(_name_to_key(cert.subject))
    return out


def is_subject_in_tsl(subject_dn: str, tsl_data: dict[str, Any]) -> bool:
    """Cross-check ``subject_dn`` against the qualified-CA subjects in the TSL.

    Matching uses :func:`pqc_audit.scanners.tls_trust_store._name_to_key`,
    so RDN ordering / case / whitespace differences do not produce
    false negatives.
    """
    try:
        probe_name = x509.Name.from_rfc4514_string(subject_dn)
    except (ValueError, TypeError):
        return False
    probe_key = _name_to_key(probe_name)
    return probe_key in _qualified_subject_keys(tsl_data)
