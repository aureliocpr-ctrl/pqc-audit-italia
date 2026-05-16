"""SAML scanner — XMLDSig + XMLEnc algorithm enumeration.

Walks the XML tree of a SAMLResponse / SAMLRequest / Assertion / IdP
metadata file and reports every ``SignatureMethod``, ``DigestMethod``
and ``EncryptionMethod`` algorithm URI found.

Anchored to:

    * XML-Signature Syntax and Processing v1.1 (W3C, 2013).
    * XML Encryption Syntax and Processing v1.1 (W3C, 2013).
    * RFC 6931 — Additional XML Security URIs.

Security note (CWE-611, CWE-776):
    Parsing untrusted SAML is one of the classic XXE vectors. We parse
    through ``defusedxml.ElementTree`` so a hostile ``<!ENTITY xxe
    SYSTEM "file:///etc/passwd">`` cannot leak local file content into
    the audit output. ``defusedxml`` raises a dedicated exception that
    we surface via ``ScanResult.errors`` rather than crashing the run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from defusedxml import ElementTree as DET  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element


@dataclass(frozen=True, slots=True)
class _AlgoSpec:
    name: str
    key_size_bits: int | None
    mode: str | None
    severity: RiskLevel  # what to report when the URI is encountered
    why: str


# Registry of XMLDSig / XMLEnc URIs. Severity reflects 2026 best
# practice (SHA-1 / CBC / 3DES = HIGH or CRITICAL, GCM / SHA-256+ = INFO).
_URI_REGISTRY: dict[str, _AlgoSpec] = {
    # ----- Signature methods -----
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1": _AlgoSpec(
        "DSA-SHA-1",
        None,
        None,
        RiskLevel.HIGH,
        "DSA with SHA-1 is forbidden by NIST SP 800-131A Rev. 2.",
    ),
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": _AlgoSpec(
        "RSA-SHA-1",
        None,
        None,
        RiskLevel.HIGH,
        "RSA signatures with SHA-1 are forbidden by NIST SP 800-131A Rev. 2.",
    ),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": _AlgoSpec(
        "RSA-SHA-256", None, None, RiskLevel.INFO, "RSA-SHA-256 is acceptable."
    ),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": _AlgoSpec(
        "RSA-SHA-384", None, None, RiskLevel.INFO, "RSA-SHA-384 is acceptable."
    ),
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": _AlgoSpec(
        "RSA-SHA-512", None, None, RiskLevel.INFO, "RSA-SHA-512 is acceptable."
    ),
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": _AlgoSpec(
        "RSA-PSS-SHA-256", None, "PSS", RiskLevel.INFO, "RSA-PSS-SHA-256 is acceptable."
    ),
    "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": _AlgoSpec(
        "RSA-PSS-SHA-512", None, "PSS", RiskLevel.INFO, "RSA-PSS-SHA-512 is acceptable."
    ),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": _AlgoSpec(
        "ECDSA-SHA-256", None, None, RiskLevel.INFO, "ECDSA-SHA-256 is acceptable."
    ),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": _AlgoSpec(
        "ECDSA-SHA-384", None, None, RiskLevel.INFO, "ECDSA-SHA-384 is acceptable."
    ),
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": _AlgoSpec(
        "ECDSA-SHA-512", None, None, RiskLevel.INFO, "ECDSA-SHA-512 is acceptable."
    ),
    # ----- Digest methods -----
    "http://www.w3.org/2000/09/xmldsig#sha1": _AlgoSpec(
        "SHA-1",
        None,
        None,
        RiskLevel.HIGH,
        "SHA-1 digest is collision-vulnerable (Shattered, 2017).",
    ),
    "http://www.w3.org/2001/04/xmlenc#sha256": _AlgoSpec(
        "SHA-256", None, None, RiskLevel.INFO, "SHA-256 digest is acceptable."
    ),
    "http://www.w3.org/2001/04/xmldsig-more#sha384": _AlgoSpec(
        "SHA-384", None, None, RiskLevel.INFO, "SHA-384 digest is acceptable."
    ),
    "http://www.w3.org/2001/04/xmlenc#sha512": _AlgoSpec(
        "SHA-512", None, None, RiskLevel.INFO, "SHA-512 digest is acceptable."
    ),
    # ----- Encryption methods -----
    "http://www.w3.org/2001/04/xmlenc#tripledes-cbc": _AlgoSpec(
        "3DES",
        168,
        "CBC",
        RiskLevel.CRITICAL,
        "3DES has been retired by NIST as of SP 800-131A Rev. 2.",
    ),
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc": _AlgoSpec(
        "AES",
        128,
        "CBC",
        RiskLevel.MEDIUM,
        "AES-128-CBC in SAML is exposed to padding-oracle attacks; prefer AES-GCM.",
    ),
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc": _AlgoSpec(
        "AES",
        192,
        "CBC",
        RiskLevel.MEDIUM,
        "AES-192-CBC in SAML is exposed to padding-oracle attacks; prefer AES-GCM.",
    ),
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc": _AlgoSpec(
        "AES",
        256,
        "CBC",
        RiskLevel.MEDIUM,
        "AES-256-CBC in SAML is exposed to padding-oracle attacks; prefer AES-GCM.",
    ),
    "http://www.w3.org/2009/xmlenc11#aes128-gcm": _AlgoSpec(
        "AES",
        128,
        "GCM",
        RiskLevel.INFO,
        "AES-128-GCM is the recommended XMLEnc cipher.",
    ),
    "http://www.w3.org/2009/xmlenc11#aes192-gcm": _AlgoSpec(
        "AES",
        192,
        "GCM",
        RiskLevel.INFO,
        "AES-192-GCM is acceptable.",
    ),
    "http://www.w3.org/2009/xmlenc11#aes256-gcm": _AlgoSpec(
        "AES",
        256,
        "GCM",
        RiskLevel.INFO,
        "AES-256-GCM is acceptable.",
    ),
}


# Tag local-names we care about. We strip the XML namespace so the
# scanner works with either ``ds:SignatureMethod`` or any other prefix.
_TARGET_LOCAL_TAGS = {
    "SignatureMethod",
    "DigestMethod",
    "EncryptionMethod",
}


def _local_tag(qname: str) -> str:
    """Return the local part of a ``{ns}name`` QName, or the input if unprefixed."""
    if qname.startswith("{"):
        return qname.split("}", 1)[1]
    return qname


def _classify(uri: str) -> tuple[Algorithm, _AlgoSpec | None]:
    spec = _URI_REGISTRY.get(uri)
    if spec is None:
        return Algorithm(name=f"SAML-URI:{uri}"), None
    return (
        Algorithm(name=spec.name, key_size_bits=spec.key_size_bits, mode=spec.mode),
        spec,
    )


def _make_vulnerability(
    spec: _AlgoSpec, uri: str, asset_id: str, tag_name: str
) -> Vulnerability | None:
    if spec.severity <= RiskLevel.LOW:
        return None
    cwe = "CWE-327" if spec.severity >= RiskLevel.HIGH else "CWE-326"
    title_prefix = (
        f"SAML {tag_name} uses SHA-1"
        if "SHA-1" in spec.name and tag_name != "EncryptionMethod"
        else f"SAML {tag_name} uses {spec.mode}"
        if spec.mode == "CBC"
        else f"SAML {tag_name} uses {spec.name}"
    )
    return Vulnerability(
        title=title_prefix,
        description=spec.why + f" (URI: {uri})",
        severity=spec.severity,
        cwe=cwe,
        references=(
            "https://www.w3.org/TR/xmldsig-core1/",
            "https://www.w3.org/TR/xmlenc-core1/",
        ),
        affected_asset_ids=(asset_id,),
    )


class SAMLScanner:
    """Offline SAML / XMLDSig / XMLEnc algorithm enumerator."""

    name = "saml"
    category = ScanCategory.CONFIG

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "config"

    async def scan(self, target: ScanTarget) -> ScanResult:
        if target.path is None:
            raise ValueError("SAML scanner requires target.path pointing to an XML file")

        started_at = datetime.now(UTC)
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        path = Path(target.path)

        if not path.is_file():  # noqa: ASYNC240 — protocol-async, local fs metadata
            errors.append(f"SAML XML file not found: {path}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=datetime.now(UTC),
                errors=errors,
            )

        try:
            tree = DET.parse(str(path))
        except DefusedXmlException as e:
            errors.append(f"refused by defusedxml (likely XXE / billion laughs): {e}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=datetime.now(UTC),
                errors=errors,
            )
        except Exception as e:
            errors.append(f"could not parse SAML XML: {type(e).__name__}: {e}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=datetime.now(UTC),
                errors=errors,
            )

        root: Element = tree.getroot()
        for elem in root.iter():
            local = _local_tag(elem.tag)
            if local not in _TARGET_LOCAL_TAGS:
                continue
            uri = elem.get("Algorithm")
            if not uri:
                continue
            algo, spec = _classify(uri)
            asset_id = f"saml://{path.name}#{local}:{uri}"
            asset = CryptoAsset(
                asset_id=asset_id,
                category=ScanCategory.CONFIG,
                algorithm=algo,
                location=f"{path}:{local}",
                discovered_at=datetime.now(UTC),
                metadata={
                    "xml_local_name": local,
                    "algorithm_uri": uri,
                    "rfc_status": (spec.why if spec else "unknown URI"),
                },
            )
            assets.append(asset)
            if spec is not None:
                vuln = _make_vulnerability(spec, uri, asset_id, local)
                if vuln is not None:
                    vulns.append(vuln)
            else:
                vulns.append(
                    Vulnerability(
                        title=f"SAML {local} uses unknown algorithm URI",
                        description=(
                            f"The SAML document references {uri!r} which is "
                            "not in the XMLDSig/XMLEnc registry as of 2026. "
                            "Verify the issuer is not silently downgrading."
                        ),
                        severity=RiskLevel.MEDIUM,
                        cwe="CWE-757",
                        references=("https://www.iana.org/assignments/xml-security-uris/",),
                        affected_asset_ids=(asset_id,),
                    )
                )

        return ScanResult(
            scanner_name=self.name,
            target=str(path),
            assets=assets,
            vulnerabilities=vulns,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            errors=errors,
        )


__all__ = ["SAMLScanner"]
