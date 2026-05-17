"""SAML scanner — XMLDSig + XMLEnc algorithm enumeration.

Anchored to:
    * XML-Signature Syntax and Processing v1.1 (W3C, 2013).
    * XML Encryption Syntax and Processing v1.1 (W3C, 2013).
    * RFC 6931 — Additional XML Security URIs.
    * NIST SP 800-131A Rev. 2 (SHA-1 disallowed for signature
      generation).

The scanner walks every ``ds:SignatureMethod``, ``ds:DigestMethod`` and
``xenc:EncryptionMethod`` element it can find and reports the algorithm
URI plus a canonical :class:`Algorithm`.

XXE is mitigated by parsing through ``defusedxml`` — a hostile
``<!ENTITY ...>`` in a SAMLResponse cannot turn this scanner into a
local-file-read primitive.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqc_audit.core.models import RiskLevel, ScanCategory
from pqc_audit.scanners.base import ScanTarget

_SAML_SHA1 = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="#abc">
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</samlp:Response>
"""

_SAML_MODERN = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
  <xenc:EncryptedData>
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/>
  </xenc:EncryptedData>
</samlp:Response>
"""

_SAML_DEPRECATED_ENC = """<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptedData>
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
  </xenc:EncryptedData>
</samlp:Response>
"""

_SAML_XXE_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>
"""


def _run_scan(tmp_path: Path, content: str) -> object:
    from pqc_audit.scanners.saml_scanner import SAMLScanner

    f = tmp_path / "saml.xml"
    f.write_text(content, encoding="utf-8")
    scanner = SAMLScanner()
    target = ScanTarget(type="config", path=str(f))
    return asyncio.run(scanner.scan(target))


def test_saml_scanner_is_applicable_only_for_config(tmp_path: Path) -> None:
    from pqc_audit.scanners.saml_scanner import SAMLScanner

    scanner = SAMLScanner()
    assert scanner.name == "saml"
    assert scanner.category == ScanCategory.CONFIG
    ok = ScanTarget(type="config", path=str(tmp_path / "x.xml"))
    no = ScanTarget(type="tls", host="x.com", port=443)
    assert asyncio.run(scanner.is_applicable(ok)) is True
    assert asyncio.run(scanner.is_applicable(no)) is False


def test_saml_scanner_flags_sha1_signature_method(tmp_path: Path) -> None:
    result = _run_scan(tmp_path, _SAML_SHA1)
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert any("SHA-1" in v.title for v in high)
    assert any("CWE-327" in (v.cwe or "") for v in high)


def test_saml_scanner_classifies_modern_rsa_sha256(tmp_path: Path) -> None:
    result = _run_scan(tmp_path, _SAML_MODERN)
    names = {a.algorithm.canonical_name for a in result.assets}
    assert any("RSA-SHA-256" in n for n in names)
    assert any("AES-128-GCM" in n or n == "AES-128-GCM" for n in names)
    # Modern profile MUST NOT produce HIGH/CRITICAL findings.
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert not high


def test_saml_scanner_warns_on_aes_cbc_encryption(tmp_path: Path) -> None:
    result = _run_scan(tmp_path, _SAML_DEPRECATED_ENC)
    medium_or_higher = [
        v for v in result.vulnerabilities if v.severity >= RiskLevel.MEDIUM
    ]
    assert any("CBC" in v.title for v in medium_or_higher)


def test_saml_scanner_blocks_xxe(tmp_path: Path) -> None:
    # defusedxml must refuse to expand external entities.
    result = _run_scan(tmp_path, _SAML_XXE_PAYLOAD)
    assert result.errors
    # Critical: the scanner must NOT have read /etc/passwd into an asset.
    assert all("/etc/passwd" not in a.location for a in result.assets)


def test_saml_scanner_handles_no_signature(tmp_path: Path) -> None:
    content = (
        '<?xml version="1.0"?>'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'
    )
    result = _run_scan(tmp_path, content)
    assert result.assets == []
    assert result.vulnerabilities == []


def test_saml_scanner_missing_file(tmp_path: Path) -> None:
    from pqc_audit.scanners.saml_scanner import SAMLScanner

    scanner = SAMLScanner()
    target = ScanTarget(type="config", path=str(tmp_path / "nope.xml"))
    result = asyncio.run(scanner.scan(target))
    assert result.errors
    assert not result.assets


def test_saml_scanner_requires_path() -> None:
    from pqc_audit.scanners.saml_scanner import SAMLScanner

    scanner = SAMLScanner()
    with pytest.raises(ValueError):
        asyncio.run(scanner.scan(ScanTarget(type="config")))
