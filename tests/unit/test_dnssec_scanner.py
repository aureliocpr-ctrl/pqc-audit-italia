"""DNSSEC scanner — DNSKEY / RRSIG algorithm enumeration.

Coverage anchors:
    * IANA DNSSEC Algorithm Numbers registry.
    * RFC 8624 — Algorithm Implementation Requirements and Usage Guidance.
    * RFC 6944 — DNSKEY Algorithm Implementation Status.
    * draft-ietf-dnsop-dnssec-pqc — emerging PQC algorithms.

The scanner is offline: it parses ``dig +dnssec``-style output (or any
master/zone file with DNSKEY records) and reports the algorithms used.
Validation of signature chains is out of scope for v1.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqc_audit.core.models import RiskLevel, ScanCategory
from pqc_audit.scanners.base import ScanTarget

_DIG_FORMAT_EXAMPLE = """; <<>> DiG 9.18.27 <<>> +dnssec example.com DNSKEY
;; ANSWER SECTION:
example.com.        3600    IN  DNSKEY  256 3 8 AwEAAaz/tAm8yTn4Mfeh5e...
example.com.        3600    IN  DNSKEY  257 3 8 AwEAAagAIKlVZrpC6Ia7gE...
example.com.        3600    IN  RRSIG   DNSKEY 8 2 3600 20260601000000 ...
"""

_SHA1_DEPRECATED_ZONE = """sha1.example.com.   3600    IN  DNSKEY  257 3 7 AwEAAdummyKey...
sha1.example.com.   3600    IN  DNSKEY  256 3 5 AwEAAdummyKey...
"""

_PQC_DRAFT_ZONE = """pqc.example.com.    3600    IN  DNSKEY  257 3 17 AwEAAdummyMLDSAKey...
"""


def _run_scan(tmp_path: Path, content: str) -> object:
    from pqc_audit.scanners.dnssec_scanner import DNSSECScanner

    f = tmp_path / "zone.txt"
    f.write_text(content, encoding="utf-8")
    scanner = DNSSECScanner()
    target = ScanTarget(type="config", path=str(f))
    return asyncio.run(scanner.scan(target))


def test_dnssec_scanner_is_applicable_to_config_target(tmp_path: Path) -> None:
    from pqc_audit.scanners.dnssec_scanner import DNSSECScanner

    scanner = DNSSECScanner()
    assert scanner.name == "dnssec"
    assert scanner.category == ScanCategory.CONFIG
    target = ScanTarget(type="config", path=str(tmp_path / "z"))
    assert asyncio.run(scanner.is_applicable(target)) is True
    other = ScanTarget(type="tls", host="example.com", port=443)
    assert asyncio.run(scanner.is_applicable(other)) is False


def test_dnssec_scanner_parses_algorithm_8_rsa_sha256(tmp_path: Path) -> None:
    result = _run_scan(tmp_path, _DIG_FORMAT_EXAMPLE)
    assert result.scanner_name == "dnssec"
    # Algorithm 8 = RSA/SHA-256 (RFC 8624 RECOMMENDED). Two DNSKEY
    # records share the same algorithm; both should be discoverable.
    algos = [a.algorithm.canonical_name for a in result.assets]
    assert algos.count("RSA-SHA-256") >= 2
    # RECOMMENDED algo → no HIGH/CRITICAL finding.
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert not high


def test_dnssec_scanner_flags_sha1_algorithms(tmp_path: Path) -> None:
    result = _run_scan(tmp_path, _SHA1_DEPRECATED_ZONE)
    # Algorithm 5 = RSA/SHA-1 NOT RECOMMENDED (RFC 8624 §3.1).
    # Algorithm 7 = RSASHA1-NSEC3-SHA1 NOT RECOMMENDED.
    high = [v for v in result.vulnerabilities if v.severity >= RiskLevel.HIGH]
    assert len(high) >= 2
    assert all(("SHA-1" in v.title or "SHA1" in v.title.upper()) for v in high)


def test_dnssec_scanner_recognises_pqc_draft_algorithm(tmp_path: Path) -> None:
    # IANA tentatively reserved 17 for ML-DSA-44 (draft-ietf-dnsop-dnssec-pqc).
    result = _run_scan(tmp_path, _PQC_DRAFT_ZONE)
    asset = result.assets[0]
    assert asset.algorithm.name.startswith("ML-DSA")


def test_dnssec_scanner_handles_blank_lines_and_comments(tmp_path: Path) -> None:
    content = (
        "; comment line\n"
        "\n"
        "example.com.    3600    IN  DNSKEY  256 3 13 AwEAAdummy...\n"
        "; another comment\n"
        "example.com.    3600    IN  DNSKEY  256 3 15 AwEAAdummyEd25519...\n"
    )
    result = _run_scan(tmp_path, content)
    assert len(result.assets) == 2
    names = {a.algorithm.canonical_name for a in result.assets}
    assert "ECDSA-P-256-SHA-256" in names
    assert "Ed25519" in names


def test_dnssec_scanner_reports_unknown_algorithm(tmp_path: Path) -> None:
    # Algorithm 200 is private / reserved range, unknown to RFC 8624.
    content = "weird.example.com.  3600    IN  DNSKEY  257 3 200 AwEAAdummy...\n"
    result = _run_scan(tmp_path, content)
    assert len(result.assets) == 1
    medium = [v for v in result.vulnerabilities if v.severity >= RiskLevel.MEDIUM]
    assert any("unknown" in v.title.lower() for v in medium)


def test_dnssec_scanner_skips_malformed_records(tmp_path: Path) -> None:
    content = (
        "broken line without dnskey type\n"
        "example.com.    3600    IN  DNSKEY  not-a-number 3 8 key\n"
        "example.com.    3600    IN  DNSKEY  256 3 8 valid\n"
    )
    result = _run_scan(tmp_path, content)
    # The third line is parseable, prior two go into errors.
    assert len(result.assets) == 1
    assert result.errors


def test_dnssec_scanner_missing_file(tmp_path: Path) -> None:
    from pqc_audit.scanners.dnssec_scanner import DNSSECScanner

    scanner = DNSSECScanner()
    target = ScanTarget(type="config", path=str(tmp_path / "missing.txt"))
    result = asyncio.run(scanner.scan(target))
    assert result.errors
    assert not result.assets


def test_dnssec_scanner_requires_path() -> None:
    from pqc_audit.scanners.dnssec_scanner import DNSSECScanner

    scanner = DNSSECScanner()
    with pytest.raises(ValueError):
        asyncio.run(scanner.scan(ScanTarget(type="config")))
