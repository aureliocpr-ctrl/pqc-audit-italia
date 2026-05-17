"""Tests for the IaC scanner (Sprint 4 #3).

The scanner is regex-based and walks a directory or a single file
looking for cryptographic primitives in Terraform / CloudFormation /
Kubernetes manifests. These tests pin the v1 pattern catalog so
regressions in the regex set surface immediately.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from pqc_audit.core.models import RiskLevel
from pqc_audit.scanners.base import ScanTarget
from pqc_audit.scanners.iac_scanner import IaCScanner

# --- helpers ---------------------------------------------------------


def _run(scanner: IaCScanner, target: ScanTarget):
    return asyncio.run(scanner.scan(target))


# --- per-pattern detection -------------------------------------------


def test_iac_scanner_flags_rsa_2048_kms_key_as_high(tmp_path: Path) -> None:
    tf = tmp_path / "kms.tf"
    tf.write_text(
        'resource "aws_kms_key" "main" {\n  customer_master_key_spec = "RSA_2048"\n}\n',
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    assert result.assets, "scanner did not surface any asset"
    assert result.vulnerabilities, "scanner did not produce any vulnerability"
    titles = [v.title for v in result.vulnerabilities]
    assert any("RSA-2048" in t for t in titles)
    severities = {v.severity for v in result.vulnerabilities}
    assert RiskLevel.HIGH in severities


def test_iac_scanner_flags_rsa_1024_acm_as_critical(tmp_path: Path) -> None:
    tf = tmp_path / "acm.tf"
    tf.write_text(
        'resource "aws_acm_certificate" "legacy" {\n  key_algorithm = "RSA_1024"\n}\n',
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    severities = {v.severity for v in result.vulnerabilities}
    assert RiskLevel.CRITICAL in severities


def test_iac_scanner_flags_tls_1_0_pinning_in_yaml(tmp_path: Path) -> None:
    """K8s / ALB-style YAML pinning TLS 1.0 must be flagged CRITICAL."""
    yaml_file = tmp_path / "ingress.yaml"
    yaml_file.write_text(
        "spec:\n  tls:\n    tls_version: TLSv1.0\n",
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    titles = [v.title for v in result.vulnerabilities]
    assert any("TLS 1.0" in t for t in titles)
    assert any(v.severity == RiskLevel.CRITICAL for v in result.vulnerabilities)


def test_iac_scanner_flags_rc4_3des_md5_sha1_as_distinct_tokens(tmp_path: Path) -> None:
    """Forbidden primitives appearing as distinct tokens are surfaced.

    The regex uses ``\\b`` word boundaries to avoid false positives on
    brand names like ``ELBSecurityPolicy-WithRC4`` (no boundary before
    "RC4"). The test inputs simulate a cipher list and a comment-free
    string literal where the primitives appear bounded.
    """
    tf = tmp_path / "listener.tf"
    tf.write_text(
        'resource "aws_lb_listener" "weak" {\n'
        '  ciphers = "RC4-SHA:DES-CBC3-SHA"\n'
        '  digest = "MD5"\n'
        '  legacy_digest = "SHA-1"\n'
        "}\n",
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    titles = " || ".join(v.title for v in result.vulnerabilities)
    assert "RC4" in titles
    # MD5 and SHA-1 must surface as their own findings.
    assert "MD5" in titles
    assert "SHA-1" in titles


def test_iac_scanner_does_not_false_positive_on_brand_names_with_substrings(tmp_path: Path) -> None:
    """`ELBSecurityPolicy-WithRC4` is a brand name, not a cipher choice."""
    tf = tmp_path / "policy.tf"
    tf.write_text(
        "# AWS predefined policy name; the policy may or may not include RC4 internally.\n"
        'ssl_policy = "ELBSecurityPolicy-WithRC4"\n',
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    titles = " || ".join(v.title for v in result.vulnerabilities)
    # No RC4 finding — there's no word-bounded "RC4" token in the value.
    assert "RC4" not in titles


def test_iac_scanner_suppresses_findings_inside_terraform_comments(tmp_path: Path) -> None:
    """3DES inside a `#` Terraform comment must be suppressed by the comment stripper."""
    tf = tmp_path / "history.tf"
    tf.write_text(
        'resource "aws_lb_listener" "x" {\n  # historical: 3DES used to be the fallback\n}\n',
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    titles = " || ".join(v.title for v in result.vulnerabilities)
    assert "3DES" not in titles


def test_iac_scanner_strips_terraform_comments_to_reduce_noise(tmp_path: Path) -> None:
    """`# RSA_2048` inside a comment must NOT count as a finding."""
    tf = tmp_path / "comment_only.tf"
    tf.write_text(
        "# we historically used customer_master_key_spec = RSA_2048 here\n# nothing else to do\n",
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    assert result.vulnerabilities == []
    assert result.assets == []


def test_iac_scanner_handles_single_file_target(tmp_path: Path) -> None:
    tf = tmp_path / "single.tf"
    tf.write_text('customer_master_key_spec = "RSA_4096"\n', encoding="utf-8")
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tf)))
    assert any("RSA-4096" in v.title for v in result.vulnerabilities)


def test_iac_scanner_missing_path_records_error(tmp_path: Path) -> None:
    bogus = tmp_path / "does_not_exist"
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(bogus)))
    assert result.assets == []
    assert result.vulnerabilities == []
    assert result.errors
    assert "does not exist" in result.errors[0]


def test_iac_scanner_rejects_target_without_path() -> None:
    with pytest.raises(ValueError, match="requires target.path"):
        _run(IaCScanner(), ScanTarget(type="iac"))


def test_iac_scanner_is_applicable_only_for_iac_type() -> None:
    scanner = IaCScanner()
    assert asyncio.run(scanner.is_applicable(ScanTarget(type="iac", path="."))) is True
    assert asyncio.run(scanner.is_applicable(ScanTarget(type="tls", host="x"))) is False


def test_iac_scanner_walks_terraform_and_yaml_in_same_directory(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'customer_master_key_spec = "ECC_NIST_P256"\n', encoding="utf-8"
    )
    (tmp_path / "ingress.yaml").write_text("minimumProtocolVersion: TLSv1.1\n", encoding="utf-8")
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    titles = " || ".join(v.title for v in result.vulnerabilities)
    assert "ECDSA-P256" in titles
    assert "TLS 1.1" in titles


def test_iac_scanner_skips_oversize_files(tmp_path: Path) -> None:
    """Files larger than _MAX_FILE_BYTES (5 MiB) must be skipped."""
    from pqc_audit.scanners import iac_scanner as iac_mod

    big = tmp_path / "huge.tf"
    # Create a 6 MiB file with content that would otherwise trigger a finding.
    payload = 'customer_master_key_spec = "RSA_2048"\n'
    repeat = (iac_mod._MAX_FILE_BYTES // len(payload)) + 1024
    big.write_text(payload * repeat, encoding="utf-8")
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    # No finding because the oversize file is skipped.
    assert not any("RSA-2048" in v.title for v in result.vulnerabilities)
    assert any("oversize" in e for e in result.errors)


def test_iac_scanner_asset_metadata_includes_iac_file_and_line(tmp_path: Path) -> None:
    tf = tmp_path / "subdir" / "kms.tf"
    tf.parent.mkdir()
    tf.write_text(
        '# header\ncustomer_master_key_spec = "RSA_2048"\n',
        encoding="utf-8",
    )
    result = _run(IaCScanner(), ScanTarget(type="iac", path=str(tmp_path)))
    assert result.assets, "expected at least one asset"
    md = result.assets[0].metadata
    assert "iac_file" in md
    assert "line" in md
    assert md["line"] == "2"
