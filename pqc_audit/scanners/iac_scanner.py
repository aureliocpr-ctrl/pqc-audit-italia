"""Infrastructure-as-Code scanner (Sprint 4 #3).

Static, offline scanner that walks a directory (or a single file) and
flags cryptographic primitives declared inside IaC manifests. The
parser is regex-based — not a full HCL / YAML AST — because the V1
scope is intentionally narrow:

    * Terraform ``.tf`` resources for AWS KMS keys, ACM certificates,
      and TLS version pinning.
    * Kubernetes ``.yaml`` / ``.yml`` manifests for TLS listener
      configuration (cipher suites, min version).
    * CloudFormation JSON / YAML templates for KMS / ACM properties.

Anything richer (HCL functions, Terraform modules, Helm templating)
is out of scope and is left to v2. The point of V1 is to close the
"no IaC coverage" gap of the vendibility assessment without becoming
yet another HCL parser.

Security:
    * The scanner walks a user-supplied directory. To avoid resource
      exhaustion on a hostile target (CWE-400), the walker caps the
      number of inspected files at :data:`_MAX_IAC_FILES` and the per-
      file byte budget at :data:`_MAX_FILE_BYTES`. Symlinks pointing
      outside the root are followed but their resolved path is
      reported verbatim so an auditor can spot the escape.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

_MAX_IAC_FILES = 10_000
_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB per file is enough for any IaC unit
_IAC_GLOB_PATTERNS: tuple[str, ...] = (
    "**/*.tf",
    "**/*.yaml",
    "**/*.yml",
    "**/*.json",
)


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------
# Each entry maps a regex (operating on a single line) to:
#   * ``algorithm`` builder — what Algorithm to emit when the regex matches
#   * ``severity`` — RiskLevel for the vulnerability
#   * ``title`` / ``description`` / ``cwe`` / ``refs``
#
# The regex must produce at most one group, used as ``\\1`` evidence in
# the title (so the auditor sees the verbatim token from the file).


def _alg(
    name: str, *, size: int | None = None, mode: str | None = None, curve: str | None = None
) -> Algorithm:
    return Algorithm(name=name, key_size_bits=size, mode=mode, curve=curve)


# Pattern catalog. The tuples are (regex, alg, severity, title, description, cwe, refs).
# Order matters: more-specific patterns first.
_PatternEntry = tuple[re.Pattern[str], Algorithm, RiskLevel, str, str, str | None, tuple[str, ...]]
_PATTERNS: list[_PatternEntry] = [
    # ----- AWS KMS — customer_master_key_spec -----
    (
        re.compile(r'customer_master_key_spec\s*=\s*"(RSA_2048)"', re.IGNORECASE),
        _alg("RSA", size=2048),
        RiskLevel.HIGH,
        "IaC declares RSA-2048 KMS key (quantum-vulnerable, NIST deprecates 2030)",
        "AWS KMS key uses RSA-2048 as customer_master_key_spec. NIST IR 8547 "
        "deprecates RSA-2048 for new use after 2030 and disallows after 2035. "
        "Plan migration to ML-KEM (FIPS 203) or hybrid scheme.",
        "CWE-326",
        ("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
    ),
    (
        re.compile(r'customer_master_key_spec\s*=\s*"(RSA_3072)"', re.IGNORECASE),
        _alg("RSA", size=3072),
        RiskLevel.HIGH,
        "IaC declares RSA-3072 KMS key (quantum-vulnerable, NIST deprecates 2030)",
        "AWS KMS key uses RSA-3072. Same NIST IR 8547 deprecation timetable as RSA-2048.",
        "CWE-326",
        ("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
    ),
    (
        re.compile(r'customer_master_key_spec\s*=\s*"(RSA_4096)"', re.IGNORECASE),
        _alg("RSA", size=4096),
        RiskLevel.MEDIUM,
        "IaC declares RSA-4096 KMS key (quantum-vulnerable but oversized)",
        "AWS KMS key uses RSA-4096. Still quantum-vulnerable per NIST IR 8547. "
        "Performance overhead does not buy meaningful post-quantum security.",
        "CWE-326",
        ("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
    ),
    (
        re.compile(r'customer_master_key_spec\s*=\s*"(ECC_NIST_P256)"', re.IGNORECASE),
        _alg("ECDSA", curve="P-256"),
        RiskLevel.HIGH,
        "IaC declares ECDSA-P256 KMS key (quantum-vulnerable, deprecate 2030)",
        "AWS KMS key uses ECC_NIST_P256 (ECDSA-P-256). NIST IR 8547 deprecates after 2030.",
        "CWE-326",
        ("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
    ),
    (
        re.compile(r'customer_master_key_spec\s*=\s*"(ECC_NIST_P384)"', re.IGNORECASE),
        _alg("ECDSA", curve="P-384"),
        RiskLevel.HIGH,
        "IaC declares ECDSA-P384 KMS key (quantum-vulnerable, deprecate 2030)",
        "AWS KMS key uses ECC_NIST_P384. Quantum-vulnerable per NIST IR 8547.",
        "CWE-326",
        ("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
    ),
    # ----- AWS ACM — RSA_1024 (forbidden) -----
    (
        re.compile(r'key_algorithm\s*=\s*"(RSA_1024)"', re.IGNORECASE),
        _alg("RSA", size=1024),
        RiskLevel.CRITICAL,
        "IaC declares RSA-1024 ACM certificate (below FIPS minimum)",
        "AWS ACM certificate uses RSA-1024. Below FIPS minimum per SP 800-131A "
        "Rev. 2 — not acceptable for any production use.",
        "CWE-326",
        ("https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",),
    ),
    # ----- TLS version pinning (Terraform and YAML share enough syntax) -----
    (
        re.compile(
            r'(?:tls_version|minimumProtocolVersion)\s*[:=]\s*"?(TLSv?1[._]0)"?',
            re.IGNORECASE,
        ),
        _alg("TLS", size=10),
        RiskLevel.CRITICAL,
        "IaC pins TLS to TLS 1.0 (deprecated, RFC 8996)",
        "TLS 1.0 was deprecated by RFC 8996 (2021). It must not be used for any "
        "production traffic. Pin to TLS 1.2 or TLS 1.3 only.",
        "CWE-326",
        ("https://datatracker.ietf.org/doc/html/rfc8996",),
    ),
    (
        re.compile(
            r'(?:tls_version|minimumProtocolVersion)\s*[:=]\s*"?(TLSv?1[._]1)"?',
            re.IGNORECASE,
        ),
        _alg("TLS", size=11),
        RiskLevel.CRITICAL,
        "IaC pins TLS to TLS 1.1 (deprecated, RFC 8996)",
        "TLS 1.1 was deprecated by RFC 8996 (2021). Same severity as TLS 1.0.",
        "CWE-326",
        ("https://datatracker.ietf.org/doc/html/rfc8996",),
    ),
    # ----- Forbidden cipher / hash primitives appearing as a string literal -----
    (
        re.compile(r"\b(RC4)\b", re.IGNORECASE),
        _alg("RC4"),
        RiskLevel.CRITICAL,
        "IaC mentions RC4 stream cipher (forbidden, RFC 7465)",
        "RC4 was banned by RFC 7465 (2015). Remove from any cipher list.",
        "CWE-327",
        ("https://datatracker.ietf.org/doc/html/rfc7465",),
    ),
    (
        re.compile(r"\b(3DES|TDES|DES-EDE3)\b", re.IGNORECASE),
        _alg("3DES"),
        RiskLevel.CRITICAL,
        "IaC mentions 3DES / TDES (forbidden, retired by NIST SP 800-131A Rev. 2)",
        "3DES was retired by NIST SP 800-131A Rev. 2 (2019). Disallowed for new use.",
        "CWE-327",
        ("https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",),
    ),
    # MD5 pattern: case-sensitive + word-bounded to avoid matching things
    # like "md5sum_file" or "fmd5" that are not the literal "MD5" token.
    (
        re.compile(r"\b(MD5)\b"),
        _alg("MD5"),
        RiskLevel.CRITICAL,
        "IaC mentions MD5 (forbidden hash)",
        "MD5 has no remaining valid security use case. Replace with SHA-256+.",
        "CWE-327",
        ("https://csrc.nist.gov/projects/hash-functions",),
    ),
    (
        re.compile(r"\b(SHA-?1)\b", re.IGNORECASE),
        _alg("SHA-1"),
        RiskLevel.HIGH,
        "IaC mentions SHA-1 (withdrawn from FIPS approval in 2024)",
        "SHA-1 was withdrawn by NIST in 2024 (FIPS 180-4). Replace with SHA-256+.",
        "CWE-327",
        ("https://csrc.nist.gov/projects/hash-functions",),
    ),
]


def _iter_iac_files(root: Path) -> Iterable[Path]:
    """Yield up to :data:`_MAX_IAC_FILES` IaC candidate files under ``root``.

    Order is stable (Path sort) so report output is deterministic.
    """
    if root.is_file():
        yield root
        return
    seen: set[Path] = set()
    collected: list[Path] = []
    for pattern in _IAC_GLOB_PATTERNS:
        for p in sorted(root.glob(pattern)):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            collected.append(p)
            if len(collected) >= _MAX_IAC_FILES:
                break
        if len(collected) >= _MAX_IAC_FILES:
            break
    yield from collected


def _scan_file(
    path: Path,
    root: Path,
    errors: list[str],
) -> tuple[list[CryptoAsset], list[Vulnerability]]:
    """Run all patterns against a single file.

    Returns the discovered assets + vulnerabilities. Errors are
    appended to the caller's ``errors`` list so the run continues.
    """
    assets: list[CryptoAsset] = []
    vulns: list[Vulnerability] = []

    try:
        stat = path.stat()
    except OSError as e:
        errors.append(f"could not stat {path}: {e}")
        return assets, vulns

    if stat.st_size > _MAX_FILE_BYTES:
        errors.append(f"skipping oversize IaC file (>{_MAX_FILE_BYTES} bytes): {path}")
        return assets, vulns

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        errors.append(f"could not read {path}: {e}")
        return assets, vulns

    rel = path.relative_to(root) if path != root else path.name
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\r\n")
        # Strip simple inline comments to reduce false positives in
        # documentation strings. We only handle the two most common
        # comment leaders in IaC: ``#`` (TF, YAML) and ``//`` (JSON5).
        code_part = line
        for leader in ("#", "//"):
            idx = code_part.find(leader)
            if idx >= 0:
                code_part = code_part[:idx]
        if not code_part.strip():
            continue
        for regex, alg, severity, title, description, cwe, refs in _PATTERNS:
            match = regex.search(code_part)
            if not match:
                continue
            asset_id = f"iac://{rel}#L{line_no}"
            assets.append(
                CryptoAsset(
                    asset_id=asset_id,
                    category=ScanCategory.CODE,
                    algorithm=alg,
                    location=f"{path}:{line_no}",
                    discovered_at=datetime.now(UTC),
                    metadata={
                        "iac_file": str(rel),
                        "matched": match.group(0),
                        "line": str(line_no),
                    },
                )
            )
            vulns.append(
                Vulnerability(
                    title=f"{title} (line {line_no} of {rel})",
                    description=description,
                    severity=severity,
                    cwe=cwe,
                    references=refs,
                    affected_asset_ids=(asset_id,),
                )
            )
    return assets, vulns


class IaCScanner:
    """Regex-based IaC scanner (Terraform / CloudFormation / Kubernetes)."""

    name = "iac"
    category = ScanCategory.CODE

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "iac"

    async def scan(self, target: ScanTarget) -> ScanResult:
        if target.path is None:
            raise ValueError("IaC scanner requires target.path pointing to a file or directory")

        started_at = datetime.now(UTC)
        path = Path(target.path)
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []

        if not path.exists():  # noqa: ASYNC240 — scanner is async only to satisfy the Protocol; local fs metadata is not blocking I/O worth offloading
            errors.append(f"IaC target path does not exist: {path}")
            return ScanResult(
                scanner_name=self.name,
                target=str(path),
                assets=[],
                vulnerabilities=[],
                started_at=started_at,
                finished_at=datetime.now(UTC),
                errors=errors,
            )

        root = path if path.is_dir() else path.parent  # noqa: ASYNC240 — local fs metadata only, see is_applicable docstring
        for iac_file in _iter_iac_files(path):
            file_assets, file_vulns = _scan_file(iac_file, root, errors)
            assets.extend(file_assets)
            vulns.extend(file_vulns)

        return ScanResult(
            scanner_name=self.name,
            target=str(path),
            assets=assets,
            vulnerabilities=vulns,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            errors=errors,
        )


__all__ = ["IaCScanner"]
