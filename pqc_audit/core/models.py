"""Core pydantic v2 data models for pqc-audit-italia.

These models are intentionally pure data containers — no I/O, no
business logic. Algorithm classification lives in ``algorithms.py``,
risk scoring in ``risk.py``, scanner orchestration in
``pqc_audit.scanners``.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(IntEnum):
    """Severity level for findings, ordered for direct comparison."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str | int | None) -> RiskLevel:
        """Tolerant parser. Unknown / None returns ``INFO``."""
        if raw is None:
            return cls.INFO
        if isinstance(raw, int):
            try:
                return cls(raw)
            except ValueError:
                return cls.INFO
        upper = str(raw).strip().upper()
        return cls.__members__.get(upper, cls.INFO)


class ScanCategory(StrEnum):
    """High-level category of a scan target."""

    NETWORK = "NETWORK"
    FILESYSTEM = "FILESYSTEM"
    BINARY = "BINARY"
    CODE = "CODE"
    CONFIG = "CONFIG"


class Algorithm(BaseModel):
    """A cryptographic algorithm in use, with optional key size."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Algorithm name, e.g. 'RSA', 'ML-KEM-768', 'AES'.")
    key_size_bits: int | None = Field(
        default=None,
        ge=0,
        description="Key size in bits where applicable.",
    )
    curve: str | None = Field(
        default=None,
        description="Elliptic curve name when applicable (e.g. 'P-256', 'X25519').",
    )
    mode: str | None = Field(
        default=None,
        description="Mode of operation for symmetric ciphers (e.g. 'GCM', 'CBC').",
    )

    @property
    def canonical_name(self) -> str:
        """Stable identifier suitable for keys / lookups.

        Examples::

            RSA(key_size_bits=2048) -> 'RSA-2048'
            ML-KEM-768() -> 'ML-KEM-768'
            AES(key_size_bits=128, mode='GCM') -> 'AES-128-GCM'
        """
        parts = [self.name]
        if (
            self.key_size_bits
            and not any(ch.isdigit() for ch in self.name.split("-")[-1])
            or self.key_size_bits
            and "-" not in self.name
        ):
            parts.append(str(self.key_size_bits))
        if self.mode:
            parts.append(self.mode)
        return "-".join(parts)


class KeyMaterial(BaseModel):
    """Metadata about a cryptographic key. **Never** stores private material."""

    model_config = ConfigDict(frozen=True)

    algorithm: str
    key_size_bits: int = Field(..., ge=0)
    public_key_fingerprint_sha256: Annotated[
        str,
        Field(
            min_length=64,
            max_length=64,
            pattern=r"^[0-9a-fA-F]{64}$",
            description="Hex SHA-256 fingerprint of the public key (64 chars).",
        ),
    ]
    not_before: datetime | None = None
    not_after: datetime | None = None
    is_self_signed: bool = False
    is_ca: bool = False


class Vulnerability(BaseModel):
    """A cryptographic finding worth surfacing in a report."""

    model_config = ConfigDict(frozen=True)

    title: str
    description: str
    severity: RiskLevel = RiskLevel.INFO
    cwe: str | None = None
    references: tuple[str, ...] = ()
    affected_asset_ids: tuple[str, ...] = ()


class MigrationRecommendation(BaseModel):
    """Concrete migration suggestion for a vulnerable asset."""

    model_config = ConfigDict(frozen=True)

    from_algorithm: str
    to_algorithm: str
    rationale: str
    priority: int = Field(..., ge=1, le=5, description="1=lowest, 5=highest.")
    hybrid_intermediate: str | None = Field(
        default=None,
        description="Optional hybrid scheme to use during the transition (RFC 9794).",
    )
    references: tuple[str, ...] = ()


class CryptoAsset(BaseModel):
    """A single cryptographic asset discovered by a scanner."""

    model_config = ConfigDict(frozen=True)

    asset_id: str = Field(..., description="Stable identifier, e.g. 'tls://host:port'.")
    category: ScanCategory
    algorithm: Algorithm
    location: str = Field(..., description="Where the asset was found (host, path, ...).")
    discovered_at: datetime
    key_material: KeyMaterial | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Output of a single scanner run against a single target."""

    model_config = ConfigDict(frozen=True)

    scanner_name: str
    target: str
    assets: list[CryptoAsset] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
    errors: list[str] = Field(default_factory=list)

    @field_validator("finished_at")
    @classmethod
    def _finished_after_started(cls, v: datetime, info: Any) -> datetime:
        started = info.data.get("started_at")
        if started is not None and v < started:
            raise ValueError("finished_at must be >= started_at")
        return v


class AuditReport(BaseModel):
    """Top-level audit deliverable, aggregating multiple scan results."""

    model_config = ConfigDict(frozen=True)

    report_id: str
    scan_results: list[ScanResult] = Field(default_factory=list)
    policy_name: str = "default"
    recommendations: list[MigrationRecommendation] = Field(default_factory=list)
    generated_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def total_assets(self) -> int:
        return sum(len(sr.assets) for sr in self.scan_results)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(sr.vulnerabilities) for sr in self.scan_results)

    @property
    def highest_severity(self) -> RiskLevel:
        max_sev = RiskLevel.INFO
        for sr in self.scan_results:
            for v in sr.vulnerabilities:
                max_sev = max(max_sev, v.severity)
        return max_sev
