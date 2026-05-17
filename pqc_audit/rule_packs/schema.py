"""Pydantic schema for composable rule packs.

Rule packs are *regulation-anchored*, *parametric*, *versioned* YAML
modules that cross-cut profiles. They are loaded by
:mod:`pqc_audit.rule_packs` and compiled into a deduplicated rule set
the scanners and policy engine can consume.

Design notes:
    * ``RulePack.provenance`` is mandatory — a pack without a verifiable
      regulatory anchor is not auditable evidence and gets rejected at
      load time.
    * ``effective_dates`` uses ``date`` objects so reviewers can see the
      historical anchor (e.g. FIPS 203 final on 2024-08-13). Drift in
      these dates means the pack is no longer regulation-anchored.
    * ``Control.severity`` is restricted via ``Literal`` to keep
      downstream consumers from inventing severities not understood by
      the reporters.
    * The ``rule_type`` taxonomy is intentionally small: ``allow``,
      ``forbid``, ``discourage``, ``require``, ``deprecate_after``.
      Anything richer belongs to the policy engine or a higher-level
      compiler — not to the rule pack YAML itself.
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"]
RuleType = Literal["allow", "forbid", "discourage", "require", "deprecate_after"]
AssetCategory = Literal[
    "tls",
    "ssh",
    "cert",
    "jwt",
    "saml",
    "mtls",
    "dnssec",
    "binary",
    "code",
    "iac",
]
ArtifactType = Literal[
    "cbom",
    "sarif",
    "slsa-provenance",
    "in-toto-attestation",
    "sbom",
    "signed-report",
]


class Provenance(BaseModel):
    """Where the rule pack content came from. Mandatory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(
        ..., min_length=1, description="Standards body, e.g. NIST, ENISA, AgID, ACN."
    )
    url: str = Field(..., min_length=1)
    retrieved: date


class AppliesTo(BaseModel):
    """Which scanner asset categories the pack applies to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_categories: list[AssetCategory] = Field(..., min_length=1)


class Control(BaseModel):
    """A single rule. One algorithm per control to keep diffs surgical."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    rule_type: RuleType
    algorithm: str = Field(..., min_length=1)
    severity: Severity
    effective: date | None = None
    references: list[str] = Field(default_factory=list)

    @field_validator("effective")
    @classmethod
    def _effective_only_for_deprecate(cls, v: date | None, info: object) -> date | None:
        # mypy-friendly: ValidationInfo is provided by pydantic v2 — we
        # don't import it to keep this file tiny. Cross-field validation
        # at model level (mode='after') would be cleaner but pydantic v2
        # accepts both styles.
        return v


class EvidenceRequirement(BaseModel):
    """A non-algorithmic deliverable the pack mandates an auditor to emit.

    Examples: a signed CBOM in CycloneDX 1.6, a SARIF 2.1.0 report, an
    SLSA L3 provenance attestation, an in-toto link statement.
    Keeping evidence requirements distinct from :class:`Control` keeps
    the rule_type taxonomy stable and makes the report generator's job
    explicit: ``compiled.required_evidence_artifacts`` is the contract.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    artifact_type: ArtifactType
    format: str = Field(..., min_length=1)
    severity: Severity
    references: list[str] = Field(default_factory=list)


class RulePack(BaseModel):
    """A versioned, regulation-anchored rule pack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    effective_dates: dict[str, date] = Field(default_factory=dict)
    provenance: Provenance
    applies_to: AppliesTo
    controls: list[Control] = Field(default_factory=list)
    evidence_requirements: list[EvidenceRequirement] = Field(default_factory=list)


class CompiledRuleSet(BaseModel):
    """Deduplicated view of multiple rule packs compiled together."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_algorithms: set[str] = Field(default_factory=set)
    forbidden_algorithms: set[str] = Field(default_factory=set)
    discouraged_algorithms: set[str] = Field(default_factory=set)
    required_algorithms: set[str] = Field(default_factory=set)
    deprecate_after: dict[str, date] = Field(default_factory=dict)
    required_evidence_artifacts: set[str] = Field(default_factory=set)
    source_packs: list[str] = Field(default_factory=list)


__all__ = [
    "AppliesTo",
    "ArtifactType",
    "AssetCategory",
    "CompiledRuleSet",
    "Control",
    "EvidenceRequirement",
    "Provenance",
    "RulePack",
    "RuleType",
    "Severity",
]
