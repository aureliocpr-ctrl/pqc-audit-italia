"""Composable rule packs — regulation-anchored, versioned audit rules.

Rule packs are distinct from :mod:`pqc_audit.policies`:

    * **Policies** are end-to-end profiles (NIST baseline, AgID 2026,
      PA critical) tuned for a single use case, with YAML inheritance.
    * **Rule packs** are modular, parametric, regulation-anchored
      units (FIPS 203/204/205, CRA, NIS2, ACN 379907) that can be
      composed by the auditor on a per-engagement basis.

Public API::

    from pqc_audit.rule_packs import (
        list_bundled_rule_packs,
        load_rule_pack,
        compile_rule_packs,
    )

    pack = load_rule_pack("nist-core-2026")
    compiled = compile_rule_packs(["nist-core-2026", "audit-evidence-emit-2026"])

The loader rejects traversal-style names before touching the filesystem
(CWE-22) and validates the YAML against the strict pydantic schema in
:mod:`pqc_audit.rule_packs.schema`. A malformed pack fails closed at
load time rather than producing silently-wrong evidence at audit time.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from pqc_audit.rule_packs.schema import CompiledRuleSet, RulePack

_RULE_PACK_DIR = Path(__file__).resolve().parent


# Names must start with a letter/digit and contain only the small
# allow-listed set of characters. Hyphens are permitted (e.g.
# ``nist-core-2026``) because every pack name we ship is hyphenated by
# convention. NUL, slashes, dots and spaces are forbidden so a hostile
# caller cannot escape :data:`_RULE_PACK_DIR` (CWE-22, CWE-73).
_VALID_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]*$")


def list_bundled_rule_packs() -> list[str]:
    """Return the names of every rule pack shipped with the package."""
    return sorted(p.stem for p in _RULE_PACK_DIR.glob("*.yaml"))


def rule_pack_file_path(name: str) -> Path:
    """Return the resolved filesystem path of the YAML file for ``name``.

    Sprint 7: needed by the policy engine to compute a content hash
    (SHA-256) of the rule pack as shipped, so audits are reproducible
    and legally auditable. Goes through the same traversal-safe
    resolution as :func:`_load_raw`, so a hostile caller cannot
    escape :data:`_RULE_PACK_DIR`.
    """
    _validate_name(name)
    path = (_RULE_PACK_DIR / f"{name}.yaml").resolve()
    try:
        path.relative_to(_RULE_PACK_DIR.resolve())
    except ValueError as exc:
        raise FileNotFoundError(f"rule pack not found: {name}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"rule pack not found: {name}")
    return path


def _validate_name(name: str) -> None:
    if not name or not _VALID_NAME_RE.fullmatch(name):
        raise ValueError(
            f"invalid rule pack name: {name!r}. Allowed: [A-Za-z0-9_-], "
            "must start with an alphanumeric character."
        )


def _load_raw(name: str) -> dict[str, Any]:
    _validate_name(name)
    path = (_RULE_PACK_DIR / f"{name}.yaml").resolve()
    try:
        path.relative_to(_RULE_PACK_DIR.resolve())
    except ValueError as exc:
        # Belt-and-braces against symlink escapes after the regex check.
        raise FileNotFoundError(f"rule pack not found: {name}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"rule pack not found: {name}")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"rule pack file is not a mapping: {path}")
    return data


def load_rule_pack(name: str) -> RulePack:
    """Load and validate a rule pack by short name.

    Raises:
        ValueError: name fails the whitelist regex, or YAML is malformed.
        FileNotFoundError: no YAML file with that name is shipped.
        pydantic.ValidationError: the YAML content does not match the
            :class:`RulePack` schema (e.g. missing provenance).
    """
    raw = _load_raw(name)
    return RulePack.model_validate(raw)


def compile_rule_packs(names: list[str]) -> CompiledRuleSet:
    """Merge multiple rule packs into a deduplicated :class:`CompiledRuleSet`.

    Duplicates of the same pack are silently collapsed (idempotent).
    Empty input yields an empty (but valid) compiled set.
    """
    allowed: set[str] = set()
    forbidden: set[str] = set()
    discouraged: set[str] = set()
    required: set[str] = set()
    deprecate_after: dict[str, Any] = {}
    required_evidence: set[str] = set()
    seen_packs: list[str] = []
    seen_set: set[str] = set()
    for name in names:
        if name in seen_set:
            continue
        seen_set.add(name)
        seen_packs.append(name)
        pack = load_rule_pack(name)
        for control in pack.controls:
            algo = control.algorithm
            rt = control.rule_type
            if rt == "allow":
                allowed.add(algo)
            elif rt == "forbid":
                forbidden.add(algo)
            elif rt == "discourage":
                discouraged.add(algo)
            elif rt == "require":
                required.add(algo)
            elif rt == "deprecate_after" and control.effective is not None:
                # Earliest deprecation wins when packs overlap.
                existing = deprecate_after.get(algo)
                if existing is None or control.effective < existing:
                    deprecate_after[algo] = control.effective
        for ev in pack.evidence_requirements:
            required_evidence.add(ev.artifact_type)
    return CompiledRuleSet(
        allowed_algorithms=allowed,
        forbidden_algorithms=forbidden,
        discouraged_algorithms=discouraged,
        required_algorithms=required,
        deprecate_after=deprecate_after,
        required_evidence_artifacts=required_evidence,
        source_packs=seen_packs,
    )


__all__ = [
    "compile_rule_packs",
    "list_bundled_rule_packs",
    "load_rule_pack",
    "rule_pack_file_path",
]
