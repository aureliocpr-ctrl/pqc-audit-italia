"""SARIF 2.1.0 reporter — interoperable security tooling output.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
consumed by GitHub code scanning, GitLab, SonarQube, Sentinel and most
IDE plugins. We emit a single ``run`` per :class:`AuditReport`, with one
``result`` per :class:`Vulnerability` and a deduplicated ``rules`` list.

Rule identifiers are stable derivations of ``(category_token, algorithm)``
so the same finding always lands on the same rule across multiple scans.

Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import re
from typing import Any

from pqc_audit import __version__
from pqc_audit.core.models import AuditReport, RiskLevel, Vulnerability

_SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_TOOL_NAME = "pqc-audit-italia"
_TOOL_INFO_URI = "https://github.com/aureliocpr-ctrl/pqc-audit-italia"
_NIST_HELP_URI = "https://csrc.nist.gov/projects/post-quantum-cryptography"


# CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note
def _sev_to_level(severity: RiskLevel) -> str:
    if severity in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return "error"
    if severity is RiskLevel.MEDIUM:
        return "warning"
    return "note"


_CATEGORY_TOKEN_RE = re.compile(r"[^A-Z0-9]+")
_RULE_TOKEN_PARTS = 2


def _category_token(title: str) -> str:
    """Stable, lossy token derived from the first words of a vulnerability title.

    We deliberately collapse to the first ``_RULE_TOKEN_PARTS`` significant
    words so that closely related findings (e.g. "Quantum-vulnerable
    algorithm in use" and a future "Quantum-vulnerable algorithm (dup)")
    map to the same SARIF rule. Bumping the constant makes ruleIds more
    granular at the cost of producing more rules.

    Examples (with parts=2)::

        'Quantum-vulnerable algorithm in use' -> 'QUANTUM_VULNERABLE'
        'Weak hash advisory'                  -> 'WEAK_HASH'
        'Missing OCSP'                        -> 'MISSING_OCSP'
    """
    upper = title.strip().upper()
    token = _CATEGORY_TOKEN_RE.sub("_", upper).strip("_")
    if not token:
        return "UNCATEGORIZED"
    parts = token.split("_")
    return "_".join(parts[:_RULE_TOKEN_PARTS])


def _primary_algorithm(report: AuditReport, asset_ids: tuple[str, ...]) -> str:
    """Return the canonical algorithm name of the first matching asset."""
    if not asset_ids:
        return "UNKNOWN"
    for sr in report.scan_results:
        for a in sr.assets:
            if a.asset_id in asset_ids:
                return a.algorithm.canonical_name.upper()
    return "UNKNOWN"


def _build_rule_id(report: AuditReport, vuln: Vulnerability) -> str:
    cat = _category_token(vuln.title)
    algo = _primary_algorithm(report, vuln.affected_asset_ids)
    return f"PQC.{cat}.{algo}"


def _asset_uri(asset_id: str) -> str:
    """Return the asset_id as-is when it already looks like a URI, otherwise wrap."""
    if "://" in asset_id:
        return asset_id
    return f"pqc-asset://{asset_id}"


def _result_for_vuln(report: AuditReport, vuln: Vulnerability) -> dict[str, Any]:
    rule_id = _build_rule_id(report, vuln)
    locations: list[dict[str, Any]] = []
    if vuln.affected_asset_ids:
        for aid in vuln.affected_asset_ids:
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _asset_uri(aid)},
                    }
                }
            )
    else:
        locations.append({"physicalLocation": {"artifactLocation": {"uri": "pqc-asset://unknown"}}})
    properties: dict[str, Any] = {
        "title": vuln.title,
        "severity": vuln.severity.name,
    }
    if vuln.cwe:
        properties["cwe"] = vuln.cwe
    if vuln.references:
        properties["references"] = list(vuln.references)
    return {
        "ruleId": rule_id,
        "level": _sev_to_level(vuln.severity),
        "message": {"text": vuln.description},
        "locations": locations,
        "properties": properties,
    }


def _rule_for_vuln(rule_id: str, vuln: Vulnerability) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": vuln.title.replace(" ", ""),
        "shortDescription": {"text": vuln.title},
        "fullDescription": {"text": vuln.description},
        "defaultConfiguration": {"level": _sev_to_level(vuln.severity)},
        "helpUri": _NIST_HELP_URI,
        "properties": {
            "category": _category_token(vuln.title),
            "cwe": vuln.cwe or "",
        },
    }


def render(report: AuditReport) -> str:
    """Serialize an :class:`AuditReport` as a SARIF 2.1.0 JSON string.

    The output is pretty-printed (indent=2) for diff-friendly storage.
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for sr in report.scan_results:
        for v in sr.vulnerabilities:
            rid = _build_rule_id(report, v)
            if rid not in rules:
                rules[rid] = _rule_for_vuln(rid, v)
            results.append(_result_for_vuln(report, v))
    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": __version__,
                        "informationUri": _TOOL_INFO_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": report.generated_at.isoformat().replace("+00:00", "Z"),
                    }
                ],
                "properties": {
                    "report_id": report.report_id,
                    "policy_name": report.policy_name,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=False, ensure_ascii=False)
