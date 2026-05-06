"""Convert ``pqc-audit batch`` JSON output to a single SARIF 2.1.0 file.

Use case: feed the batch scan into GitLab "Security & Compliance"
or GitHub "Code Scanning" — both consume native SARIF.

Usage::

    python batch_to_sarif.py \\
        --input  artefacts/batch_report.json \\
        --output artefacts/batch_report.sarif

The script aggregates per-host findings (vulnerabilities + policy
violations) into one ``runs[0].results[]`` array. Each ``ruleId`` is
keyed on the host so reviewers can quickly bisect what failed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _severity_to_sarif(severity: str | int) -> str:
    """Map our int RiskLevel / string severity to SARIF level."""
    s = str(severity).lower()
    if s in ("critical", "5"):
        return "error"
    if s in ("high", "4"):
        return "error"
    if s in ("medium", "3"):
        return "warning"
    return "note"


def _build_run(reports: list[dict]) -> dict[str, Any]:
    """One SARIF run aggregating all per-host findings."""
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []

    for report in reports:
        # Error stub (unreachable host) — emit as a single SARIF result
        if "error" in report and "scan_results" not in report:
            host = str(report.get("host", "?"))
            rule_id = "scan_failure"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": "Scan failed"},
                    "fullDescription": {
                        "text": "TLS handshake failed — host unreachable, "
                                "TLS-disabled, or behind a firewall."
                    },
                })
            results.append({
                "ruleId": rule_id,
                "level": "warning",
                "message": {
                    "text": (
                        f"Host {host}: {report.get('error', 'unknown error')}"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"tls://{host}"}
                    }
                }],
            })
            continue

        # OK path: walk the AuditReport structure
        for sr in report.get("scan_results") or []:
            target = sr.get("target", "?")
            # ``target`` is "host:port" string in the json reporter
            host = str(target).split(":")[0] if isinstance(target, str) else "?"
            for vuln in sr.get("vulnerabilities") or []:
                rule_id = str(vuln.get("identifier") or "pqc.vulnerability")
                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    rules.append({
                        "id": rule_id,
                        "shortDescription": {
                            "text": str(vuln.get("title", rule_id))
                        },
                        "fullDescription": {
                            "text": str(vuln.get("description", ""))
                        },
                    })
                results.append({
                    "ruleId": rule_id,
                    "level": _severity_to_sarif(vuln.get("severity", "note")),
                    "message": {"text": str(vuln.get("description", ""))},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"tls://{host}"}
                        }
                    }],
                })

        # Policy evaluation FAIL → emit one SARIF result per violation
        pe = report.get("policy_evaluation") or {}
        for v in pe.get("violations") or []:
            rule_id = f"policy.{v.get('rule', 'violation')}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {
                        "text": f"Policy violation: {v.get('rule', '?')}"
                    },
                    "fullDescription": {
                        "text": str(v.get("reason", "policy violation"))
                    },
                })
            host = "?"
            sr_list = report.get("scan_results") or []
            if sr_list:
                t = sr_list[0].get("target", "?")
                host = str(t).split(":")[0] if isinstance(t, str) else "?"
            results.append({
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": (
                        f"Host {host} fails policy "
                        f"{pe.get('policy', '?')}: {v.get('reason', '?')}"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"tls://{host}"}
                    }
                }],
            })

    return {
        "tool": {
            "driver": {
                "name": "pqc-audit-italia",
                "informationUri": "https://github.com/aureliocpr/pqc-audit-italia",
                "rules": rules,
            }
        },
        "results": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(prog="batch_to_sarif")
    p.add_argument("--input", "-i", required=True,
                   help="batch_report.json from `pqc-audit batch`")
    p.add_argument("--output", "-o", required=True,
                   help="Destination SARIF 2.1.0 file")
    args = p.parse_args()

    reports = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if not isinstance(reports, list):
        print("error: input must be a JSON list (output of `pqc-audit batch`)")
        return 2

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/"
                   "schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [_build_run(reports)],
    }
    Path(args.output).write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
