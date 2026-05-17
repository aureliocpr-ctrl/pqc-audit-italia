"""Schema-validate the CBOM and SARIF reporter outputs against the
official upstream JSON Schemas.

Why this exists: claiming "CycloneDX 1.6" or "SARIF 2.1.0" in the
README is just marketing unless an actual third-party verifier
accepts the output. These tests run the reporter outputs through
the upstream JSON Schemas vendored under
``tests/fixtures/schemas/``. If a future change drifts the output
away from the spec, the test fails *before* a PA / Big4 reviewer
discovers it.

The vendored schema files are bit-identical copies of:

  * https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json
  * https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json

Re-download with the same URLs to refresh.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "schemas"
CYCLONEDX_SCHEMA_PATH = SCHEMA_DIR / "cyclonedx-1.6.schema.json"
SARIF_SCHEMA_PATH = SCHEMA_DIR / "sarif-2.1.0.schema.json"


def _ts() -> datetime:
    return datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC)


def _build_sample_report():
    from pqc_audit.core.models import (
        Algorithm,
        AuditReport,
        CryptoAsset,
        RiskLevel,
        ScanCategory,
        ScanResult,
        Vulnerability,
    )

    asset = CryptoAsset(
        asset_id="tls://example.it:443",
        category=ScanCategory.NETWORK,
        algorithm=Algorithm(name="RSA", key_size_bits=2048),
        location="example.it:443",
        discovered_at=_ts(),
        metadata={"tls_version": "TLSv1.2", "signature_hash": "SHA-256"},
    )
    vuln = Vulnerability(
        title="RSA-2048 is quantum-vulnerable",
        description="NIST IR 8547 deprecates RSA-2048 after 2030.",
        severity=RiskLevel.HIGH,
        cwe="CWE-326",
        references=("https://csrc.nist.gov/pubs/ir/8547/initial-public-draft",),
        affected_asset_ids=(asset.asset_id,),
    )
    sr = ScanResult(
        scanner_name="tls",
        target="example.it:443",
        assets=[asset],
        vulnerabilities=[vuln],
        started_at=_ts(),
        finished_at=_ts(),
    )
    return AuditReport(report_id="audit-fixture", scan_results=[sr], generated_at=_ts())


# ---------------------------------------------------------------------------
# CycloneDX 1.6 CBOM
# ---------------------------------------------------------------------------


def test_cbom_output_validates_against_cyclonedx_1_6_official_schema() -> None:
    """The CBOM reporter output must validate against the upstream
    CycloneDX 1.6 JSON Schema. Failing this test means we are claiming
    spec compliance we cannot deliver to a third party (Dependency-Track,
    Anchore, Microsoft SBOM Tool)."""
    from pqc_audit.reporters.cbom_reporter import render as render_cbom

    if not CYCLONEDX_SCHEMA_PATH.is_file():
        pytest.skip(f"CycloneDX schema not vendored at {CYCLONEDX_SCHEMA_PATH}")

    schema = json.loads(CYCLONEDX_SCHEMA_PATH.read_text(encoding="utf-8"))
    cbom_text = render_cbom(_build_sample_report())
    cbom = json.loads(cbom_text)

    # Use Draft 7 explicitly (matches the schema's $schema declaration).
    validator_cls = jsonschema.Draft7Validator
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(cbom), key=lambda e: e.path)
    assert not errors, "\n".join(
        f"  - {'.'.join(str(p) for p in err.path) or '<root>'}: {err.message}"
        for err in errors[:10]
    )


def test_cbom_declares_correct_spec_version() -> None:
    from pqc_audit.reporters.cbom_reporter import render as render_cbom

    cbom = json.loads(render_cbom(_build_sample_report()))
    assert cbom.get("bomFormat") == "CycloneDX"
    assert cbom.get("specVersion") == "1.6"


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def test_sarif_output_validates_against_oasis_sarif_2_1_0_official_schema() -> None:
    """The SARIF reporter output must validate against the upstream OASIS
    SARIF 2.1.0 schema. Failing means GitHub Code Scanning / GitLab SAST /
    Azure DevOps will reject our findings on import."""
    from pqc_audit.reporters.sarif_reporter import render as render_sarif

    if not SARIF_SCHEMA_PATH.is_file():
        pytest.skip(f"SARIF schema not vendored at {SARIF_SCHEMA_PATH}")

    schema = json.loads(SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
    sarif_text = render_sarif(_build_sample_report())
    sarif = json.loads(sarif_text)

    # SARIF schema declares draft-04; validate with the matching draft.
    validator_cls = jsonschema.Draft4Validator
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(sarif), key=lambda e: e.path)
    assert not errors, "\n".join(
        f"  - {'.'.join(str(p) for p in err.path) or '<root>'}: {err.message}"
        for err in errors[:10]
    )


def test_sarif_declares_correct_version_field() -> None:
    from pqc_audit.reporters.sarif_reporter import render as render_sarif

    sarif = json.loads(render_sarif(_build_sample_report()))
    assert sarif.get("version") == "2.1.0"
    assert sarif.get("$schema", "").endswith("sarif-schema-2.1.0.json") or sarif.get(
        "$schema", ""
    ).endswith("sarif-2.1.0.json")
