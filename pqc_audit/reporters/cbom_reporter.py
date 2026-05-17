"""CycloneDX 1.6 CBOM reporter — Cryptography Bill of Materials.

CycloneDX 1.6 introduces native support for cryptographic-asset
components, classical-security level metadata and NIST PQC categories.
We emit a self-contained JSON BOM that can be ingested by Dependency-Track,
Anchore, Microsoft SBOM Tool and similar consumers.

We do *not* depend on ``cyclonedx-python-lib``: the JSON spec is stable
and the schema small enough that a hand-rolled writer keeps the install
footprint minimal. Spec: https://cyclonedx.org/docs/1.6/json/
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from pqc_audit import __version__
from pqc_audit.core.algorithms import (
    AlgorithmClass,
    classify_algorithm,
)
from pqc_audit.core.models import (
    Algorithm,
    AuditReport,
    CryptoAsset,
    Vulnerability,
)

_TOOL_NAME = "pqc-audit-italia"
_TOOL_VENDOR = "aureliocpr"


# ---------------------------------------------------------------------------
# Algorithm property mapping
# ---------------------------------------------------------------------------

_SIGNATURE_ALGOS: frozenset[str] = frozenset(
    {
        "RSA",
        "DSA",
        "ECDSA",
        "EDDSA",
        "ED25519",
        "ED448",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-128S",
        "SLH-DSA-SHA2-128F",
        "SLH-DSA-SHA2-192S",
        "SLH-DSA-SHA2-192F",
        "SLH-DSA-SHA2-256S",
        "SLH-DSA-SHA2-256F",
        "SLH-DSA-SHAKE-128S",
        "SLH-DSA-SHAKE-128F",
        "SLH-DSA-SHAKE-192S",
        "SLH-DSA-SHAKE-192F",
        "SLH-DSA-SHAKE-256S",
        "SLH-DSA-SHAKE-256F",
        "LMS",
        "XMSS",
    }
)

_KEX_ALGOS: frozenset[str] = frozenset(
    {
        "DH",
        "ECDH",
        "X25519",
        "X448",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "HQC-128",
        "HQC-192",
        "HQC-256",
    }
)

_HASH_ALGOS: frozenset[str] = frozenset(
    {
        "MD5",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
    }
)

_SYMMETRIC_ALGOS: frozenset[str] = frozenset(
    {
        "AES",
        "AES-128",
        "AES-192",
        "AES-256",
        "CHACHA20",
        "3DES",
        "RC4",
    }
)

# NIST quantum security categories for PQC algorithms (FIPS 203/204/205).
_NIST_CATEGORY: dict[str, int] = {
    "ML-KEM-512": 1,
    "ML-KEM-768": 3,
    "ML-KEM-1024": 5,
    "ML-DSA-44": 2,
    "ML-DSA-65": 3,
    "ML-DSA-87": 5,
    "SLH-DSA-SHA2-128S": 1,
    "SLH-DSA-SHA2-128F": 1,
    "SLH-DSA-SHA2-192S": 3,
    "SLH-DSA-SHA2-192F": 3,
    "SLH-DSA-SHA2-256S": 5,
    "SLH-DSA-SHA2-256F": 5,
    "SLH-DSA-SHAKE-128S": 1,
    "SLH-DSA-SHAKE-128F": 1,
    "SLH-DSA-SHAKE-192S": 3,
    "SLH-DSA-SHAKE-192F": 3,
    "SLH-DSA-SHAKE-256S": 5,
    "SLH-DSA-SHAKE-256F": 5,
    "HQC-128": 1,
    "HQC-192": 3,
    "HQC-256": 5,
}

# NIST PQC categories mapped to minimum classical-bit thresholds for
# quantum-weakened symmetric primitives (used as fallback when the
# specific algorithm isn't pre-mapped above).
_NIST_BITS_THRESHOLDS: tuple[tuple[int, int], ...] = (
    (256, 5),
    (192, 3),
    (128, 1),
)

# Classical security level (bits of equivalent symmetric strength).
_CLASSICAL_SECURITY: dict[str, int] = {
    "RSA-2048": 112,
    "RSA-3072": 128,
    "RSA-4096": 152,
    "ECDSA-P-256": 128,
    "ECDSA-P-384": 192,
    "ECDSA-P-521": 256,
    "AES-128": 128,
    "AES-192": 192,
    "AES-256": 256,
    "SHA-256": 256,
    "SHA-384": 384,
    "SHA-512": 512,
    "MD5": 0,
    "SHA-1": 0,
}


def _primitive_for(algorithm_name: str) -> str:
    norm = algorithm_name.strip().upper()
    if norm in _SIGNATURE_ALGOS:
        return "signature"
    if norm in _KEX_ALGOS:
        return "key-encapsulation" if "KEM" in norm or "HQC" in norm else "kex"
    if norm in _HASH_ALGOS:
        return "hash"
    # Symmetric: strip optional mode tail (AES-128-GCM -> AES-128 -> AES)
    head = norm.split("-")[0]
    if norm in _SYMMETRIC_ALGOS or head in _SYMMETRIC_ALGOS:
        return "block-cipher"
    return "other"


def _crypto_functions_for(primitive: str) -> list[str]:
    if primitive == "signature":
        return ["sign", "verify"]
    if primitive in {"kex", "key-encapsulation"}:
        return ["keyAgreement"]
    if primitive == "hash":
        return ["digest"]
    if primitive == "block-cipher":
        return ["encrypt", "decrypt"]
    return []


def _nist_quantum_security_level(algo: Algorithm) -> int:
    """Return NIST PQC category 1-5, or 0 for quantum-vulnerable.

    Callers prefer 0 (vulnerable) over a missing field for downstream
    consumers that don't accept null.
    """
    canonical = algo.canonical_name.upper()
    if canonical in _NIST_CATEGORY:
        return _NIST_CATEGORY[canonical]
    cls = classify_algorithm(algo.name)
    if cls is AlgorithmClass.QUANTUM_WEAKENED:
        bits = algo.key_size_bits or 0
        for threshold, level in _NIST_BITS_THRESHOLDS:
            if bits >= threshold:
                return level
    return 0


def _classical_security_level(algo: Algorithm) -> int:
    canonical = algo.canonical_name.upper()
    if canonical in _CLASSICAL_SECURITY:
        return _CLASSICAL_SECURITY[canonical]
    return algo.key_size_bits or 0


def _component_bom_ref(asset: CryptoAsset) -> str:
    return f"crypto:{asset.asset_id}"


def _asset_type_for(asset: CryptoAsset) -> str:
    """Map the audit asset into a CycloneDX cryptoProperties.assetType."""
    primitive = _primitive_for(asset.algorithm.name)
    if primitive in {"signature", "kex", "key-encapsulation", "hash", "block-cipher"}:
        return "algorithm"
    return "algorithm"


def _component_for(asset: CryptoAsset) -> dict[str, Any]:
    primitive = _primitive_for(asset.algorithm.name)
    algo_props: dict[str, Any] = {
        "primitive": primitive,
        "parameterSetIdentifier": asset.algorithm.canonical_name,
        # CycloneDX 1.6 enum: software-plain-ram | software-encrypted-ram
        # | software-tee | hardware | other | unknown. We default to
        # ``unknown`` because pqc-audit does not introspect runtime
        # memory protection of the asset under audit. A later sprint
        # can downgrade to ``software-plain-ram`` for software-only
        # discoveries and ``hardware`` when an HSM is detected.
        "executionEnvironment": "unknown",
        "implementationPlatform": "generic",
        "certificationLevel": ["none"],
        "cryptoFunctions": _crypto_functions_for(primitive),
        "classicalSecurityLevel": _classical_security_level(asset.algorithm),
        "nistQuantumSecurityLevel": _nist_quantum_security_level(asset.algorithm),
    }
    if asset.algorithm.mode:
        algo_props["mode"] = asset.algorithm.mode
    if asset.algorithm.curve:
        algo_props["curve"] = asset.algorithm.curve
    crypto_props: dict[str, Any] = {
        "assetType": _asset_type_for(asset),
        "algorithmProperties": algo_props,
        "oid": asset.metadata.get("oid", ""),
    }
    return {
        "type": "cryptographic-asset",
        "bom-ref": _component_bom_ref(asset),
        "name": asset.algorithm.canonical_name,
        "description": (f"{asset.category.value} asset at {asset.location} (scanner-discovered)"),
        "cryptoProperties": crypto_props,
        "properties": [
            {"name": "asset_id", "value": asset.asset_id},
            {"name": "category", "value": asset.category.value},
            {"name": "location", "value": asset.location},
        ],
    }


def _vulnerability_entry(report: AuditReport, vuln: Vulnerability) -> dict[str, Any]:
    affects: list[dict[str, Any]] = []
    for sr in report.scan_results:
        for a in sr.assets:
            if a.asset_id in vuln.affected_asset_ids:
                affects.append({"ref": _component_bom_ref(a)})
    if not affects:
        # Always emit at least one affects entry to keep VEX consumers happy
        affects.append({"ref": "crypto:unknown"})
    # Stable, deterministic 8-hex-digit suffix derived from the
    # vulnerability title. Built-in ``hash()`` is randomized per
    # Python interpreter (PEP 456 ``PYTHONHASHSEED``), so it would
    # produce a different CBOM id every run and defeat any
    # idempotent CBOM diffing / Dependency-Track ingestion.
    title_digest = hashlib.sha256(vuln.title.encode("utf-8")).hexdigest()[:8]
    entry: dict[str, Any] = {
        "id": f"PQC-{vuln.severity.name}-{title_digest}",
        "description": vuln.description,
        "ratings": [
            {
                "source": {"name": _TOOL_NAME},
                "severity": vuln.severity.name.lower(),
                "method": "other",
            }
        ],
        "affects": affects,
    }
    if vuln.cwe:
        # CycloneDX expects integer CWE IDs; tolerate "CWE-327" or "327"
        try:
            cwe_int = int(vuln.cwe.upper().removeprefix("CWE-").strip())
            entry["cwes"] = [cwe_int]
        except (TypeError, ValueError):
            pass
    if vuln.references:
        entry["advisories"] = [{"url": r} for r in vuln.references]
    return entry


def render(report: AuditReport) -> str:
    """Serialize an :class:`AuditReport` as a CycloneDX 1.6 CBOM JSON string.

    The output is pretty-printed and includes a ``vulnerabilities[]`` VEX
    section so consumers see findings alongside the cryptographic assets.
    """
    components: list[dict[str, Any]] = []
    vex_entries: list[dict[str, Any]] = []
    for sr in report.scan_results:
        for asset in sr.assets:
            components.append(_component_for(asset))
        for v in sr.vulnerabilities:
            vex_entries.append(_vulnerability_entry(report, v))

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.generated_at.isoformat().replace("+00:00", "Z"),
            # CycloneDX 1.6 ``metadata.tools`` is ``oneOf`` (a) legacy
            # array of Tool objects or (b) a ``{components, services}``
            # object. We emit the legacy ARRAY form because it is
            # accepted by every consumer in the wild (Dependency-Track
            # 4.x and 5.x, cyclonedx-cli, Anchore, GitHub SBOM ingest)
            # whereas the newer object form is still rejected by some
            # strict validators in late-2025 fleets. The legacy form is
            # not deprecated in 1.6, only marked as "consider migration
            # to .components" in the spec.
            "tools": [
                {
                    "vendor": _TOOL_VENDOR,
                    "name": _TOOL_NAME,
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"audit:{report.report_id}",
                "name": report.report_id,
                "version": __version__,
                "description": (f"pqc-audit-italia audit report. Policy: {report.policy_name}."),
            },
            "properties": [
                {"name": "report_id", "value": report.report_id},
                {"name": "policy_name", "value": report.policy_name},
            ],
        },
        "components": components,
        "vulnerabilities": vex_entries,
    }
    return json.dumps(bom, indent=2, sort_keys=False, ensure_ascii=False)
