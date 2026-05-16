"""Tests for pqc_audit.policies — bundled YAML loaders."""

from __future__ import annotations

import pytest


def test_list_bundled_policies() -> None:
    from pqc_audit.policies import list_bundled_policies

    names = list_bundled_policies()
    assert {"nist_baseline", "agid_2026", "banking_italy", "pa_critical"} <= set(names)


def test_load_nist_baseline_required_fields() -> None:
    from pqc_audit.policies import load_policy

    p = load_policy("nist_baseline")
    assert p["name"] == "nist_baseline"
    assert "data_sensitivity_years" in p
    assert "forbidden_algorithms" in p
    assert "thresholds" in p
    assert isinstance(p["forbidden_algorithms"], list)


def test_load_agid_inherits_nist_minimum_tls() -> None:
    from pqc_audit.policies import load_policy

    nist = load_policy("nist_baseline")
    agid = load_policy("agid_2026")
    # AgID inherits from NIST: keys absent in agid file should fall through
    assert agid.get("minimum_tls_version") == "TLSv1.2"
    assert nist.get("minimum_tls_version") == "TLSv1.2"


def test_load_pa_critical_strictest() -> None:
    from pqc_audit.policies import load_policy

    p = load_policy("pa_critical")
    assert p["minimum_tls_version"] == "TLSv1.3"
    assert "RSA-2048" in p["forbidden_algorithms"]
    assert p["thresholds"]["hndl_max_score"] <= 30
    assert p["data_sensitivity_years"] >= 30


def test_load_unknown_policy_raises() -> None:
    from pqc_audit.policies import load_policy

    with pytest.raises(FileNotFoundError):
        load_policy("does-not-exist")


@pytest.mark.parametrize(
    "evil_name",
    [
        "../../etc/foo",
        "../etc/foo",
        "..\\..\\etc\\foo",
        "/etc/passwd",
        "policy/with/slash",
        "policy with space",
        "policy.with.dot",
        "",
        "\x00malicious",
        "policy;rm-rf",
        "-leading-dash",
        "_leading-underscore",
    ],
)
def test_load_policy_rejects_path_traversal_and_invalid_names(evil_name: str) -> None:
    """CWE-22 / CWE-73 guard: only the whitelisted name pattern is accepted.

    ``load_policy`` MUST refuse anything that doesn't match
    ``^[A-Za-z0-9][A-Za-z0-9_-]*$`` before opening any file. Without
    this guard, an attacker controlling the ``--policy`` argument
    (or the equivalent Python-API parameter) gets an arbitrary
    ``*.yaml`` read primitive on the host.
    """
    from pqc_audit.policies import load_policy

    with pytest.raises((ValueError, FileNotFoundError)):
        load_policy(evil_name)


@pytest.mark.parametrize("name", ["nist_baseline", "agid_2026", "banking_italy", "pa_critical"])
def test_every_policy_has_references(name: str) -> None:
    from pqc_audit.policies import load_policy

    p = load_policy(name)
    refs = p.get("references", [])
    assert isinstance(refs, list)
    assert len(refs) >= 1
    for r in refs:
        assert r.startswith("http")
