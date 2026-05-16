"""Predefined policies (NIST baseline, AgID, banking IT, PA critical).

Each policy lives as a YAML file shipped alongside this package.
The loader resolves ``inherits`` chains so callers always receive a
fully merged dictionary.

Public API::

    from pqc_audit.policies import list_bundled_policies, load_policy

    names = list_bundled_policies()
    policy = load_policy("agid_2026")

The Phase 5 policy *engine* (evaluation against scan results) lands
alongside the classifiers.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_POLICY_DIR = Path(__file__).resolve().parent


def list_bundled_policies() -> list[str]:
    """Return the names of every YAML policy shipped with the package."""
    return sorted(p.stem for p in _POLICY_DIR.glob("*.yaml"))


# Conservative whitelist of characters allowed in a policy name. Stops
# ``..`` / absolute paths / NUL / slash-injection from reaching the
# filesystem walker (CWE-22 / CWE-73). Anything else MUST be added to
# a YAML file under :data:`_POLICY_DIR` first.
_VALID_POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]*$")


def _load_raw(name: str) -> dict[str, Any]:
    # Validate the name before touching the filesystem so a hostile
    # ``../../etc/foo`` cannot turn the YAML loader into an arbitrary
    # ``*.yaml`` read primitive on the host.
    if not _VALID_POLICY_NAME_RE.fullmatch(name):
        raise ValueError(
            f"invalid policy name: {name!r}. Allowed: [A-Za-z0-9_-], "
            "must start with an alphanumeric character."
        )
    path = (_POLICY_DIR / f"{name}.yaml").resolve()
    # Belt-and-braces: enforce that the resolved path still lives inside
    # the bundled policies directory. Catches symlink-based escapes.
    try:
        path.relative_to(_POLICY_DIR.resolve())
    except ValueError as exc:
        raise FileNotFoundError(f"policy not found: {name}") from exc
    if not path.is_file():
        raise FileNotFoundError(f"policy not found: {name}")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"policy file is not a mapping: {path}")
    return data


def load_policy(name: str) -> dict[str, Any]:
    """Return a fully-merged policy dictionary, resolving ``inherits``.

    ``inherits`` chains are resolved depth-first; child keys override
    parent keys. A loop in the inheritance graph raises ``RuntimeError``.

    The implementation reads each YAML file *once* via a local cache —
    previously the chain walk and the merge phase each re-opened the
    same file, which was both wasteful and (in pathological cases)
    racy if the filesystem mutated between calls.

    The name is validated against the whitelist regex BEFORE any
    filesystem access, so an empty / traversal / NUL-injected name
    cannot turn this loader into an arbitrary ``*.yaml`` read
    primitive.
    """
    if not name or not _VALID_POLICY_NAME_RE.fullmatch(name):
        raise ValueError(
            f"invalid policy name: {name!r}. Allowed: [A-Za-z0-9_-], "
            "must start with an alphanumeric character."
        )
    seen: set[str] = set()
    chain: list[str] = []
    cache: dict[str, dict[str, Any]] = {}
    cursor: str = name
    while cursor:
        if cursor in seen:
            raise RuntimeError("policy inheritance loop detected: " + " -> ".join([*chain, cursor]))
        seen.add(cursor)
        chain.append(cursor)
        if cursor not in cache:
            cache[cursor] = _load_raw(cursor)
        cursor = str(cache[chain[-1]].get("inherits") or "")
    merged: dict[str, Any] = {}
    for base_name in reversed(chain):
        # Each base is already cached; copy so we can pop ``inherits``
        # from the local view without mutating the cache.
        raw = dict(cache[base_name])
        raw.pop("inherits", None)
        merged.update(raw)
    return merged


__all__ = ["list_bundled_policies", "load_policy"]
