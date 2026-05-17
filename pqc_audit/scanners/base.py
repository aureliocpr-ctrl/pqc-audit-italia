"""Scanner protocol and shared :class:`ScanTarget` model.

Each concrete scanner (TLS, certs, SSH, ...) implements
:class:`BaseScanner`, exposes a stable ``name`` and ``category``,
and an async ``scan(target) -> ScanResult`` method.

The protocol is intentionally narrow so scanners can be combined
arbitrarily — the orchestrator picks scanners by ``is_applicable``.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from pqc_audit.core.models import ScanCategory, ScanResult

TargetType = Literal[
    "tls",
    "ssh",
    "vpn",
    "certs",
    "filesystem",
    "binary",
    "code",
    "config",
    "token",
    "iac",
    "jwks",
    "pqc-hybrid",
    "postgres-ssl",
    "mysql-ssl",
    "smtp-starttls",
]


_TYPE_TO_CATEGORY: dict[str, ScanCategory] = {
    "tls": ScanCategory.NETWORK,
    "ssh": ScanCategory.NETWORK,
    "vpn": ScanCategory.NETWORK,
    "certs": ScanCategory.FILESYSTEM,
    "filesystem": ScanCategory.FILESYSTEM,
    "binary": ScanCategory.BINARY,
    "code": ScanCategory.CODE,
    "config": ScanCategory.CONFIG,
    "token": ScanCategory.CONFIG,
    "iac": ScanCategory.CODE,
    "jwks": ScanCategory.NETWORK,
    "pqc-hybrid": ScanCategory.NETWORK,
    "postgres-ssl": ScanCategory.DATABASE,
    "mysql-ssl": ScanCategory.DATABASE,
    "smtp-starttls": ScanCategory.NETWORK,
}


def target_to_category(target_type: str) -> ScanCategory:
    """Map a target type literal to its broad scan category."""
    if target_type not in _TYPE_TO_CATEGORY:
        raise ValueError(f"unknown target type: {target_type!r}")
    return _TYPE_TO_CATEGORY[target_type]


class ScanTarget(BaseModel):
    """A scan target description, validated up front.

    Network targets use ``host`` + ``port``. Filesystem / config / code
    targets use ``path``. Other fields stay optional / default.
    """

    model_config = ConfigDict(frozen=True)

    type: TargetType
    host: str | None = Field(default=None, description="Hostname or IP for network targets.")
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str | None = Field(
        default=None, description="Filesystem path for FS / code / config / binary targets."
    )
    extra: dict[str, str] = Field(default_factory=dict)


@runtime_checkable
class BaseScanner(Protocol):
    """Protocol every concrete scanner must satisfy."""

    name: str
    category: ScanCategory

    async def is_applicable(self, target: ScanTarget) -> bool:
        """Return True if this scanner can handle the given target."""
        ...

    async def scan(self, target: ScanTarget) -> ScanResult:
        """Run the scan and return a :class:`ScanResult`."""
        ...
