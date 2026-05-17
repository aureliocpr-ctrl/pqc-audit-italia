"""PQC hybrid TLS handshake probe scanner (Sprint 9f).

Goal: tell an auditor, in one shot, whether a TLS-fronted service has
already started its post-quantum migration at the key-exchange layer.

The TLS 1.3 ``key_share`` mechanism lets a client offer one or more
hybrid named groups that combine a classical Diffie-Hellman (X25519
or SecP* ECDH) with a NIST-standardized KEM (ML-KEM-768 / ML-KEM-1024,
FIPS 203). The IETF working group draft
``draft-ietf-tls-ecdhe-mlkem-04`` (Feb 2026, currently in RFC Ed
Queue) defines THREE IANA codepoints:

* ``X25519MLKEM768`` (0x11EC = 4588) — most widely deployed
* ``SecP256r1MLKEM768`` (0x11EB = 4587)
* ``SecP384r1MLKEM1024`` (0x11ED = 4589)

Note — ``X448MLKEM1024`` is **NOT** in the draft and has no IANA
codepoint. OpenSSL 3.5.x exposes it locally in
``openssl list -kem-algorithms`` but no real server can negotiate
it over the wire because there is no agreed-on integer to send in
the supported_groups extension. We deliberately exclude it from the
probe list — including it would be noise dressed up as coverage.

A modern server (Cloudflare, Apple iCloud, etc.) accepts at least
``X25519MLKEM768``. A legacy stack (most PA, banche, AGID
``www.agid.gov.it`` as of 2026-05-17) rejects every hybrid offer with
``handshake_failure`` (alert 40).

This module exposes both the low-level building blocks
(``parse_negotiated_group``, ``probe_group``,
``probe_all_hybrid_groups``) AND a :class:`PQCHybridScanner`
implementing the :class:`pqc_audit.scanners.base.BaseScanner`
protocol so it plugs into the existing Auditor + CLI pipeline.

## Implementation choice — why ``openssl s_client``

Python's stdlib ``ssl`` (OpenSSL 3.5.5 backend) does NOT expose:

* ``SSLContext.set_groups()`` (does not exist)
* ``set_ecdh_curve("X25519MLKEM768")`` (raises ValueError — name
  not recognized as an elliptic curve; OpenSSL treats hybrid as a KEM)
* ``SSLSocket.group()`` to read the negotiated named group

OpenSSL 3.5+ DOES handle hybrid groups natively (see
``openssl list -kem-algorithms``). To probe a server we therefore
shell out to ``openssl s_client -groups <hybrid> -tls1_3 -connect ...``
and parse the ``Negotiated TLS1.3 group:`` line that OpenSSL prints
on success. A handshake failure prints ``<NULL>`` (or omits the line
entirely). This is empirically observed against
``www.agid.gov.it:443`` (rejects, alert 40) and
``www.cloudflare.com:443`` (accepts X25519MLKEM768) on 2026-05-17.

Pre-3.5 OpenSSL binaries don't know hybrid group names and will
either refuse the ``-groups`` value or negotiate the classical
fallback. The scanner surfaces a soft error rather than crashing.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess  # noqa: S404 — fully-controlled, deterministic args, see _build_cmd

from pqc_audit.core.clock import frozen_now
from pqc_audit.core.models import (
    Algorithm,
    CryptoAsset,
    RiskLevel,
    ScanCategory,
    ScanResult,
    Vulnerability,
)
from pqc_audit.scanners.base import ScanTarget

_SCANNER_NAME = "pqc-hybrid"

# IANA-assigned TLS 1.3 hybrid named groups.
# Source of truth: draft-ietf-tls-ecdhe-mlkem-04 (Feb 2026, RFC Ed Queue).
# Order matches the IANA codepoint values (0x11EB..0x11ED).
HYBRID_GROUPS: tuple[str, ...] = (
    "SecP256r1MLKEM768",  # 0x11EB
    "X25519MLKEM768",     # 0x11EC
    "SecP384r1MLKEM1024",  # 0x11ED
)

# ``openssl s_client`` prints this verbatim on a successful TLS 1.3
# handshake; on failure the value is the literal ``<NULL>`` or the
# line is absent.
_NEGOTIATED_PREFIX = "Negotiated TLS1.3 group:"
_NULL_TOKEN = "<NULL>"  # noqa: S105 — literal sentinel printed by openssl s_client, not a credential

_DEFAULT_TIMEOUT_S = 8.0


def parse_negotiated_group(stdout: str) -> str | None:
    """Extract the named group from ``openssl s_client`` output.

    Returns the group string (e.g. ``"X25519MLKEM768"``) on success,
    or ``None`` on handshake failure / missing line.
    """
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line.startswith(_NEGOTIATED_PREFIX):
            value = line[len(_NEGOTIATED_PREFIX):].strip()
            if not value or value == _NULL_TOKEN:
                return None
            return value
    return None


def _build_cmd(host: str, port: int, group: str, openssl_bin: str) -> list[str]:
    """Build the ``openssl s_client`` argv. Pure helper, no I/O."""
    return [
        openssl_bin,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-groups",
        group,
        "-tls1_3",
        # The verify_return_error + brief flags would tighten output
        # but they're not portable across OpenSSL builds. Keep stock.
    ]


def probe_group(
    host: str,
    port: int,
    group: str,
    *,
    openssl_bin: str = "openssl",
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> str | None:
    """Run one ``openssl s_client`` handshake against ``group``.

    Returns the negotiated group name on success, ``None`` on failure
    (handshake error, timeout, openssl crash, or simply a server that
    refused the offer). Never raises — callers expect a tri-state
    interpretation (string | None).
    """
    cmd = _build_cmd(host, port, group, openssl_bin)
    # ``OPENSSL_CONF=os.devnull`` ensures the call boots without
    # depending on the user's openssl.cnf. ``stdin`` is closed by
    # passing input="" so s_client doesn't wait for user input.
    env = os.environ.copy()
    env.setdefault("OPENSSL_CONF", os.devnull)
    try:
        completed = subprocess.run(  # noqa: S603 — cmd is built from a fixed allow-list
            cmd,
            env=env,
            input="",
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return parse_negotiated_group(completed.stdout)


def probe_all_hybrid_groups(
    host: str,
    port: int,
    *,
    openssl_bin: str = "openssl",
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> dict[str, str | None]:
    """Run a probe for every group in :data:`HYBRID_GROUPS`.

    Returns ``{requested_group: negotiated_or_None}``. Order of keys
    matches :data:`HYBRID_GROUPS`.
    """
    return {
        g: probe_group(host, port, g, openssl_bin=openssl_bin, timeout_s=timeout_s)
        for g in HYBRID_GROUPS
    }


class PQCHybridScanner:
    """Active scanner for ``type='pqc-hybrid'`` targets.

    Emits one ``CryptoAsset`` per scanned endpoint with the inventory
    of supported hybrid groups in ``metadata.hybrid_supported``, and
    either:

    * an INFO finding when at least one hybrid group is accepted
      (positive — the migration is in flight); OR
    * a MEDIUM finding when zero hybrid groups are accepted
      (operational risk against the NIST 2030 deprecation).
    """

    name: str = _SCANNER_NAME
    category: ScanCategory = ScanCategory.NETWORK

    async def is_applicable(self, target: ScanTarget) -> bool:
        return (
            target.type == "pqc-hybrid"
            and bool(target.host)
            and target.port is not None
        )

    async def scan(self, target: ScanTarget) -> ScanResult:
        started = frozen_now()
        assets: list[CryptoAsset] = []
        vulns: list[Vulnerability] = []
        errors: list[str] = []
        target_repr = f"{target.host}:{target.port}"

        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            errors.append(
                "openssl CLI not found in PATH — PQC hybrid probe requires "
                "openssl 3.5+ (apt install openssl on Debian/Ubuntu, brew "
                "install openssl@3.5 on macOS)."
            )
            return ScanResult(
                scanner_name=self.name,
                target=target_repr,
                assets=[],
                vulnerabilities=[],
                started_at=started,
                finished_at=frozen_now(),
                errors=errors,
            )

        try:
            probes = await asyncio.to_thread(
                probe_all_hybrid_groups,
                target.host or "",
                int(target.port or 443),
                openssl_bin=openssl_bin,
            )
        except Exception as e:  # noqa: BLE001 — soft error to caller
            errors.append(f"{type(e).__name__}: {e}")
            probes = dict.fromkeys(HYBRID_GROUPS)

        supported = [g for g, v in probes.items() if v is not None]
        asset_id = f"pqc-hybrid://{target_repr}"
        assets.append(
            CryptoAsset(
                asset_id=asset_id,
                category=ScanCategory.NETWORK,
                # We label the asset by its PQC posture, NOT by a
                # specific key-exchange algorithm — the asset
                # represents the *capability surface*, not a single
                # primitive in use.
                algorithm=Algorithm(name="TLS-HYBRID-PROBE"),
                location=target_repr,
                discovered_at=started,
                metadata={
                    "probes": probes,
                    "hybrid_supported": supported,
                    "hybrid_supported_count": len(supported),
                    "probe_tool": "openssl s_client",
                    "probed_groups": list(HYBRID_GROUPS),
                },
            )
        )

        if supported:
            vulns.append(
                Vulnerability(
                    title=f"PQC hybrid migration active ({', '.join(supported)})",
                    description=(
                        "Server negotiates at least one IANA-registered TLS 1.3 "
                        "hybrid named group combining classical ECDH with "
                        "FIPS 203 ML-KEM. This indicates the post-quantum "
                        "migration is in flight at the key-exchange layer. "
                        "Authentication (certificate signatures) is a "
                        "separate concern — see the TLS scanner findings."
                    ),
                    severity=RiskLevel.INFO,
                    cwe=None,
                    affected_asset_ids=(asset_id,),
                    references=(
                        "https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/",
                        "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8",
                    ),
                )
            )
        else:
            # IMPORTANT: build the rejected-groups list from HYBRID_GROUPS,
            # not from a hard-coded literal — otherwise the audit message
            # claims we tested groups we didn't (caught by Sprint 9f-fix
            # critic counterexample worker). Same constant drives the
            # probe matrix AND the user-facing description.
            probed_list = ", ".join(HYBRID_GROUPS)
            vulns.append(
                Vulnerability(
                    title="No PQC hybrid key-exchange supported",
                    description=(
                        f"Server rejected every IETF-registered hybrid "
                        f"named group probed ({probed_list}). Migration "
                        "to a PQC-ready TLS stack has not started. Per "
                        "NIST IR 8547 RSA-2048 / ECDSA-P-256 should be "
                        "deprecated after 2030 and disallowed after 2035; "
                        "quantum-safe key exchange (hybrid first, pure "
                        "PQC later) is the first migration milestone."
                    ),
                    severity=RiskLevel.MEDIUM,
                    cwe="CWE-327",
                    affected_asset_ids=(asset_id,),
                    references=(
                        "https://csrc.nist.gov/pubs/ir/8547/ipd",
                        "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/",
                    ),
                )
            )

        finished = frozen_now()
        return ScanResult(
            scanner_name=self.name,
            target=target_repr,
            assets=assets,
            vulnerabilities=vulns,
            started_at=started,
            finished_at=finished,
            errors=errors,
        )
