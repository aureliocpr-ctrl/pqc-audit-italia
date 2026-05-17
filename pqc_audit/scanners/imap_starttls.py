"""IMAP STARTTLS probe — Sprint 9m.

IMAP (RFC 3501) defaults to plaintext on port 143. A server that
wants encryption advertises the ``STARTTLS`` capability (RFC 2595)
in response to the ``CAPABILITY`` command. The probe is purely
passive: connect, read ``* OK`` greeting, send tagged
``CAPABILITY``, parse capability tokens.

A server without ``STARTTLS`` on a mailbox channel violates NIS2
art. 21(2)(j) / D.Lgs. 138/2024 art. 24(2)(j) and CWE-319
cleartext transmission.

Wire shape::

    -> connect
    <- "* OK IMAP4rev1 ready\\r\\n"           (greeting)
    -> "A001 CAPABILITY\\r\\n"
    <- "* CAPABILITY IMAP4rev1 STARTTLS …\\r\\n"   (data line)
    <- "A001 OK CAPABILITY completed\\r\\n"        (tagged final)

The presence of a ``* CAPABILITY`` data line is the signal that the
exchange completed. Greeting-only-then-silence (see Sprint 9k
counterexample) is surfaced as ``error``, not ``not_supported``.
"""

from __future__ import annotations

import contextlib
import socket

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

_RECV_CHUNK = 4096
_MAX_RESPONSE_BYTES = 16_384
_IMAP_TAG = "A001"


def parse_imap_capabilities(response: str) -> dict:
    """Extract IMAP capability tokens from a CAPABILITY response.

    Returns ``{"starttls_supported": bool, "capabilities": list[str]}``.
    Tokens are uppercased for stable comparison. The ``* CAPABILITY``
    data line carries the tokens; the tagged final line (``A001 OK``)
    is ignored for capability extraction.
    """
    capabilities: list[str] = []
    for raw in (response or "").splitlines():
        line = raw.rstrip("\r")
        if not line:
            continue
        # Untagged CAPABILITY data line: "* CAPABILITY TOKEN1 TOKEN2 ..."
        upper = line.upper()
        if upper.startswith("* CAPABILITY"):
            rest = line[len("* CAPABILITY"):].strip()
            for tok in rest.split():
                capabilities.append(tok.upper())
    return {
        "starttls_supported": "STARTTLS" in capabilities,
        "capabilities": capabilities,
    }


def _error(host: str, port: int, message: str) -> dict:
    return {
        "host": host,
        "port": port,
        "starttls_status": "error",
        "error_message": message,
        "greeting": "",
        "capabilities": [],
    }


def probe_imap_starttls(
    host: str, port: int = 143, *, timeout: float = 5.0
) -> dict:
    """Connect, read greeting, send CAPABILITY, parse response.

    Returns ``{host, port, starttls_status, error_message,
    greeting, capabilities}``. ``starttls_status`` is
    ``"supported" / "not_supported" / "error"``. Greeting-only
    silence is surfaced as ``error`` — never raises.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, TimeoutError, socket.gaierror, OSError) as exc:
        return _error(host, port, str(exc) or type(exc).__name__)

    full = b""
    try:
        sock.settimeout(timeout)
        # 1) Greeting (one short read should suffice).
        try:
            first = sock.recv(_RECV_CHUNK)
        except (TimeoutError, OSError) as exc:
            return _error(host, port, f"recv greeting failed: {exc}")
        full = first

        # 2) Send CAPABILITY.
        try:
            sock.sendall(f"{_IMAP_TAG} CAPABILITY\r\n".encode())
        except OSError as exc:
            return _error(host, port, f"sendall CAPABILITY failed: {exc}")

        # 3) Drain until we see the tagged final line "A001 OK ..." or cap.
        sock.settimeout(timeout)
        final_token = f"\r\n{_IMAP_TAG} ".encode()
        while len(full) < _MAX_RESPONSE_BYTES:
            try:
                chunk = sock.recv(_RECV_CHUNK)
            except (TimeoutError, OSError):
                break
            if not chunk:
                break
            full += chunk
            if final_token in full and full.endswith(b"\r\n"):
                break
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    # Greeting is the first CRLF-terminated line (untagged * OK).
    nl = full.find(b"\r\n")
    if nl >= 0:
        greeting = full[:nl].decode("utf-8", errors="replace")
        cap_response = full[nl + 2:].decode("utf-8", errors="replace")
    else:
        greeting = full.decode("utf-8", errors="replace")
        cap_response = ""

    # Sprint 9m anti-false-positive (lesson from Sprint 9k):
    # no * CAPABILITY data line => server hung up / timed out after
    # greeting => error, not not_supported.
    if "* CAPABILITY" not in cap_response.upper():
        return {
            "host": host,
            "port": port,
            "starttls_status": "error",
            "error_message": (
                "no * CAPABILITY response received (server hung up or timed out)"
            ),
            "greeting": greeting,
            "capabilities": [],
        }

    parsed = parse_imap_capabilities(cap_response)
    status = "supported" if parsed["starttls_supported"] else "not_supported"
    return {
        "host": host,
        "port": port,
        "starttls_status": status,
        "error_message": None,
        "greeting": greeting,
        "capabilities": parsed["capabilities"],
    }


# ---------------------------------------------------------------------
# Scanner class.
# ---------------------------------------------------------------------


class IMAPStartTLSScanner:
    """Scanner protocol implementation for IMAP STARTTLS probing."""

    name: str = "imap-starttls"
    category: ScanCategory = ScanCategory.NETWORK

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "imap-starttls"

    async def scan(self, target: ScanTarget) -> ScanResult:
        host = target.host or ""
        port = int(target.port or 143)
        started = frozen_now()
        probe = probe_imap_starttls(host, port)
        finished = frozen_now()

        asset_id = f"imap-starttls://{host}:{port}"
        location = f"{host}:{port}"
        status = probe.get("starttls_status", "error")
        algo_name = (
            "IMAP-STARTTLS-CAPABLE"
            if status == "supported"
            else "IMAP-PLAINTEXT"
            if status == "not_supported"
            else "IMAP-UNKNOWN"
        )
        asset = CryptoAsset(
            asset_id=asset_id,
            category=ScanCategory.NETWORK,
            algorithm=Algorithm(name=algo_name),
            location=location,
            discovered_at=started,
            metadata={
                "probe": "imap-capability-starttls",
                "starttls_status": status,
                "greeting": probe.get("greeting", ""),
                "capabilities": probe.get("capabilities", []),
                "error_message": probe.get("error_message") or "",
            },
        )

        vulns: list[Vulnerability] = []
        if status == "not_supported":
            vulns.append(
                Vulnerability(
                    title="IMAP server does not advertise STARTTLS",
                    description=(
                        f"IMAP endpoint {location} returned a CAPABILITY "
                        "response without STARTTLS. Mail clients fetching "
                        "via this channel transit credentials and message "
                        "bodies in cleartext."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-319",
                    affected_asset_ids=(asset_id,),
                    references=(
                        "https://datatracker.ietf.org/doc/html/rfc2595",
                        "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
                    ),
                )
            )
        elif status == "error":
            vulns.append(
                Vulnerability(
                    title="IMAP STARTTLS probe error",
                    description=(
                        f"IMAP STARTTLS probe against {location} could not "
                        f"complete: {probe.get('error_message') or 'unknown'}. "
                        "The audit cannot make a positive or negative "
                        "statement about STARTTLS."
                    ),
                    severity=RiskLevel.INFO,
                    cwe=None,
                    affected_asset_ids=(asset_id,),
                )
            )

        return ScanResult(
            scanner_name=self.name,
            target=location,
            assets=[asset],
            vulnerabilities=vulns,
            started_at=started,
            finished_at=finished,
        )
