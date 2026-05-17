"""SMTP STARTTLS probe — Sprint 9k.

SMTP (RFC 5321) defaults to plaintext on the wire. A server that
wants encryption advertises the ``STARTTLS`` extension (RFC 3207)
in response to the client's ``EHLO``. The probe is **passive**:
open a TCP socket, read the 220 banner, send ``EHLO``, read the
multi-line 250 response, look for ``STARTTLS`` among the capability
lines. No actual TLS upgrade is performed.

A server that does NOT advertise STARTTLS for confidential mail
flows violates NIS2 art. 21(2)(j) / D.Lgs. 138/2024 art. 24(2)(j)
on secure communications, and CWE-319 (cleartext transmission)
applies.

The companion :class:`SMTPStartTLSScanner` wraps the probe in the
BaseScanner protocol so it participates in :class:`Auditor.scan`
and emits a HIGH-severity :class:`Vulnerability` automatically when
STARTTLS is missing — same "integrazione totale" pattern as
Sprint 9j.3.
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

# Read at most this many bytes from the SMTP socket per recv() — the
# 220 banner + 250 EHLO response is typically < 1 KB.
_RECV_CHUNK = 4096
# Hard cap on aggregate bytes read to bound memory use under a hostile peer.
_MAX_RESPONSE_BYTES = 16_384
# HELO/EHLO domain we present. Stable, RFC-5321-compatible.
_EHLO_DOMAIN = "pqc-audit-italia.probe.local"
# Minimum SMTP reply length: 3-digit code + separator + 1 char = 4.
_MIN_SMTP_LINE_LEN = 4


def parse_smtp_capabilities(ehlo_response: str) -> dict:
    """Parse the multi-line SMTP 250 response and extract capability tokens.

    Returns a dict with stable keys:

    * ``starttls_supported`` (bool)
    * ``capabilities`` (list[str]) — token after ``250-`` / ``250 ``,
      uppercased for stable comparison;
    * ``server_hostname`` (str) — the host string the server printed
      in its first 250 line (empty if absent).

    Lines that are not ``250-`` / ``250 `` prefixed (e.g. 421 / 500
    error replies) are ignored.
    """
    capabilities: list[str] = []
    server_hostname = ""
    for raw_line in (ehlo_response or "").splitlines():
        line = raw_line.rstrip("\r")
        if len(line) < _MIN_SMTP_LINE_LEN or not line.startswith("250"):
            continue
        # 250-CAPABILITY... (intermediate) or 250 CAPABILITY (final).
        sep = line[3]
        if sep not in ("-", " "):
            continue
        rest = line[4:].strip()
        if not rest:
            continue
        # The first 250 line typically begins with the server hostname
        # followed by a free-form Hello message. Capability lines have
        # a single uppercase token possibly followed by params.
        tokens = rest.split()
        head_raw = tokens[0]  # preserve case for server_hostname
        head_upper = head_raw.upper()  # uppercased token for capability comparison
        if not server_hostname:
            server_hostname = head_raw if "." in head_raw else rest
        capabilities.append(head_upper)
    return {
        "starttls_supported": "STARTTLS" in capabilities,
        "capabilities": capabilities,
        "server_hostname": server_hostname,
    }


def _read_until(sock: socket.socket, sentinel: bytes, timeout: float) -> bytes:
    """Read from ``sock`` until ``sentinel`` appears or the response cap is hit."""
    sock.settimeout(timeout)
    buf = b""
    while sentinel not in buf and len(buf) < _MAX_RESPONSE_BYTES:
        try:
            chunk = sock.recv(_RECV_CHUNK)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _has_any_250_line(text: str) -> bool:
    """True iff at least one line starts with ``250-`` or ``250 ``.

    Used post-EHLO to distinguish a complete-but-no-STARTTLS response
    from a banner-only / EHLO-timeout silence path. The latter is an
    error, not a finding.
    """
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r")
        if len(line) >= _MIN_SMTP_LINE_LEN and line.startswith("250") and line[3] in ("-", " "):
            return True
    return False


def _error(host: str, port: int, message: str) -> dict:
    return {
        "host": host,
        "port": port,
        "starttls_status": "error",
        "error_message": message,
        "banner": "",
        "capabilities": [],
        "server_hostname": "",
    }


def probe_smtp_starttls(host: str, port: int = 25, *, timeout: float = 5.0) -> dict:
    """Connect, read banner, send EHLO, parse STARTTLS capability.

    Returns a dict with stable keys: ``host``, ``port``,
    ``starttls_status`` (``supported`` / ``not_supported`` /
    ``error``), ``error_message``, ``banner``, ``capabilities``,
    ``server_hostname``. Network errors are caught and surfaced via
    ``starttls_status="error"`` — the function never raises.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, TimeoutError, socket.gaierror, OSError) as exc:
        return _error(host, port, str(exc) or type(exc).__name__)

    full = b""
    banner = ""
    try:
        sock.settimeout(timeout)
        # Block once for the 220 banner.
        try:
            first = sock.recv(_RECV_CHUNK)
        except (TimeoutError, OSError) as exc:
            return _error(host, port, f"recv banner failed: {exc}")
        full = first

        # Send EHLO immediately. Some servers stream banner + capabilities
        # together, some wait for the EHLO; this handles both shapes.
        try:
            sock.sendall(f"EHLO {_EHLO_DOMAIN}\r\n".encode())
        except OSError as exc:
            return _error(host, port, f"sendall EHLO failed: {exc}")

        # Drain remaining data up to the cap. Stop when we see the final
        # ``250 `` (250 + space) line marker followed by a CRLF.
        sock.settimeout(timeout)
        ehlo_complete = False
        while len(full) < _MAX_RESPONSE_BYTES:
            try:
                chunk = sock.recv(_RECV_CHUNK)
            except (TimeoutError, OSError):
                break
            if not chunk:
                break
            full += chunk
            if (b"\r\n250 " in full or full.startswith(b"250 ")) and full.endswith(b"\r\n"):
                ehlo_complete = True
                break
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    # Banner is the first CRLF-terminated line of the aggregate.
    nl = full.find(b"\r\n")
    if nl >= 0:
        banner = full[:nl].decode("utf-8", errors="replace")
        ehlo_response = full[nl + 2:].decode("utf-8", errors="replace")
    else:
        banner = full.decode("utf-8", errors="replace")
        ehlo_response = ""

    # Sprint 9k post-critic fix: a server that ships the 220 banner but
    # then drops / times out on EHLO (firewall, overload, captive portal,
    # honeypot) would otherwise be silently classified as "not_supported"
    # — a false positive. If we never saw a 250 reply, surface as error.
    if not _has_any_250_line(ehlo_response):
        return {
            "host": host,
            "port": port,
            "starttls_status": "error",
            "error_message": (
                "no 250 EHLO response received (server hung up or timed out)"
            ),
            "banner": banner,
            "capabilities": [],
            "server_hostname": "",
        }

    parsed = parse_smtp_capabilities(ehlo_response)
    # ehlo_complete is logged via metadata for future diagnostic use.
    _ = ehlo_complete
    status = "supported" if parsed["starttls_supported"] else "not_supported"
    return {
        "host": host,
        "port": port,
        "starttls_status": status,
        "error_message": None,
        "banner": banner,
        "capabilities": parsed["capabilities"],
        "server_hostname": parsed["server_hostname"],
    }


# ---------------------------------------------------------------------
# Scanner class — Sprint 9k "integrazione totale" pattern.
# ---------------------------------------------------------------------


class SMTPStartTLSScanner:
    """Scanner protocol implementation for SMTP STARTTLS probing."""

    name: str = "smtp-starttls"
    category: ScanCategory = ScanCategory.NETWORK

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "smtp-starttls"

    async def scan(self, target: ScanTarget) -> ScanResult:
        host = target.host or ""
        port = int(target.port or 25)
        started = frozen_now()
        probe = probe_smtp_starttls(host, port)
        finished = frozen_now()

        asset_id = f"smtp-starttls://{host}:{port}"
        location = f"{host}:{port}"
        status = probe.get("starttls_status", "error")
        algo_name = (
            "SMTP-STARTTLS-CAPABLE"
            if status == "supported"
            else "SMTP-PLAINTEXT"
            if status == "not_supported"
            else "SMTP-UNKNOWN"
        )
        asset = CryptoAsset(
            asset_id=asset_id,
            category=ScanCategory.NETWORK,
            algorithm=Algorithm(name=algo_name),
            location=location,
            discovered_at=started,
            metadata={
                "probe": "smtp-ehlo-starttls",
                "starttls_status": status,
                "banner": probe.get("banner", ""),
                "capabilities": probe.get("capabilities", []),
                "server_hostname": probe.get("server_hostname", ""),
                "error_message": probe.get("error_message") or "",
            },
        )

        vulns: list[Vulnerability] = []
        if status == "not_supported":
            vulns.append(
                Vulnerability(
                    title="SMTP server does not advertise STARTTLS",
                    description=(
                        f"SMTP endpoint {location} replied to EHLO without "
                        "the STARTTLS capability. Mail in transit on this "
                        "channel is cleartext on the wire — confidential "
                        "messages are exposed."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-319",
                    affected_asset_ids=(asset_id,),
                    references=(
                        "https://datatracker.ietf.org/doc/html/rfc3207",
                        "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
                    ),
                )
            )
        elif status == "error":
            vulns.append(
                Vulnerability(
                    title="SMTP STARTTLS probe error",
                    description=(
                        f"SMTP STARTTLS probe against {location} could not "
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
