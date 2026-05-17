"""PostgreSQL SSL probe — Sprint 9j.

PostgreSQL servers do NOT begin with a TLS ClientHello. A client that
wants encryption must first send an ``SSLRequest`` message:

* 8 bytes total, big-endian:
  ``00 00 00 08`` (length=8) ``04 d2 16 2f`` (magic 80877103,
  = ``1234`` in MSW + ``5679`` in LSW).
* Server responds with **one byte**:
  * ``'S'`` (0x53) — SSL supported, the connection upgrades to TLS;
  * ``'N'`` (0x4E) — SSL not supported, server expects plaintext.

A naive ``ssl.wrap_socket()`` against a Postgres port would fail
because the server is not in TLS state yet. This probe implements
the correct two-step handshake.

For the audit value-add, "not supported" on a production database
should be a HIGH finding: NIS2 art. 21(2)(h) requires encryption
"in trasmissione" for confidential data.

Source: PostgreSQL docs, "Message Formats — SSLRequest",
https://www.postgresql.org/docs/current/protocol-message-formats.html
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

# 8 bytes: Int32(8) length + Int32(80877103) magic.
SSL_REQUEST_BYTES: bytes = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"

_RESPONSE_SUPPORTED = b"S"  # 0x53
_RESPONSE_NOT_SUPPORTED = b"N"  # 0x4E


def parse_ssl_response_byte(data: bytes) -> str:
    """Classify the first byte of the server's SSLRequest response.

    Returns one of:

    * ``"supported"`` — server replied ``'S'`` (offers TLS upgrade);
    * ``"not_supported"`` — server replied ``'N'`` (plaintext only);
    * ``"error"`` — empty input or unknown byte (protocol violation).

    Extra bytes past the first are tolerated but ignored — the
    protocol guarantees exactly 1 byte.
    """
    if not data:
        return "error"
    first = data[:1]
    if first == _RESPONSE_SUPPORTED:
        return "supported"
    if first == _RESPONSE_NOT_SUPPORTED:
        return "not_supported"
    return "error"


def probe_postgres_ssl(
    host: str,
    port: int = 5432,
    *,
    timeout: float = 5.0,
) -> dict:
    """Open a TCP socket to ``host:port`` and probe PostgreSQL SSL support.

    Returns a 5-key dict ``{host, port, ssl_status, error_message,
    raw_response_hex}``. ``ssl_status`` is one of ``supported``,
    ``not_supported``, ``error``. ``raw_response_hex`` is the
    lowercase hex of the first response byte (empty string on error).
    Network and protocol errors are caught and surfaced via
    ``ssl_status="error"`` + ``error_message`` — the function never
    raises to the caller.
    """
    base: dict = {
        "host": host,
        "port": port,
        "ssl_status": "error",
        "error_message": None,
        "raw_response_hex": "",
    }
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, TimeoutError, socket.gaierror, OSError) as exc:
        return {**base, "error_message": str(exc) or type(exc).__name__}

    try:
        sock.settimeout(timeout)
        sock.sendall(SSL_REQUEST_BYTES)
        # PostgreSQL guarantees 1 byte for the SSLRequest response.
        # We pull up to 4 to be defensive against odd server behavior.
        response = sock.recv(4)
    except (TimeoutError, OSError) as exc:
        return {**base, "error_message": str(exc) or type(exc).__name__}
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    raw_hex = response[:1].hex() if response else ""
    status = parse_ssl_response_byte(response)
    return {
        "host": host,
        "port": port,
        "ssl_status": status,
        "error_message": None if status != "error" else f"unexpected response: {raw_hex!r}",
        "raw_response_hex": raw_hex,
    }


# ---------------------------------------------------------------------
# Scanner class — Sprint 9j.3 "integrazione totale".
# Wraps the probe in the BaseScanner protocol so it participates in
# Auditor.scan and produces audit-grade CryptoAsset + Vulnerability.
# ---------------------------------------------------------------------


class PostgresSSLScanner:
    """Scanner protocol implementation for PostgreSQL SSL probing.

    Emits a single :class:`CryptoAsset` (category DATABASE) per
    target, plus a HIGH :class:`Vulnerability` with CWE-319 when
    the server refuses SSL — citable verbatim under D.Lgs. 138/2024
    art. 24(2)(h) via :mod:`pqc_audit.compliance.nis2`.
    """

    name: str = "postgres-ssl"
    category: ScanCategory = ScanCategory.DATABASE

    async def is_applicable(self, target: ScanTarget) -> bool:
        return target.type == "postgres-ssl"

    async def scan(self, target: ScanTarget) -> ScanResult:
        host = target.host or ""
        port = int(target.port or 5432)
        started = frozen_now()
        probe = probe_postgres_ssl(host, port)
        finished = frozen_now()

        asset_id = f"postgres-ssl://{host}:{port}"
        location = f"{host}:{port}"
        # The "algorithm" for a database SSL asset is the negotiated
        # cipher — but we don't actually upgrade in this probe. We
        # surface "TLS-CAPABLE" or "PLAINTEXT" as a synthetic
        # placeholder so the asset record is honest.
        algo_name = "POSTGRES-TLS-CAPABLE" if probe["ssl_status"] == "supported" else (
            "POSTGRES-PLAINTEXT" if probe["ssl_status"] == "not_supported" else "POSTGRES-UNKNOWN"
        )
        asset = CryptoAsset(
            asset_id=asset_id,
            category=ScanCategory.DATABASE,
            algorithm=Algorithm(name=algo_name),
            location=location,
            discovered_at=started,
            metadata={
                "probe": "postgres-sslrequest",
                "ssl_status": probe["ssl_status"],
                "raw_response_hex": probe["raw_response_hex"],
                "error_message": probe["error_message"] or "",
            },
        )

        vulns: list[Vulnerability] = []
        if probe["ssl_status"] == "not_supported":
            vulns.append(
                Vulnerability(
                    title="PostgreSQL allows non-SSL connection",
                    description=(
                        f"PostgreSQL server at {location} responded 'N' to the "
                        "SSLRequest message, indicating it accepts plaintext "
                        "connections. Confidential data transiting this "
                        "endpoint is cleartext on the wire."
                    ),
                    severity=RiskLevel.HIGH,
                    cwe="CWE-319",
                    affected_asset_ids=(asset_id,),
                    references=(
                        "https://www.postgresql.org/docs/current/ssl-tcp.html",
                        "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
                    ),
                )
            )
        elif probe["ssl_status"] == "error":
            vulns.append(
                Vulnerability(
                    title="PostgreSQL SSL probe error",
                    description=(
                        f"PostgreSQL SSL probe against {location} could not "
                        f"complete: {probe['error_message']}. The audit cannot "
                        "make a positive or negative statement about SSL."
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
