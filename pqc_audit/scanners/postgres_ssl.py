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
