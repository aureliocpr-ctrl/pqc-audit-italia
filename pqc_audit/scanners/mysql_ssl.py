"""MySQL/MariaDB SSL probe — Sprint 9j.2.

MySQL servers speak first: on TCP connect, the server immediately
sends an Initial Handshake Packet (Protocol::HandshakeV10) that
encodes its supported capabilities — including the
``CLIENT_SSL`` flag at bit 11 (``0x0800``, decimal ``2048``).

This probe is **passive**: read the handshake, parse the capability
flags, never sends an SSLRequest. Audit-friendly because it does
not perturb the server state.

Wire layout (MySQL packet = 4-byte header + payload):

* header: 3 bytes payload-length (LE) + 1 byte sequence-id (0).
* payload (Protocol::HandshakeV10):
    1 byte   protocol_version (always ``0x0a``)
    var      server_version (NUL-terminated string)
    4 bytes  thread_id
    8 bytes  auth-plugin-data-part-1
    1 byte   filler (``0x00``)
    2 bytes  capability_flags_1 (low 16 bits, LE) ← CLIENT_SSL bit
    1 byte   character_set
    2 bytes  status_flags
    2 bytes  capability_flags_2 (high 16 bits, LE)
    ... (rest optional — auth-plugin-data-part-2 etc.; we stop here)

References:

* Protocol::HandshakeV10 —
  https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
* CLIENT_SSL = 2048 (0x0800, bit 11) —
  https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
"""

from __future__ import annotations

import contextlib
import socket
import struct

CLIENT_SSL_BIT: int = 0x0800  # 2048, bit 11

# Bytes after server_version NUL + fixed prefix in payload until the
# end of capability_flags_2: 4 (thread_id) + 8 (auth1) + 1 (filler)
# + 2 (cap1) + 1 (charset) + 2 (status) + 2 (cap2) = 20.
_MIN_BYTES_AFTER_VERSION = 20

# Offsets within the "post server_version" slice:
_OFFSET_CAPABILITY_FLAGS_1 = 4 + 8 + 1  # 13
_OFFSET_CHARACTER_SET = _OFFSET_CAPABILITY_FLAGS_1 + 2  # 15
_OFFSET_STATUS_FLAGS = _OFFSET_CHARACTER_SET + 1  # 16
_OFFSET_CAPABILITY_FLAGS_2 = _OFFSET_STATUS_FLAGS + 2  # 18

_EXPECTED_PROTOCOL_VERSION = 10

# MySQL packet header is exactly 4 bytes (3 length + 1 sequence id).
_PACKET_HEADER_LEN = 4

# Sanity ceiling on initial handshake payload length. Realistically
# every server stays well under 1 KB; we use 16 KB as an upper bound
# that rejects garbage / framing-error reads without false negatives.
_MAX_PLAUSIBLE_HANDSHAKE_PAYLOAD = 16_384


def _error(host: str, port: int, message: str) -> dict:
    return {
        "host": host,
        "port": port,
        "ssl_status": "error",
        "error_message": message,
        "server_version": None,
        "client_ssl_supported": None,
        "capability_flags": None,
        "capability_flags_hex": None,
    }


def parse_handshake_v10_capabilities(payload: bytes) -> dict:
    """Parse a Protocol::HandshakeV10 payload (NO 4-byte packet header).

    Returns a dict with stable keys:

    * ``ssl_status``: ``"supported"`` / ``"not_supported"`` / ``"error"``
    * ``error_message``: str | None
    * ``protocol_version``: int | None
    * ``server_version``: str | None
    * ``capability_flags``: int | None  (32-bit, LE-decoded)
    * ``capability_flags_hex``: str | None  (``"0xdeadbeef"`` lowercase)
    * ``client_ssl_supported``: bool | None

    Returns ``ssl_status="error"`` on any parse failure — never raises.
    """
    base = {
        "ssl_status": "error",
        "error_message": None,
        "protocol_version": None,
        "server_version": None,
        "capability_flags": None,
        "capability_flags_hex": None,
        "client_ssl_supported": None,
    }
    if not payload:
        return {**base, "error_message": "empty payload"}

    protocol_version = payload[0]
    if protocol_version != _EXPECTED_PROTOCOL_VERSION:
        return {
            **base,
            "protocol_version": protocol_version,
            "error_message": f"unsupported protocol version {protocol_version} (expected 10)",
        }

    # NUL-terminated server_version.
    nul = payload.find(b"\x00", 1)
    if nul < 0:
        return {**base, "protocol_version": 10, "error_message": "server_version not terminated"}
    server_version = payload[1:nul].decode("utf-8", errors="replace")

    rest = payload[nul + 1:]
    if len(rest) < _MIN_BYTES_AFTER_VERSION:
        return {
            **base,
            "protocol_version": 10,
            "server_version": server_version,
            "error_message": (
                f"truncated payload: {len(rest)} bytes after server_version, "
                f"need >= {_MIN_BYTES_AFTER_VERSION}"
            ),
        }

    cap1 = struct.unpack_from("<H", rest, _OFFSET_CAPABILITY_FLAGS_1)[0]
    cap2 = struct.unpack_from("<H", rest, _OFFSET_CAPABILITY_FLAGS_2)[0]
    capability_flags = cap1 | (cap2 << 16)
    ssl_supported = bool(cap1 & CLIENT_SSL_BIT)

    return {
        "ssl_status": "supported" if ssl_supported else "not_supported",
        "error_message": None,
        "protocol_version": 10,
        "server_version": server_version,
        "capability_flags": capability_flags,
        "capability_flags_hex": f"0x{capability_flags:08x}",
        "client_ssl_supported": ssl_supported,
    }


def _read_n_bytes(sock: socket.socket, n: int, timeout: float) -> bytes:
    """Drain ``n`` bytes from ``sock`` or return what was received."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def probe_mysql_ssl(
    host: str,
    port: int = 3306,
    *,
    timeout: float = 5.0,
) -> dict:
    """Connect, read the initial Handshake v10, classify CLIENT_SSL bit.

    Returns the dict produced by :func:`parse_handshake_v10_capabilities`
    augmented with ``host`` and ``port``. ``error`` covers any
    network or parse failure.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (ConnectionRefusedError, TimeoutError, socket.gaierror, OSError) as exc:
        return _error(host, port, str(exc) or type(exc).__name__)

    try:
        header = _read_n_bytes(sock, _PACKET_HEADER_LEN, timeout)
        if len(header) < _PACKET_HEADER_LEN:
            return _error(host, port, f"short packet header ({len(header)} bytes)")
        # 3-byte LE length + 1-byte sequence id.
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        if length == 0 or length > _MAX_PLAUSIBLE_HANDSHAKE_PAYLOAD:
            return _error(host, port, f"implausible handshake length: {length}")
        payload = _read_n_bytes(sock, length, timeout)
        if len(payload) < length:
            return _error(host, port, f"truncated payload ({len(payload)}/{length})")
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    parsed = parse_handshake_v10_capabilities(payload)
    return {"host": host, "port": port, **parsed}
