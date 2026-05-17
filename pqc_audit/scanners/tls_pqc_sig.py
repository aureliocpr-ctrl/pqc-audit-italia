"""ML-DSA signature_algorithms TLS 1.3 probe — Sprint 9f.2.

Companion module to :mod:`pqc_audit.scanners.pqc_hybrid_scanner` (which
probes the ``key_share`` extension for PQC KEM readiness). This one
probes the ``signature_algorithms`` extension for PQC signature
readiness.

**Scope** — ONLY ML-DSA (NIST FIPS 204 → draft-ietf-tls-mldsa-03):

* ML-DSA-44 → 0x0904
* ML-DSA-65 → 0x0905
* ML-DSA-87 → 0x0906

**SLH-DSA is intentionally excluded.** As of 2026-05-17 no TLS 1.3
SignatureScheme codepoint is registered for SLH-DSA (RFC 9909 covers
only X.509, RFC 9814 covers only CMS). Probing SLH-DSA in TLS 1.3
would require inventing codepoints, which the project's anti-fuffa
stance bans.

**Method** — drive ``openssl s_client -sigalgs <MLDSA*>`` against the
target. The empirical signal validated on agid.gov.it 2026-05-17:

* ``Negotiated TLS1.3 group: <NULL>`` → server refused, no MLDSA cert;
* ``Negotiated TLS1.3 group: <something>`` AND ``Certificate chain``
  block present → server returned a cert that survived the MLDSA-only
  signature_algorithms restriction → MLDSA-signed cert.

OpenSSL 3.5.5 (default on the audit box) supports MLDSA-{44,65,87}
natively as sigalg names. Older OpenSSL releases (< 3.5.0) do not —
on those the probe returns ``status=error`` instead of falsely
claiming "not supported".
"""

from __future__ import annotations

import subprocess

# Codepoint mapping per draft-ietf-tls-mldsa-03.
# https://datatracker.ietf.org/doc/html/draft-ietf-tls-mldsa
MLDSA_CODEPOINTS: dict[str, int] = {
    "MLDSA44": 0x0904,
    "MLDSA65": 0x0905,
    "MLDSA87": 0x0906,
}

MLDSA_SIGALGS: tuple[str, ...] = tuple(MLDSA_CODEPOINTS.keys())

# Tokens we look for in OpenSSL output to discriminate the three states.
_NEGOTIATED_PREFIX = "Negotiated TLS1.3 group:"
_NULL_TOKEN = "<NULL>"  # noqa: S105 — not a credential, OpenSSL output marker
_CERTIFICATE_CHAIN_MARKER = "Certificate chain"
_HANDSHAKE_ALERT_MARKERS: tuple[str, ...] = (
    "ssl/tls alert",
    "tlsv1 alert handshake failure",
    "tlsv13 alert",
)
_CONNECT_ERROR_MARKERS: tuple[str, ...] = (
    "getaddrinfo",
    "connect:errno",
    "no route to host",
    "connection refused",
)


def parse_negotiated_signature_status(*, stdout: str, stderr: str) -> str:  # noqa: PLR0911
    """Classify an openssl s_client run into one of three states.

    Returns one of:

    * ``"supported"`` — the handshake produced a Certificate chain
      under the MLDSA-only sigalgs restriction → server has a
      cert signed with an algorithm in the requested list (and
      that algorithm is MLDSA).
    * ``"not_supported"`` — handshake either negotiated NULL group
      (server refused at sigalg step) or returned a handshake_failure
      alert; the server does not have a MLDSA-signed cert.
    * ``"error"`` — DNS failure, connection refused, OpenSSL crash,
      or empty input. Caller must surface separately from
      not_supported — we cannot infer signature support from a
      network-layer error.
    """
    combined = (stdout or "") + "\n" + (stderr or "")
    if not combined.strip():
        return "error"
    lower = combined.lower()

    for marker in _CONNECT_ERROR_MARKERS:
        if marker in lower:
            return "error"

    for marker in _HANDSHAKE_ALERT_MARKERS:
        if marker in lower:
            return "not_supported"

    # Look for Negotiated group line.
    for line in combined.splitlines():
        if _NEGOTIATED_PREFIX in line:
            after = line.split(_NEGOTIATED_PREFIX, 1)[1].strip()
            if after == _NULL_TOKEN:
                return "not_supported"
            # Non-NULL group AND a cert chain block → handshake real.
            if _CERTIFICATE_CHAIN_MARKER in combined:
                return "supported"
            # Non-NULL group but no chain — still treat as not supported
            # because TLS 1.3 cert delivery requires the chain block.
            return "not_supported"
    # No Negotiated group line at all → handshake never reached TLS 1.3.
    return "error"


def probe_mldsa_sigalg(host: str, port: int, sigalg: str) -> dict:
    """Probe a single MLDSA sigalg against ``host:port``.

    Returns a 5-key dict ``{sigalg, codepoint, status, host, port}``.
    Schema is stable — callers (CLI, reporter) depend on it.
    """
    cmd = [
        "openssl",
        "s_client",
        "-sigalgs",
        sigalg,
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-tls1_3",
    ]
    base = {
        "sigalg": sigalg,
        "codepoint": MLDSA_CODEPOINTS.get(sigalg, 0),
        "host": host,
        "port": port,
    }
    try:
        cp = subprocess.run(  # noqa: S603 — args are constants + validated host/port
            cmd,
            input=b"",
            capture_output=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {**base, "status": "error"}
    except FileNotFoundError:
        return {**base, "status": "error"}
    except OSError:
        return {**base, "status": "error"}

    raw_out = cp.stdout
    raw_err = cp.stderr
    stdout_text = (
        raw_out.decode("utf-8", errors="replace")
        if isinstance(raw_out, (bytes, bytearray))
        else (raw_out or "")
    )
    stderr_text = (
        raw_err.decode("utf-8", errors="replace")
        if isinstance(raw_err, (bytes, bytearray))
        else (raw_err or "")
    )
    status = parse_negotiated_signature_status(stdout=stdout_text, stderr=stderr_text)
    return {**base, "status": status}


def probe_all_mldsa_sigalgs(host: str, port: int) -> dict[str, dict]:
    """Probe all three MLDSA codepoints sequentially.

    Returns ``{sigalg_name: probe_result_dict}`` for each entry in
    :data:`MLDSA_SIGALGS`. Sequential rather than parallel to keep
    the subprocess load predictable and avoid burdening the target.
    """
    out: dict[str, dict] = {}
    for sigalg in MLDSA_SIGALGS:
        out[sigalg] = probe_mldsa_sigalg(host, port, sigalg)
    return out
