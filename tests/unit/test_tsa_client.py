"""Tests for the RFC 3161 TSA client (Sprint 8 step D).

The client builds a TimeStampReq (ASN.1 DER) over a SHA-256 digest of
the report, ships it to a TSA endpoint, and parses the TimeStampResp.
Tests run offline: the HTTP layer is stubbed via monkeypatch so the
suite never touches the public TSAs (FreeTSA, DigiCert, etc.).
"""

from __future__ import annotations

import hashlib

import pytest


def test_build_timestamp_request_produces_asn1_der_blob() -> None:
    """The request must be ASN.1 DER (length-prefixed, starts with 0x30)."""
    from pqc_audit.signing.tsa_client import build_timestamp_request

    digest = hashlib.sha256(b"some-canonical-report-bytes").digest()
    blob = build_timestamp_request(digest, hash_algo="sha256")
    assert isinstance(blob, bytes)
    assert len(blob) > 32  # not empty, not a stub
    # First byte of a DER SEQUENCE.
    assert blob[0] == 0x30


def test_build_timestamp_request_includes_the_digest_verbatim() -> None:
    """The 32-byte SHA-256 digest must appear inside the DER blob."""
    from pqc_audit.signing.tsa_client import build_timestamp_request

    digest = hashlib.sha256(b"pin-this-payload").digest()
    blob = build_timestamp_request(digest, hash_algo="sha256")
    assert digest in blob


def test_build_timestamp_request_sets_cert_req_flag_by_default() -> None:
    """``certReq`` defaults to True so the TSA returns its signing cert
    (otherwise the verifier has to fetch it out-of-band)."""
    from pqc_audit.signing.tsa_client import build_timestamp_request

    digest = hashlib.sha256(b"x").digest()
    with_cert = build_timestamp_request(digest, hash_algo="sha256", cert_req=True)
    without_cert = build_timestamp_request(digest, hash_algo="sha256", cert_req=False)
    # Setting the flag changes at least one byte in the DER encoding.
    assert with_cert != without_cert


def test_build_timestamp_request_rejects_invalid_digest_length() -> None:
    """SHA-256 digests must be exactly 32 bytes."""
    from pqc_audit.signing.tsa_client import build_timestamp_request

    with pytest.raises(ValueError, match="32 bytes"):
        build_timestamp_request(b"too-short", hash_algo="sha256")
    with pytest.raises(ValueError, match="32 bytes"):
        build_timestamp_request(b"\x00" * 33, hash_algo="sha256")


def test_build_timestamp_request_rejects_unknown_hash_algo() -> None:
    from pqc_audit.signing.tsa_client import build_timestamp_request

    digest = hashlib.sha256(b"x").digest()
    with pytest.raises(ValueError, match="unsupported"):
        build_timestamp_request(digest, hash_algo="md5")


def test_request_timestamp_token_sends_correct_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The HTTP POST must use ``application/timestamp-query`` per RFC 3161."""
    from pqc_audit.signing import tsa_client

    captured: dict[str, object] = {}

    def _fake_urlopen(req, timeout):  # noqa: ARG001
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data

        class _FakeResp:
            status = 200

            def getcode(self) -> int:
                return 200

            def read(self, n: int = -1) -> bytes:  # noqa: ARG002
                # Minimal stub — `request_timestamp_token` only returns
                # the body; the suite doesn't try to parse it.
                return b"\x30\x82\x00\x00"  # ASN.1 SEQUENCE placeholder

            def __enter__(self) -> _FakeResp:
                return self

            def __exit__(self, *a: object) -> None:  # noqa: D401
                return None

        return _FakeResp()

    monkeypatch.setattr(tsa_client, "_urlopen", _fake_urlopen)
    monkeypatch.setattr(tsa_client, "_is_public_host", lambda _h: True)
    digest = hashlib.sha256(b"payload").digest()
    tsa_client.request_timestamp_token("https://freetsa.example/tsr", digest, hash_algo="sha256")
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers.get("content-type", "").lower() == "application/timestamp-query"
    assert captured["url"] == "https://freetsa.example/tsr"


def test_request_timestamp_token_rejects_non_https_url() -> None:
    """The TSA URL MUST be HTTPS — same SSRF posture as the JWKS scanner."""
    from pqc_audit.signing.tsa_client import request_timestamp_token

    digest = hashlib.sha256(b"x").digest()
    with pytest.raises(ValueError, match="must use https"):
        request_timestamp_token("http://tsa.example/tsr", digest)


def test_request_timestamp_token_rejects_ssrf_private_host() -> None:
    """Private / loopback / link-local TSA URLs must be refused (CWE-918)."""
    from pqc_audit.signing.tsa_client import request_timestamp_token

    digest = hashlib.sha256(b"x").digest()
    with pytest.raises(ValueError, match="SSRF"):
        request_timestamp_token("https://127.0.0.1/tsr", digest)
    with pytest.raises(ValueError, match="SSRF"):
        request_timestamp_token("https://169.254.169.254/tsr", digest)


def test_request_timestamp_token_raises_on_non_2xx(monkeypatch: pytest.MonkeyPatch) -> None:
    from pqc_audit.signing import tsa_client

    class _FakeResp:
        status = 503

        def getcode(self) -> int:
            return 503

        def read(self, n: int = -1) -> bytes:  # noqa: ARG002
            return b"upstream down"

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *a: object) -> None:  # noqa: D401
            return None

    def _fake_urlopen(req, timeout):  # noqa: ARG001
        return _FakeResp()

    monkeypatch.setattr(tsa_client, "_urlopen", _fake_urlopen)
    monkeypatch.setattr(tsa_client, "_is_public_host", lambda _h: True)
    digest = hashlib.sha256(b"x").digest()
    with pytest.raises(ValueError, match="HTTP 503"):
        tsa_client.request_timestamp_token(
            "https://freetsa.example/tsr", digest, hash_algo="sha256"
        )


def test_request_timestamp_token_caps_response_size(monkeypatch: pytest.MonkeyPatch) -> None:
    from pqc_audit.signing import tsa_client

    class _FakeResp:
        status = 200

        def getcode(self) -> int:
            return 200

        def read(self, n: int = -1) -> bytes:
            size = tsa_client._MAX_TSR_BYTES + 1 if n < 0 else n
            return b"\x00" * size

        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *a: object) -> None:  # noqa: D401
            return None

    monkeypatch.setattr(tsa_client, "_urlopen", lambda req, timeout: _FakeResp())  # noqa: ARG005
    monkeypatch.setattr(tsa_client, "_is_public_host", lambda _h: True)
    digest = hashlib.sha256(b"x").digest()
    with pytest.raises(ValueError, match="exceeds"):
        tsa_client.request_timestamp_token(
            "https://freetsa.example/tsr", digest, hash_algo="sha256"
        )
