"""Signing primitives: RFC 3161 timestamping + sigstore wrappers.

This subpackage is intentionally pure-protocol — it builds and ships
TimeStampReq / TimeStampResp blobs and signs/verifies report digests.
It does NOT implement an in-house qualified TSA or qualified seal:
those statuses require external certified authorities (ETSI EN 319
421 TSAs, AgID-accredited services).
"""
