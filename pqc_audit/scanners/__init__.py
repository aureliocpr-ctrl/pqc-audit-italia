"""Crypto-discovery scanners (TLS, certs, SSH, JWT, DNSSEC, SAML, mTLS, IaC, JWKS)."""

from __future__ import annotations

from pqc_audit.scanners.base import BaseScanner, ScanTarget, target_to_category
from pqc_audit.scanners.cert_scanner import CertificateScanner
from pqc_audit.scanners.dnssec_scanner import DNSSECScanner
from pqc_audit.scanners.iac_scanner import IaCScanner
from pqc_audit.scanners.jwks_scanner import JWKSScanner
from pqc_audit.scanners.jwt_scanner import JWTScanner
from pqc_audit.scanners.mtls_scanner import MTLSScanner
from pqc_audit.scanners.saml_scanner import SAMLScanner
from pqc_audit.scanners.ssh_scanner import SSHScanner
from pqc_audit.scanners.tls_scanner import TLSScanner

__all__ = [
    "BaseScanner",
    "CertificateScanner",
    "DNSSECScanner",
    "IaCScanner",
    "JWKSScanner",
    "JWTScanner",
    "MTLSScanner",
    "SAMLScanner",
    "SSHScanner",
    "ScanTarget",
    "TLSScanner",
    "target_to_category",
]
