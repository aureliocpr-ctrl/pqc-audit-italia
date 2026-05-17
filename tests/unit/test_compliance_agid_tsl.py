"""Tests for AgID Trusted List (TSL) parser — Sprint 9d.5.

The AgID Trusted List (https://eidas.agid.gov.it/TL/TSL-IT.xml) is
the AUTHORITATIVE roster of qualified Trust Service Providers in
Italy. Cross-checking a resolved root CA against the TSL — not just
against a hand-curated pattern list — is what makes the pedigree
classification "legal-grade" in the sense Aurelio asked for.

The XML conforms to ETSI TS 119 612 v2.1.1:

* root element: ``{http://uri.etsi.org/02231/v2#}TrustServiceStatusList``
* TSP names at: ``TrustServiceProviderList/TrustServiceProvider/
  TSPInformation/TSPName/Name``
* qualified-CA cert blobs at:
  ``…/TSPService/ServiceInformation/ServiceDigitalIdentity/DigitalId/X509Certificate``
* qualified-CA service type:
  ``http://uri.etsi.org/TrstSvc/Svctype/CA/QC``

This sprint ships the parser. Sprint 9d.6 will wire it into
:mod:`pqc_audit.scanners.tls_trust_store` so the resolver upgrades
``pedigree="qualified_it_tsp"`` to
``pedigree="qualified_it_tsp_verified_via_tsl"`` when the resolved
root's subject DN appears in the live TSL.
"""

from __future__ import annotations

import base64
import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------


def _make_self_signed_pem_and_der(cn: str) -> tuple[bytes, bytes]:
    """Return (PEM, DER) of a one-shot self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        ]
    )
    now = dt.datetime.now(tz=dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        cert.public_bytes(serialization.Encoding.DER),
    )


def _build_minimal_tsl_xml(*, tsp_name: str, qualified_cert_der: bytes) -> bytes:
    """Build a minimal but spec-conformant ETSI TS 119 612 TSL XML."""
    b64 = base64.b64encode(qualified_cert_der).decode("ascii")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"
                       xmlns:ns3="http://www.w3.org/2000/09/xmldsig#">
  <SchemeInformation>
    <TSLVersionIdentifier>5</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
  </SchemeInformation>
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName>
          <Name xml:lang="it">{tsp_name}</Name>
        </TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
            <ServiceName>
              <Name xml:lang="it">{tsp_name} - Qualified CA</Name>
            </ServiceName>
            <ServiceDigitalIdentity>
              <DigitalId>
                <ns3:X509Certificate>{b64}</ns3:X509Certificate>
              </DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>""".encode()


# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------


def test_agid_tsl_url_is_the_official_one() -> None:
    from pqc_audit.compliance.agid_tsl import AGID_TSL_URL

    # Official AgID published endpoint (eIDAS art. 22).
    assert AGID_TSL_URL == "https://eidas.agid.gov.it/TL/TSL-IT.xml"


def test_qualified_ca_service_type_uri_matches_etsi_spec() -> None:
    from pqc_audit.compliance.agid_tsl import SERVICE_TYPE_QUALIFIED_CA

    assert SERVICE_TYPE_QUALIFIED_CA == "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"


# ---------------------------------------------------------------------
# parse_agid_tsl — pure function
# ---------------------------------------------------------------------


def test_parse_returns_tsp_names_and_qualified_certs() -> None:
    from pqc_audit.compliance.agid_tsl import parse_agid_tsl

    _, cert_der = _make_self_signed_pem_and_der("Aruba PEC S.p.A.")
    xml = _build_minimal_tsl_xml(tsp_name="Aruba PEC S.p.A.", qualified_cert_der=cert_der)

    out = parse_agid_tsl(xml)
    assert "tsps" in out
    assert "qualified_certs" in out
    assert any("Aruba PEC" in name for name in out["tsps"])
    assert len(out["qualified_certs"]) == 1
    assert out["qualified_certs"][0] == cert_der


def test_parse_returns_empty_lists_on_xml_without_tsps() -> None:
    from pqc_audit.compliance.agid_tsl import parse_agid_tsl

    xml = (
        b"<?xml version='1.0'?>"
        b"<TrustServiceStatusList xmlns='http://uri.etsi.org/02231/v2#'>"
        b"<SchemeInformation/>"
        b"</TrustServiceStatusList>"
    )
    out = parse_agid_tsl(xml)
    assert out["tsps"] == []
    assert out["qualified_certs"] == []


def test_parse_raises_on_malformed_xml() -> None:
    from pqc_audit.compliance.agid_tsl import AgIDTSLParseError, parse_agid_tsl

    with pytest.raises(AgIDTSLParseError):
        parse_agid_tsl(b"this is not xml")


def test_parse_skips_non_qualified_services() -> None:
    """Only CA/QC services count; non-QC trust services (timestamping,
    OCSP responders, etc.) are ignored for trust-anchor pedigree."""
    from pqc_audit.compliance.agid_tsl import parse_agid_tsl

    _, cert_der = _make_self_signed_pem_and_der("Aruba PEC S.p.A. TSA")
    b64 = base64.b64encode(cert_der).decode("ascii")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"
                       xmlns:ns3="http://www.w3.org/2000/09/xmldsig#">
  <TrustServiceProviderList>
    <TrustServiceProvider>
      <TSPInformation>
        <TSPName><Name xml:lang="it">Aruba PEC S.p.A.</Name></TSPName>
      </TSPInformation>
      <TSPServices>
        <TSPService>
          <ServiceInformation>
            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST</ServiceTypeIdentifier>
            <ServiceDigitalIdentity>
              <DigitalId><ns3:X509Certificate>{b64}</ns3:X509Certificate></DigitalId>
            </ServiceDigitalIdentity>
          </ServiceInformation>
        </TSPService>
      </TSPServices>
    </TrustServiceProvider>
  </TrustServiceProviderList>
</TrustServiceStatusList>""".encode()
    out = parse_agid_tsl(xml)
    # TSP is listed (it exists) but no qualified-CA cert because the
    # only service is QTST not CA/QC.
    assert "Aruba PEC S.p.A." in out["tsps"]
    assert out["qualified_certs"] == []


# ---------------------------------------------------------------------
# is_subject_in_tsl — cross-check
# ---------------------------------------------------------------------


def test_is_subject_in_tsl_matches_canonical_name() -> None:
    from pqc_audit.compliance.agid_tsl import is_subject_in_tsl, parse_agid_tsl

    _, cert_der = _make_self_signed_pem_and_der("ArubaPEC S.p.A. NG CA 3")
    xml = _build_minimal_tsl_xml(
        tsp_name="Aruba PEC S.p.A.", qualified_cert_der=cert_der
    )
    tsl_data = parse_agid_tsl(xml)
    # Build a probe cert whose subject is "the same" canonically.
    cert = x509.load_der_x509_certificate(cert_der)

    assert is_subject_in_tsl(cert.subject.rfc4514_string(), tsl_data) is True


def test_is_subject_in_tsl_returns_false_for_unknown_subject() -> None:
    from pqc_audit.compliance.agid_tsl import is_subject_in_tsl, parse_agid_tsl

    _, cert_der = _make_self_signed_pem_and_der("ArubaPEC S.p.A. NG CA 3")
    xml = _build_minimal_tsl_xml(
        tsp_name="Aruba PEC S.p.A.", qualified_cert_der=cert_der
    )
    tsl_data = parse_agid_tsl(xml)

    assert is_subject_in_tsl("CN=DigiCert Global Root G2", tsl_data) is False


def test_is_subject_in_tsl_is_case_and_attribute_order_insensitive() -> None:
    """Canonical matching: the resolver in 9d.3 already uses _name_to_key.
    AgID TSL cross-check must apply the same canonical equality so a
    subject DN encoded in a different order still matches the TSL entry."""
    from pqc_audit.compliance.agid_tsl import is_subject_in_tsl, parse_agid_tsl

    _, cert_der = _make_self_signed_pem_and_der("InfoCert RSA TLS Issuing CA")
    xml = _build_minimal_tsl_xml(
        tsp_name="InfoCert S.p.A.", qualified_cert_der=cert_der
    )
    tsl_data = parse_agid_tsl(xml)
    # Same Name reordered + case differs (cryptography's RFC 4514
    # parser is strict on whitespace inside attribute values, so we
    # keep the probe well-formed but lexicographically different).
    probe = "O=INFOCERT RSA TLS ISSUING CA,C=IT,CN=INFOCERT RSA TLS ISSUING CA"
    assert is_subject_in_tsl(probe, tsl_data) is True


# ---------------------------------------------------------------------
# fetch_agid_tsl — network probe
# ---------------------------------------------------------------------


def test_fetch_uses_https_url(monkeypatch) -> None:
    from pqc_audit.compliance import agid_tsl

    captured_url: dict[str, str] = {}

    class FakeResponse:
        status_code = 200
        content = b"<?xml version='1.0'?><TrustServiceStatusList xmlns='http://uri.etsi.org/02231/v2#'/>"

        def raise_for_status(self):
            pass

    def fake_get(url, timeout=None, follow_redirects=False):
        captured_url["url"] = url
        return FakeResponse()

    monkeypatch.setattr(agid_tsl.httpx, "get", fake_get)

    xml = agid_tsl.fetch_agid_tsl()
    assert xml.startswith(b"<?xml")
    assert captured_url["url"].startswith("https://")


def test_fetch_raises_agid_tsl_fetch_error_on_http_error(monkeypatch) -> None:
    import httpx as real_httpx

    from pqc_audit.compliance import agid_tsl

    def raise_http(*args, **kwargs):
        raise real_httpx.HTTPError("boom")

    monkeypatch.setattr(agid_tsl.httpx, "get", raise_http)

    with pytest.raises(agid_tsl.AgIDTSLFetchError):
        agid_tsl.fetch_agid_tsl()


# ---------------------------------------------------------------------
# Integration test: real network fetch of AgID's published TSL
# ---------------------------------------------------------------------


@pytest.mark.integration
def test_real_fetch_and_parse_agid_tsl_finds_known_italian_tsps() -> None:
    """Hits the live AgID endpoint and asserts canonical IT TSPs are
    present. Skip-by-default — run with -m integration."""
    from pqc_audit.compliance.agid_tsl import fetch_agid_tsl, parse_agid_tsl

    xml = fetch_agid_tsl(timeout=30.0)
    tsl = parse_agid_tsl(xml)
    # The AgID TSL has historically listed Aruba, InfoCert, Namirial,
    # Poste, Actalis among others. Assert the lookup returns at least
    # one that matches our known pedigree pattern set.
    names_lower = "|".join(name.lower() for name in tsl["tsps"])
    matches = [p for p in ("aruba", "infocert", "namirial", "poste", "actalis")
               if p in names_lower]
    assert matches, f"no known IT TSP found in TSL; names: {tsl['tsps']}"
    assert len(tsl["qualified_certs"]) > 0, "TSL should contain >=1 qualified CA cert"


# Ensure the module is importable as a package member.
def test_module_exposed_from_compliance_package() -> None:
    from pqc_audit.compliance import agid_tsl

    assert hasattr(agid_tsl, "AGID_TSL_URL")
    assert hasattr(agid_tsl, "parse_agid_tsl")
    assert hasattr(agid_tsl, "fetch_agid_tsl")
    assert hasattr(agid_tsl, "is_subject_in_tsl")


# ---------------------------------------------------------------------
# CLI wiring tests — closes the caller_verification gap raised by
# critic-orchestrator on v1 of this sprint.
# ---------------------------------------------------------------------


def test_cli_compliance_agid_tsl_with_input_file_emits_valid_json(tmp_path) -> None:
    """The `pqc-audit compliance agid-tsl --input <path>` subcommand
    must parse the supplied XML and emit valid JSON with the documented
    top-level keys, without hitting the network."""
    import json

    from typer.testing import CliRunner

    from pqc_audit.cli import app

    _, cert_der = _make_self_signed_pem_and_der("Aruba PEC S.p.A.")
    xml = _build_minimal_tsl_xml(tsp_name="Aruba PEC S.p.A.", qualified_cert_der=cert_der)
    tsl_path = tmp_path / "tsl.xml"
    tsl_path.write_bytes(xml)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["compliance", "agid-tsl", "--input", str(tsl_path)],
    )
    assert result.exit_code == 0, f"CLI exited {result.exit_code}: {result.stdout}"
    payload = json.loads(result.stdout)
    assert payload["source"] == str(tsl_path)
    assert payload["tsp_count"] == 1
    assert payload["qualified_ca_count"] == 1
    assert "Aruba PEC S.p.A." in payload["tsps"]


def test_cli_compliance_agid_tsl_check_subject_returns_in_tsl_true(tmp_path) -> None:
    """The --check-subject flag must perform the canonical-name lookup
    end-to-end and surface a boolean verdict in the JSON output."""
    import json

    from cryptography import x509

    from pqc_audit.cli import app

    _, cert_der = _make_self_signed_pem_and_der("InfoCert Qualified CA")
    cert = x509.load_der_x509_certificate(cert_der)
    xml = _build_minimal_tsl_xml(
        tsp_name="InfoCert S.p.A.", qualified_cert_der=cert_der
    )
    tsl_path = tmp_path / "tsl.xml"
    tsl_path.write_bytes(xml)

    from typer.testing import CliRunner

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compliance",
            "agid-tsl",
            "--input",
            str(tsl_path),
            "--check-subject",
            cert.subject.rfc4514_string(),
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["in_tsl"] is True


def test_cli_compliance_agid_tsl_fetch_uses_module_function(monkeypatch) -> None:
    """When --fetch is default and no --input is supplied, the CLI must
    invoke fetch_agid_tsl (production-caller wiring)."""
    import json

    from typer.testing import CliRunner

    from pqc_audit.cli import app
    from pqc_audit.compliance import agid_tsl as agid_tsl_module

    _, cert_der = _make_self_signed_pem_and_der("Namirial Qualified CA")
    xml = _build_minimal_tsl_xml(
        tsp_name="Namirial S.p.A.", qualified_cert_der=cert_der
    )

    def fake_fetch(*args, **kwargs):
        return xml

    monkeypatch.setattr(agid_tsl_module, "fetch_agid_tsl", fake_fetch)

    runner = CliRunner()
    result = runner.invoke(app, ["compliance", "agid-tsl"])
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["source"] == agid_tsl_module.AGID_TSL_URL
    assert "Namirial S.p.A." in payload["tsps"]


# Silence the linter on Path import.
_ = Path
