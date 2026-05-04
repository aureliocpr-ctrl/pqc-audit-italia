# AgID mapping

This page maps `pqc-audit-italia` findings onto the **Agenzia per
l'Italia Digitale** (AgID) cryptography and security guidelines that
apply to Italian Public Administration.

> **Disclaimer.** AgID guidelines evolve frequently. The mapping
> below targets the technical *spirit* of the requirements, not the
> exact wording of any single circular. Validate with the active
> "Linee Guida" version on the official AgID portal before claiming
> compliance.

## Reference

- **AgID — Linee Guida tecniche** (security, identity, document
  preservation)
- **Misure minime di sicurezza ICT** for PA (legacy reference for the
  baseline)
- **AgID — Linee guida funzioni crittografiche** (2018 + later
  revisions)
- Italian Cybersecurity Strategy 2022-2026 (with PQC roadmap
  references for sensitive data)

## Mapping by control area

### Authentication and identity (SPID / CIE)

| `pqc-audit-italia` finding                        | Control                                | Severity |
| ------------------------------------------------- | -------------------------------------- | -------- |
| RSA / ECDSA on SPID metadata signing              | document signing supports PQC roadmap  | HIGH     |
| SHA-1 in any SAML / OIDC artifact                 | hash strength requirement              | HIGH     |
| Self-signed cert on a SPID / CIE-facing endpoint  | trust anchor management                | HIGH     |

### Document preservation (Conservazione)

| `pqc-audit-italia` finding                  | Control                                | Severity |
| ------------------------------------------- | -------------------------------------- | -------- |
| Documents signed with RSA-2048              | long-term preservation crypto-agility  | MEDIUM   |
| Hash MD5 / SHA-1 in document fingerprints   | integrity over preservation lifetime   | HIGH     |
| HNDL on documents with 30y+ retention       | data confidentiality lifecycle         | HIGH     |

### TLS / transport posture

| `pqc-audit-italia` finding              | Control                                  | Severity |
| --------------------------------------- | ---------------------------------------- | -------- |
| TLS < 1.2                               | minimum protocol baseline                | HIGH     |
| RSA key < 2048 bits                     | minimum key size                         | HIGH     |
| EC curve weaker than P-256              | minimum curve strength                   | HIGH     |
| Cipher suite with RC4 / 3DES / NULL     | deprecated cipher exclusion              | HIGH     |

### Key custody

| `pqc-audit-italia` finding              | Control                                  | Severity |
| --------------------------------------- | ---------------------------------------- | -------- |
| Private key file on web-facing path     | key separation principle                 | CRITICAL |
| HSM-backed but cert pinned (low agility) | key rotation feasibility                 | MEDIUM   |
| Hardcoded keys in PA application code   | secret hygiene + supply chain            | HIGH     |

## PQC roadmap (informational)

AgID and ACN have started publishing reading guidance on the NIST
PQC standards. While **PQC adoption is not mandatory** at the time
of writing, the trajectory is clear:

1. Inventory crypto assets — `pqc-audit-italia` scan output
2. Score HNDL exposure for long-confidentiality data — `risk_summary`
3. Plan migration with hybrid intermediates — `recommendations[]`
4. Track migration as a KPI in the PA digital transition plan

## Operational checklist

- [ ] Run a baseline scan on every PA-managed `.gov.it` endpoint
- [ ] Persist JSON + CBOM in the PA security archive
- [ ] Map findings to the AgID Misure minime control family
- [ ] Open migration tickets when recommendations.priority >= 4
- [ ] Review HNDL trend monthly with the PA RTD / RPD

## Sources

- [Agenzia per l'Italia Digitale — Linee Guida](https://www.agid.gov.it/it/sicurezza)
- [AgID Linee guida funzioni crittografiche](https://www.agid.gov.it/sites/agid/files/2024-04/linee_guida_funzioni_crittografiche.pdf)
- [Misure minime di sicurezza ICT](https://www.agid.gov.it/it/sicurezza/misure-minime-sicurezza-ict)
- [Strategia nazionale di cybersicurezza 2022-2026](https://www.acn.gov.it/strategia)
