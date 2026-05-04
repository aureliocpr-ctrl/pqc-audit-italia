# DORA mapping

This page maps `pqc-audit-italia` findings onto the **Digital
Operational Resilience Act** (Regulation (EU) 2022/2554) and its
implementing technical standards.

> **Disclaimer.** This mapping is a technical aid. It does not
> certify compliance with DORA. Validate with your CISO / compliance
> officer and refer to the original Regulation, the related RTS, and
> the EBA / ESMA / EIOPA guidelines.

## Reference

- Regulation: **(UE) 2022/2554** — DORA
- Application date: **17 January 2025**
- Scope: financial entities (banks, insurers, payment institutions,
  CSPs supporting them, etc.) under EU supervision

## Article 9 — Protection and prevention

Art. 9 requires ICT security tools, policies, and procedures
appropriate to the risk profile. Cryptography is part of that
baseline.

### Mapping

| `pqc-audit-italia` finding              | DORA article             | Severity hint |
| --------------------------------------- | ------------------------ | ------------- |
| Quantum-vulnerable algorithm            | art. 9 — confidentiality | HIGH          |
| Deprecated hash / cipher                | art. 9 — integrity       | HIGH          |
| Undersized RSA / EC key                 | art. 9 — confidentiality | HIGH          |
| HNDL on long-lived financial records    | art. 9 + art. 10         | HIGH          |
| Hardcoded keys in code                  | art. 9 + art. 28 (3PR)   | HIGH          |
| Lack of crypto-agility                  | art. 6(8) digital o.r.   | MEDIUM        |
| Self-signed cert on customer-facing TLS | art. 9 — authenticity    | LOW           |

## Article 10 — Detection

DORA art. 10 requires mechanisms to promptly detect anomalous
activities. A periodic crypto inventory delta — comparing the
current scan against the baseline — provides early signal of
unsanctioned algorithm changes (e.g. a shadow service spinning up
with TLS 1.0).

## Article 28 — Third-party risk

When auditing a CSP or a fintech vendor, the JSON / CBOM exports of
`pqc-audit-italia` are designed to slot into **TPRM** evidence
packs. The CBOM in CycloneDX 1.6 is the emerging contractual
artefact regulators expect to see.

## Article 24-26 — Threat-led penetration testing (TLPT)

The toolkit is **not** a TLPT framework. It produces *defensive*
evidence — what the financial entity exposes in steady state. TLPT
campaigns may consume the inventory as their starting point.

## Operational checklist

- [ ] Baseline crypto inventory across every customer-facing service
- [ ] Re-scan monthly, persist the deltas as evidence
- [ ] Map each `MigrationRecommendation` to a Resilience Plan ticket
- [ ] Include `risk_summary` in board-level ICT risk reports
- [ ] When auditing a 3rd party, request a CBOM signed by them

## Sources

- [Regolamento (UE) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [Banca d'Italia — circolari operative](https://www.bancaditalia.it/)
- [European Banking Authority — DORA RTS / GL](https://www.eba.europa.eu/)
