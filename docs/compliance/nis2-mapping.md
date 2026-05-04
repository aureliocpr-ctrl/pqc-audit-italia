# NIS2 mapping

This page maps `pqc-audit-italia` findings onto the relevant NIS2
articles as transposed into Italian law by **D.Lgs. 138/2024** and
operationalized by AgID and ACN guidance.

> **Disclaimer.** This mapping is a *technical aid*. It does not
> certify compliance. Always validate findings with your DPO / CISO
> and consult the original normative sources.

## Reference

- Regulation: **Direttiva (UE) 2022/2555** ("NIS2")
- Italian transposition: **D.Lgs. 4 settembre 2024, n. 138**
- Implementing acts: **Determinazioni ACN** (Agenzia per la
  Cybersicurezza Nazionale)

## Article 21 — Cybersecurity risk-management measures

NIS2 art. 21 requires "essential" and "important" entities to take
appropriate technical, operational, and organisational measures to
manage risks to network and information systems. Cryptography is
explicitly named at art. 21(2)(h):

> *"policies and procedures regarding the use of cryptography and,
> where appropriate, encryption."*

### Mapping

| `pqc-audit-italia` finding                       | NIS2 art. 21 lever                             | Severity hint |
| ------------------------------------------------ | ---------------------------------------------- | ------------- |
| Quantum-vulnerable algorithm in use              | (h) cryptography policy obsolescence           | HIGH          |
| Deprecated hash (MD5 / SHA-1)                    | (h) cryptography policy + (e) supply chain     | HIGH          |
| Self-signed leaf certificate (public service)    | (a) risk analysis + (g) basic cyber hygiene    | LOW           |
| Undersized RSA / EC key                          | (h) cryptography minimum requirements          | HIGH          |
| Static / hardcoded key in code                   | (a) risk analysis + (i) HR security            | HIGH          |
| HNDL exposure on long-lived data (10y+)          | (a) risk analysis (data lifecycle)             | HIGH          |
| Lack of crypto-agility (cert pinning, hardcoded) | (h) cryptography policy + (j) incident posture | MEDIUM        |

## Article 23 — Reporting obligations

Cryptographic incidents (key compromise, deprecated-algo abuse) may
trigger the 24h early-warning + 72h notification window. The audit
trail emitted by `pqc-audit-italia` (JSON / SARIF / CBOM) is
designed to be attachable to ACN incident notifications.

## Operational checklist

- [ ] Run a baseline scan against every public-facing endpoint
- [ ] Persist the JSON report and the CBOM to your evidence vault
- [ ] Re-scan on every cert rotation
- [ ] Track HNDL `risk_summary.hndl_max` over time as a KPI
- [ ] When `recommendations[].priority >= 4`, open a migration ticket

## Sources

- [Direttiva (UE) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
- [D.Lgs. 138/2024](https://www.gazzettaufficiale.it/eli/id/2024/10/01/24G00155/sg)
- [Agenzia per la Cybersicurezza Nazionale](https://www.acn.gov.it/)
- [AgID — Linee guida sicurezza](https://www.agid.gov.it/)
