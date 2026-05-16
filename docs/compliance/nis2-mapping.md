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
  Cybersicurezza Nazionale), including **Determinazione ACN
  n. 379907/2025** on registration of essential and important
  entities.

## Scope assessment — am I in scope?

NIS2 (D.Lgs. 138/2024 art. 3) distinguishes between **essential**
and **important** entities by sector and size:

- **Essential** (Annex I): energy, transport, banking, financial
  market infrastructure, healthcare, drinking water, waste water,
  digital infrastructure (TLD/DNS/CSP/data center/IXP), public
  administration (central + regional), space, ICT service management
  (managed services + MSSP).
- **Important** (Annex II): postal/courier, waste management,
  chemicals, food, manufacturing of medical / electronic / vehicle /
  machinery products, digital providers (search engines, social
  networks, online marketplaces), research organisations.

Size threshold (general rule, art. 3(2-3) D.Lgs.):

- Medium-sized: ≥ 50 employees **OR** annual turnover/balance
  > 10 M€ → important
- Large-sized: ≥ 250 employees **OR** turnover > 50 M€ **OR**
  balance > 43 M€ → essential

Some sectors are in scope regardless of size (DNS, TLD registries,
trust service providers, electronic communications providers, PA).

`pqc-audit-italia` does not perform legal classification — but the
bundled `pa_critical.yaml` policy is calibrated for **essential**
PA entities and `agid_2026.yaml` for the general PA baseline.

## Article 21 — Cybersecurity risk-management measures

NIS2 art. 21 requires "essential" and "important" entities to take
appropriate technical, operational, and organisational measures to
manage risks to network and information systems. Art. 21(2) lists
ten lever categories (a–j); cryptography is explicitly named at
art. 21(2)(h):

> *"policies and procedures regarding the use of cryptography and,
> where appropriate, encryption."*

### Coverage matrix art. 21(2) a–j

| Lever | Measure                                              | Tool coverage   | Where in the tool                          |
| ----- | ---------------------------------------------------- | --------------- | ------------------------------------------ |
| (a)   | Risk analysis & info-system security policy         | **FULL**        | HNDL + Q-Day scoring; per-asset risk metadata |
| (b)   | Incident handling                                    | PARTIAL         | Findings attachable to art. 23 notifications |
| (c)   | Business continuity / backup / DR                    | out of scope    | (BCM is outside a crypto scanner)          |
| (d)   | **Supply chain security**                            | **FULL**        | CBOM (CycloneDX 1.6) per scan — see below  |
| (e)   | Secure acquisition / development / vuln. handling    | PARTIAL         | SARIF 2.1.0 → GitHub Code Scanning / GitLab SAST |
| (f)   | **Effectiveness assessment of measures**             | **FULL**        | `pqc-audit batch-diff` snapshot delta      |
| (g)   | Cyber hygiene & training                             | PARTIAL         | Italian-language Markdown report as awareness material |
| (h)   | **Cryptography policies**                            | **FULL**        | Core scanner + policy engine + 4 bundled YAML policies |
| (i)   | HR security / access control / asset management      | PARTIAL         | Asset inventory (CBOM); hardcoded-key detection |
| (j)   | Authentication & secure communications               | PARTIAL         | TLS minimum version enforcement, MFA-readiness via crypto-agility score |

### Mapping of typical findings

| `pqc-audit-italia` finding                       | NIS2 art. 21 lever                                       | Severity hint |
| ------------------------------------------------ | -------------------------------------------------------- | ------------- |
| Quantum-vulnerable algorithm in use              | (h) cryptography policy obsolescence                     | HIGH          |
| Deprecated hash (MD5 / SHA-1)                    | (h) cryptography policy + (e) supply chain               | HIGH          |
| Self-signed leaf certificate (public service)    | (a) risk analysis + (g) basic cyber hygiene              | LOW           |
| Undersized RSA / EC key                          | (h) cryptography minimum requirements                    | HIGH          |
| Static / hardcoded key in code                   | (a) risk analysis + (i) HR security / asset management   | HIGH          |
| HNDL exposure on long-lived data (10y+)          | (a) risk analysis (data lifecycle)                       | HIGH          |
| Lack of crypto-agility (cert pinning, hardcoded) | (h) cryptography policy + (j) incident posture           | MEDIUM        |
| **Certificate expired** (CWE-298)                | (g) basic cyber hygiene + (j) secure communications      | HIGH          |
| **Policy threshold exceeded** (HNDL > policy max)| (a) risk analysis (quantified)                           | HIGH          |

## Article 21(2)(d) — Supply-chain security via CBOM

The tool emits a **CycloneDX 1.6 Cryptography Bill of Materials**
(`pqc-audit report -f cbom`) containing one
`cryptographic-asset` per discovered primitive plus a VEX section
listing every finding. This is the artefact that fulfils
art. 21(2)(d) for the cryptographic supply chain:

- Operators ingest the CBOM in **Dependency-Track**, Anchore, or
  the GitHub SBOM tab.
- A signed CBOM from a vendor (CycloneDX `signature` field)
  becomes contractually attachable evidence of cryptographic
  posture — what AgID circular guidance calls *"evidenza
  documentale di posture crittografica del fornitore"*.
- Pair with `batch-diff` to spot regressions across vendor releases.

CBOM IDs are SHA-256-derived (`PQC-<SEV>-<8 hex>`) so cross-snapshot
de-duplication and VEX statements are stable across runs.

## Article 21(2)(f) — Effectiveness assessment via `batch-diff`

Art. 21(2)(f) requires *"policies and procedures to assess the
effectiveness of cybersecurity risk-management measures"*.
Re-running `pqc-audit batch` on the same portfolio every month
and feeding two consecutive snapshots into `pqc-audit batch-diff`
produces exactly the deliverable the regulator expects:

- **Improved**: assets that previously failed the policy and now
  pass — measurable ROI of remediation.
- **Regressed**: assets that previously passed and now fail —
  the early-warning surface that drives art. 23 notifications.
- **Unchanged / Added / Removed**: portfolio drift.

Recommended cadence: monthly for essential entities; quarterly for
important entities.

## Article 23 — Reporting obligations

Cryptographic incidents (key compromise, deprecated-algo abuse,
discovery of a vendor primitive below the contracted policy) may
trigger the 24h early-warning + 72h notification + 1-month final
report cycle. The audit trail emitted by `pqc-audit-italia`
(JSON / SARIF / CBOM) is designed to be attachable to ACN incident
notifications. Minimal payload shape ACN expects (paraphrased from
the ACN online portal flow):

| ACN field                       | Source in `pqc-audit-italia` output           |
| ------------------------------- | --------------------------------------------- |
| `event_timestamp`               | `scan_results[].started_at`                   |
| `affected_system`               | `scan_results[].target`                       |
| `vulnerability.cwe`             | `vulnerabilities[].cwe`                       |
| `vulnerability.description_it`  | `vulnerabilities[].description` (Markdown)    |
| `severity_level`                | `vulnerabilities[].severity` (CRITICAL/HIGH/MEDIUM/LOW) |
| `mitigation_plan`               | `recommendations[]`                           |
| `policy_breach_detail`          | `policy_evaluation.violations[]`              |

Operational guidance: persist the **full JSON** report in your
evidence vault — ACN may request the underlying scan artefact in
the final-report phase (M+1).

## Article 24 D.Lgs. 138/2024 — Misure tecniche di base (Italian recepimento)

Art. 24 D.Lgs. 138/2024 operationalizes art. 21 NIS2 with a
catalogue of *"misure tecniche minime"* that ACN expects every
in-scope entity to deploy. The crypto-relevant items map directly
to bundled tool functionality:

| Art. 24 D.Lgs. measure                  | Tool feature                                |
| --------------------------------------- | ------------------------------------------- |
| Cryptography policy in writing          | `nist_baseline.yaml` / `agid_2026.yaml` / etc. as starting point |
| Asset inventory of crypto primitives    | CBOM (`-f cbom`)                            |
| Quantum-readiness assessment            | HNDL + Q-Day scoring + migration recommendations |
| Continuous monitoring                   | `pqc-audit batch` periodic re-scan          |
| Effectiveness metric                    | `batch-diff` snapshot trend                 |
| Incident notification artefact          | JSON / SARIF output                         |

For PA critical entities (essential, Annex I sectors), the
`pa_critical.yaml` policy carries `data_sensitivity_years: 40`
and `hndl_max_score: 25` — the most defensive defaults shipped.

## Sanctions — economic exposure (D.Lgs. 138/2024 art. 38)

NIS2 transposes art. 32 of the directive into Italian law with
**material** fines. The numbers are part of the value-prop for
running a free `pqc-audit-italia` baseline scan:

| Entity class                          | Maximum administrative fine                                  |
| ------------------------------------- | ------------------------------------------------------------ |
| **Essential** entities (Annex I)      | up to **10 M€** OR **2 %** of total worldwide annual turnover (whichever higher) |
| **Important** entities (Annex II)     | up to **7 M€** OR **1.4 %** of total worldwide annual turnover (whichever higher) |
| Public administration                 | administrative measures + personal liability for the head of the entity (art. 38(7) D.Lgs.) |
| Repeated breach / wilful misconduct   | suspension of business activity (art. 38(8) D.Lgs.)          |

For a mid-sized Italian bank (annual turnover ~3 B€), 2 % is
**60 M€** of regulatory exposure — orders of magnitude above the
cost of a periodic crypto audit.

## Operational checklist

- [ ] Run a baseline scan against every public-facing endpoint
- [ ] Persist the JSON report and the CBOM to your evidence vault
- [ ] Re-scan on every cert rotation
- [ ] Track HNDL `risk_summary.hndl_max` over time as a KPI
- [ ] When `recommendations[].priority >= 4`, open a migration ticket
- [ ] Run `pqc-audit batch-diff` between consecutive monthly
      snapshots and archive the delta report as art. 21(2)(f) evidence
- [ ] When an asset crosses `thresholds.hndl_max_score`, attach the
      JSON to an ACN art. 23 notification within 24h

## Sources

- [Direttiva (UE) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
- [D.Lgs. 138/2024](https://www.gazzettaufficiale.it/eli/id/2024/10/01/24G00155/sg)
- [Agenzia per la Cybersicurezza Nazionale](https://www.acn.gov.it/)
- [AgID — Linee guida sicurezza](https://www.agid.gov.it/)
- [CycloneDX 1.6 spec](https://cyclonedx.org/docs/1.6/json/)
- [NIST IR 8547 — Transition to PQC](https://csrc.nist.gov/pubs/ir/8547/initial-public-draft)
