# Algorithm reference

This page lists every algorithm tracked by `pqc_audit.core.algorithms`
and the classification verdict the toolkit emits.

The classification is a static lookup. It does not depend on key size
alone (Shor breaks RSA at *every* practically usable size) or on cipher
mode. Where key size or mode matters for safety, the assessment lives
in `assess_certificate` (TLS scanner) and `risk.py`.

## Quantum-vulnerable

Broken by Shor's algorithm on a sufficiently large CRQC. No classical
key size saves you. Migrate to NIST PQC.

| Algorithm | Use                                | NIST replacement   |
| --------- | ---------------------------------- | ------------------ |
| RSA       | encryption + signature             | ML-KEM / ML-DSA    |
| DSA       | signature                          | ML-DSA             |
| ECDSA     | signature                          | ML-DSA             |
| EdDSA     | signature                          | ML-DSA             |
| ECDH      | key agreement                      | ML-KEM             |
| DH        | key agreement                      | ML-KEM             |

## Quantum-weakened

Grover's algorithm halves effective security. Mitigation: double the
key size where applicable. Already-deprecated primitives (MD5, SHA-1,
3DES, RC4) are flagged as **deprecated** independently of PQC.

| Algorithm | Effective post-quantum security | Recommended       | Deprecated |
| --------- | ------------------------------- | ----------------- | ---------- |
| AES-128   | 64 bits                         | AES-256           | no         |
| AES-192   | 96 bits                         | AES-256           | no         |
| AES-256   | 128 bits                        | AES-256           | no         |
| ChaCha20  | 128 bits                        | ChaCha20          | no         |
| SHA-256   | 128 bits                        | SHA-384 / SHA-512 | no         |
| SHA-384   | 192 bits                        | SHA-384           | no         |
| SHA-512   | 256 bits                        | SHA-512           | no         |
| SHA-1     | 0 bits (broken classically)     | SHA-256+          | YES        |
| MD5       | 0 bits                          | SHA-256+          | YES        |
| 3DES      | 56 bits                         | AES-256           | YES        |
| RC4       | 0 bits                          | AES-256-GCM       | YES        |

## Quantum-resistant

NIST PQC standards (FIPS 203 / 204 / 205), the 2025 backup KEM (HQC),
and the stateful hash-based schemes from NIST SP 800-208 used for
firmware signing.

### FIPS 203 — ML-KEM (key encapsulation, ex CRYSTALS-Kyber)

| Variant      | NIST category | Use              |
| ------------ | ------------- | ---------------- |
| ML-KEM-512   | 1             | key encapsulation |
| ML-KEM-768   | 3             | key encapsulation |
| ML-KEM-1024  | 5             | key encapsulation |

### FIPS 204 — ML-DSA (signature, ex CRYSTALS-Dilithium)

| Variant   | NIST category | Use       |
| --------- | ------------- | --------- |
| ML-DSA-44 | 2             | signature |
| ML-DSA-65 | 3             | signature |
| ML-DSA-87 | 5             | signature |

### FIPS 205 — SLH-DSA (hash-based signature, ex SPHINCS+)

| Variant              | NIST category | Use       |
| -------------------- | ------------- | --------- |
| SLH-DSA-SHA2-128s/f  | 1             | signature |
| SLH-DSA-SHA2-192s/f  | 3             | signature |
| SLH-DSA-SHA2-256s/f  | 5             | signature |
| SLH-DSA-SHAKE-128s/f | 1             | signature |
| SLH-DSA-SHAKE-192s/f | 3             | signature |
| SLH-DSA-SHAKE-256s/f | 5             | signature |

`s` = small signature (slow), `f` = fast (larger signature).

### Backup KEM (selected 2025-03-11)

| Variant | NIST category | Use              |
| ------- | ------------- | ---------------- |
| HQC-128 | 1             | key encapsulation |
| HQC-192 | 3             | key encapsulation |
| HQC-256 | 5             | key encapsulation |

### Stateful hash-based (NIST SP 800-208)

For firmware / boot signing where signature counts are bounded.

| Variant | NIST category | Use                 |
| ------- | ------------- | ------------------- |
| LMS     | 5             | stateful signature  |
| XMSS    | 5             | stateful signature  |

## Hybrid schemes (transition phase)

`pqc-audit-italia` recommends one of these as `hybrid_intermediate`
when emitting a `MigrationRecommendation`. Combining a classical
algorithm with a PQC algorithm hedges against vulnerabilities in
either branch during the migration window.

| Combination            | RFC          | Phase      | Use            |
| ---------------------- | ------------ | ---------- | -------------- |
| X25519 + ML-KEM-768    | RFC 9794     | transition | key agreement  |
| X25519 + ML-KEM-1024   | RFC 9794     | transition | key agreement  |
| P-256 + ML-KEM-768     | RFC 9794     | transition | key agreement  |
| ECDSA-P256 + ML-DSA-65 | draft        | transition | signature      |
| RSA-3072 + ML-DSA-65   | draft        | transition | signature      |

## Sources

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST SP 800-208 (Stateful HBS)](https://csrc.nist.gov/pubs/sp/800/208/final)
- [NIST SP 800-227 (Hybrid)](https://csrc.nist.gov/pubs/sp/800/227)
- [RFC 9794 (Hybrid PQC terminology)](https://datatracker.ietf.org/doc/rfc9794/)
- [ETSI TS 103 744 (Quantum-safe hybrid)](https://www.etsi.org/standards)
