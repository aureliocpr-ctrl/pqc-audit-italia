"""Compliance mapping helpers — feed audit findings back to regulators.

Submodules:

* :mod:`pqc_audit.compliance.nis2` — Italian NIS2 transposition
  (D.Lgs. 138/2024) article-level mapping.

The compliance layer is intentionally separate from the policy_engine:
the policy_engine answers "does the audit pass MY internal policy?",
the compliance layer answers "which regulator articles does each
finding cite?". A finding can be policy-clean and still cite NIS2 art.
24(2)(h) — they answer different questions.
"""
