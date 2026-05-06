"""pqc-audit-italia — crypto-discovery and crypto-agility audit toolkit.

Public API::

    from pqc_audit import Auditor, ScanTarget, AuditReport

The :class:`Auditor` is the high-level orchestrator: configure with a
policy, hand it a list of :class:`ScanTarget`, and receive an
:class:`AuditReport` ready to be serialized via the reporters.

Lower-level types live in :mod:`pqc_audit.core`. Individual scanners
live in :mod:`pqc_audit.scanners`. Reporters live in
:mod:`pqc_audit.reporters`.

The toolkit deliberately does NOT implement post-quantum algorithms
itself. It identifies WHERE cryptography is used, classifies its
exposure to HNDL and Q-Day, and supports compliance mapping.
"""

from __future__ import annotations

__version__ = "0.2.0"

from pqc_audit.auditor import Auditor
from pqc_audit.core.models import AuditReport, ScanResult
from pqc_audit.scanners.base import ScanTarget

__all__ = [
    "Auditor",
    "AuditReport",
    "ScanResult",
    "ScanTarget",
    "__version__",
]
