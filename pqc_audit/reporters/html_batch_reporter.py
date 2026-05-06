"""Self-contained HTML reporter for ``pqc-audit batch``.

Produces a single ``.html`` document with inline CSS and JavaScript —
no remote fonts, no CDN, no external logo. The page is e-mail-safe
(open it in any modern browser, no internet round trip needed) and
is meant to land in the inbox of a CISO / CFO who wants something
more digestible than the raw Markdown table or the JSON dump.

Tone & shape: the report mirrors :mod:`pqc_audit.reporters.markdown_reporter`'s
executive summary — same numbers, same Italian section headers — but
adds two interactive affordances that only make sense in a browser:

* a free-text filter that hides rows whose host doesn't match;
* a "Scarica CSV" button that produces the same data as a one-shot
  download (no spreadsheet round-trip, no copy-paste).

The function ``render(rows, *, policy, sensitivity, enforce) -> str``
is intentionally pure — no I/O, no globals, no template engine.
That keeps it trivially unit-testable (see
``tests/unit/test_html_batch_reporter.py``) and makes it safe to
call from inside an asyncio context (``pqc_audit.batch.run_batch``).
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from typing import Any

from pqc_audit import __version__

# Above this HNDL score, the row is treated as "critical" and
# carries the ``hndl-high`` CSS class so the auditor's eye finds
# the bad rows without reading the column.
_HNDL_HIGH_THRESHOLD = 80

# Inline CSS — kept short on purpose. The page must render legibly
# even without JS (filter just won't work).
_CSS = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  margin: 0; padding: 24px; color: #1f2937; background: #f8fafc;
}
header { margin-bottom: 24px; }
h1 { margin: 0 0 8px 0; font-size: 22px; }
.meta {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 8px 24px; padding: 12px; background: white;
  border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px;
}
.meta b { color: #374151; }
.controls {
  display: flex; gap: 12px; align-items: center; margin: 16px 0;
  flex-wrap: wrap;
}
.controls input {
  padding: 6px 10px; border: 1px solid #d1d5db; border-radius: 4px;
  font-size: 14px; min-width: 220px;
}
.controls button {
  padding: 6px 14px; border: 1px solid #2563eb; background: #2563eb;
  color: white; border-radius: 4px; cursor: pointer; font-size: 14px;
}
.controls button:hover { background: #1d4ed8; }
table { width: 100%; border-collapse: collapse; background: white; }
th, td { padding: 8px 10px; border-bottom: 1px solid #e5e7eb;
         text-align: left; font-size: 13px; }
th { background: #f3f4f6; font-weight: 600; }
tr.row-error { color: #6b7280; background: #fef9c3; }
tr.row-error td { font-style: italic; }
tr.hndl-high { background: #fef2f2; }
tr.hndl-high td:first-child { border-left: 3px solid #dc2626; }
.verdict-fail { color: #b91c1c; font-weight: 600; }
.verdict-partial { color: #d97706; font-weight: 600; }
.verdict-pass { color: #15803d; font-weight: 600; }
.note {
  margin-top: 16px; padding: 12px; background: #fef3c7;
  border-left: 4px solid #f59e0b; border-radius: 4px; font-size: 13px;
}
footer {
  margin-top: 24px; padding-top: 12px; border-top: 1px solid #e5e7eb;
  font-size: 12px; color: #6b7280;
}
.summary-numbers {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin: 16px 0;
}
.summary-numbers .card {
  background: white; padding: 12px; border: 1px solid #e5e7eb;
  border-radius: 6px;
}
.summary-numbers .card .v {
  font-size: 24px; font-weight: 700; color: #1f2937;
}
.summary-numbers .card .l {
  font-size: 12px; color: #6b7280; text-transform: uppercase;
  letter-spacing: 0.05em;
}
"""

# Inline JS — host filter + CSV download. Kept dependency-free.
_JS = """
(function () {
  var input = document.getElementById('host-filter');
  var rows = document.querySelectorAll('tbody tr');
  if (input) {
    input.addEventListener('input', function (e) {
      var q = (e.target.value || '').toLowerCase();
      rows.forEach(function (r) {
        var host = (r.getAttribute('data-host') || '').toLowerCase();
        r.style.display = (q === '' || host.indexOf(q) !== -1) ? '' : 'none';
      });
    });
  }
  var btn = document.getElementById('csv-dl');
  if (btn) {
    btn.addEventListener('click', function () {
      var lines = [];
      var head = document.querySelectorAll('thead th');
      var headRow = [];
      head.forEach(function (th) { headRow.push(th.textContent.trim()); });
      lines.push(headRow.join(','));
      rows.forEach(function (r) {
        var cells = r.querySelectorAll('td');
        var rowOut = [];
        cells.forEach(function (td) {
          var t = td.textContent.replace(/\\s+/g, ' ').trim();
          if (t.indexOf(',') !== -1 || t.indexOf('"') !== -1) {
            t = '"' + t.replace(/"/g, '""') + '"';
          }
          rowOut.push(t);
        });
        lines.push(rowOut.join(','));
      });
      var blob = new Blob([lines.join('\\n')], {type: 'text/csv'});
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = 'pqc_audit_batch.csv';
      document.body.appendChild(a); a.click();
      document.body.removeChild(a); URL.revokeObjectURL(url);
    });
  }
})();
"""


def _verdict_class(v: str) -> str:
    v = (v or "").upper()
    if v.startswith("FAIL"):
        return "verdict-fail"
    if v.startswith("PARTIAL"):
        return "verdict-partial"
    if v.startswith("PASS"):
        return "verdict-pass"
    return ""


def _has_pqc(algorithm: str) -> bool:
    return any(p in (algorithm or "") for p in ("ML-DSA", "ML-KEM", "SLH-DSA", "sntrup", "FALCON"))


def render(
    rows: list[dict[str, Any]],
    *,
    policy: str,
    sensitivity: int,
    enforce: bool,
) -> str:
    """Render a self-contained HTML batch report.

    Parameters
    ----------
    rows:
        Output of :func:`pqc_audit.batch.summarize_one`, one entry
        per scanned host.
    policy:
        Name of the policy enforced (e.g. ``agid_2026``).
    sensitivity:
        Data-sensitivity-years horizon used for HNDL scoring.
    enforce:
        Whether the auditor actually evaluated the policy.

    Returns
    -------
    str
        A complete HTML document, ready to be written to disk and
        e-mailed as one attachment.
    """
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    n = len(rows)
    ok = sum(1 for r in rows if r.get("status") == "ok")
    err = n - ok
    high = sum(
        1 for r in rows if r.get("status") == "ok" and (r.get("hndl") or 0) >= _HNDL_HIGH_THRESHOLD
    )
    pqc_present = sum(
        1 for r in rows if r.get("status") == "ok" and _has_pqc(r.get("algorithm") or "")
    )
    fails = sum(
        1
        for r in rows
        if r.get("status") == "ok" and (r.get("policy_verdict") or "").upper().startswith("FAIL")
    )

    body_rows: list[str] = []
    for r in rows:
        host = escape(str(r.get("host", "")))
        if r.get("status") == "ok":
            algo = escape(str(r.get("algorithm", "?")))
            vulns = r.get("vulns", 0)
            hndl = r.get("hndl", "?")
            qday = r.get("qday", "?")
            verdict = str(r.get("policy_verdict") or "n/v")
            violations = r.get("violations") or 0
            verdict_text = verdict
            if violations:
                verdict_text = f"{verdict} ({violations} viol.)"
            top_reco = escape(str(r.get("top_reco", "—")))
            v_class = _verdict_class(verdict)
            row_classes = []
            if isinstance(hndl, (int, float)) and hndl >= _HNDL_HIGH_THRESHOLD:
                row_classes.append("hndl-high")
            cls_attr = f' class="{" ".join(row_classes)}"' if row_classes else ""
            body_rows.append(
                f'<tr{cls_attr} data-host="{host}">'
                f"<td>{host}</td>"
                f"<td>{algo}</td>"
                f"<td>{vulns}</td>"
                f"<td>{hndl}</td>"
                f"<td>{qday}</td>"
                f'<td class="{v_class}">{escape(verdict_text)}</td>'
                f"<td>{top_reco}</td>"
                "</tr>"
            )
        else:
            err_msg = escape(str(r.get("error", "?")))
            body_rows.append(
                f'<tr class="row-error" data-host="{host}">'
                f"<td>{host}</td>"
                f'<td colspan="6">errore: {err_msg}</td>'
                "</tr>"
            )

    note_html = ""
    if pqc_present == 0 and ok > 0:
        note_html = (
            '<div class="note"><b>Nota:</b> nessuno dei target valutati ha '
            "negoziato un algoritmo NIST PQC (ML-KEM / ML-DSA / SLH-DSA) né "
            "un hybrid sntrup. La raccomandazione di migrazione è "
            "<b>uniformemente P5</b> — coerente con il quadro globale "
            "tipicamente rilevato in PA italiana.</div>"
        )

    enforce_label = "sì" if enforce else "no"
    safe_policy = escape(policy)

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="it"><head>',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Batch PQC audit — sintesi esecutiva</title>",
        f"<style>{_CSS}</style>",
        "</head><body>",
        "<header>",
        "<h1>Batch PQC audit — sintesi esecutiva</h1>",
        '<div class="meta">',
        f"<div><b>Generato:</b> {escape(now)}</div>",
        f"<div><b>Policy applicata:</b> <code>{safe_policy}</code></div>",
        f"<div><b>Sensitivity (anni):</b> {int(sensitivity)}</div>",
        f"<div><b>Enforce policy:</b> {enforce_label}</div>",
        f"<div><b>Reporter:</b> pqc-audit-italia v{escape(__version__)}</div>",
        "</div>",
        "</header>",
        '<div class="summary-numbers">',
        f'<div class="card"><div class="v">{n}</div><div class="l">Target totali</div></div>',
        f'<div class="card"><div class="v">{ok}</div><div class="l">Scansionati ok</div></div>',
        f'<div class="card"><div class="v">{err}</div><div class="l">Errori</div></div>',
        f'<div class="card"><div class="v">{high}</div><div class="l">HNDL ≥ 80</div></div>',
        f'<div class="card"><div class="v">{pqc_present}</div>'
        '<div class="l">PQC negoziato</div></div>',
        f'<div class="card"><div class="v">{fails}</div><div class="l">FAIL policy</div></div>',
        "</div>",
        '<div class="controls">',
        '<input id="host-filter" type="text" placeholder="Filtra per host (filter)…">',
        '<button id="csv-dl" type="button">Scarica CSV</button>',
        "</div>",
        "<table>",
        "<thead><tr>",
        "<th>Host</th><th>Algoritmo</th><th>Vulns</th>",
        "<th>HNDL</th><th>Q-Day</th><th>Verdict policy</th><th>Top reco</th>",
        "</tr></thead>",
        "<tbody>",
        *body_rows,
        "</tbody>",
        "</table>",
        note_html,
        "<footer>",
        f"Report generato da <b>pqc-audit-italia v{escape(__version__)}</b> — "
        '<a href="https://github.com/aureliocpr/pqc-audit-italia">'
        "github.com/aureliocpr/pqc-audit-italia</a>. AGPL-3.0.",
        "</footer>",
        f"<script>{_JS}</script>",
        "</body></html>",
    ]
    return "".join(parts) + "\n"


__all__ = ["render"]
