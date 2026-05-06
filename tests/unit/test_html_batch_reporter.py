"""Unit tests for the self-contained HTML batch reporter.

The HTML reporter takes the same ``rows`` dict the Markdown reporter
consumes and produces a *single*, *self-contained* HTML document with
inline CSS + JavaScript — no external fonts, no CDN, no remote logo.
The page is meant to be e-mailed as one .html attachment to a CISO /
CFO who wants something more digestible than a Markdown table but
without the print artifacts of a PDF.

Functional requirements covered here:

* render(rows, policy=, sensitivity=, enforce=) returns a complete
  HTML document with ``<!doctype html>``, ``<style>`` and ``<script>``.
* Each host appears as one ``<tr data-host="...">`` so the in-page
  JavaScript filters can target it.
* Hostnames are HTML-escaped — they come from CSV input and end up
  in the DOM, so XSS surface must be zero.
* Error rows render with a distinct CSS class so the user can spot
  unreachable targets without reading every row.
* The "no PQC negotiated" advisory note from the Markdown reporter
  carries over verbatim — the executive summary text is part of the
  product, not boilerplate.
* No external resources: no ``http://``/``https://``/``//cdn`` URLs
  in ``<link>``, ``<script src=>``, ``<img src=>``, or ``url(...)``.
  Plain anchor links in body text are allowed.
"""

from __future__ import annotations

import re

from pqc_audit.reporters import html_batch_reporter


def _row_ok(
    host: str = "example.it",
    algorithm: str = "RSA-2048",
    vulns: int = 1,
    hndl: int = 80,
    qday: int = 80,
    policy_verdict: str = "FAIL",
    violations: int = 1,
    top_reco: str = "ML-DSA-65",
) -> dict:
    return {
        "host": host,
        "status": "ok",
        "algorithm": algorithm,
        "vulns": vulns,
        "hndl": hndl,
        "qday": qday,
        "policy_verdict": policy_verdict,
        "violations": violations,
        "top_reco": top_reco,
    }


def _row_err(host: str = "broken.invalid", error: str = "TimeoutError: x") -> dict:
    return {"host": host, "status": "error", "error": error}


def test_render_returns_full_html_document() -> None:
    html = html_batch_reporter.render(
        [_row_ok()],
        policy="agid_2026",
        sensitivity=10,
        enforce=True,
    )
    assert html.startswith("<!doctype html>") or html.startswith("<!DOCTYPE html>")
    assert "<html" in html
    assert "</html>" in html
    assert "<style" in html and "</style>" in html
    assert "<script" in html and "</script>" in html


def test_render_inserts_one_row_per_host() -> None:
    rows = [_row_ok(host="a.gov.it"), _row_ok(host="b.gov.it")]
    html = html_batch_reporter.render(rows, policy="agid_2026", sensitivity=10, enforce=True)
    assert 'data-host="a.gov.it"' in html
    assert 'data-host="b.gov.it"' in html


def test_render_html_escapes_hostnames_against_xss() -> None:
    nasty = 'evil"><script>alert(1)</script>'
    html = html_batch_reporter.render(
        [_row_ok(host=nasty)],
        policy="agid_2026",
        sensitivity=10,
        enforce=True,
    )
    # The literal payload must NOT survive into the rendered HTML.
    assert "<script>alert(1)</script>" not in html
    # But the escaped form should be present somewhere (in the data
    # attribute or the cell text). We check for the unmistakable
    # "&lt;script&gt;" footprint.
    assert "&lt;script&gt;" in html


def test_render_marks_error_rows_with_dedicated_class() -> None:
    html = html_batch_reporter.render(
        [_row_ok(), _row_err()],
        policy="agid_2026",
        sensitivity=10,
        enforce=True,
    )
    # Error rows carry a class hook the JS / CSS uses to dim them.
    assert 'class="row-error"' in html or "row-error" in html


def test_render_includes_policy_metadata_header() -> None:
    html = html_batch_reporter.render(
        [_row_ok()],
        policy="pa_critical_2027",
        sensitivity=50,
        enforce=True,
    )
    assert "pa_critical_2027" in html
    assert "50" in html  # sensitivity years


def test_render_no_pqc_note_when_all_classical() -> None:
    rows = [_row_ok(algorithm="RSA-2048", top_reco="ML-DSA-65")]
    html = html_batch_reporter.render(rows, policy="agid_2026", sensitivity=10, enforce=True)
    assert "P5" in html or "ML-DSA" in html


def test_render_skips_no_pqc_note_when_pqc_present() -> None:
    rows = [_row_ok(algorithm="ML-DSA-65")]
    html = html_batch_reporter.render(rows, policy="agid_2026", sensitivity=10, enforce=True)
    # The ``uniformemente P5`` warning should NOT appear when the
    # batch already shows a PQC-negotiated host. The substring is
    # specific enough that we can pin it.
    assert "uniformemente P5" not in html


def test_render_is_self_contained_no_external_resources() -> None:
    html = html_batch_reporter.render(
        [_row_ok()],
        policy="agid_2026",
        sensitivity=10,
        enforce=True,
    )
    # No external <link rel="stylesheet">.
    assert not re.search(r'<link[^>]+rel=["\']stylesheet["\']', html, re.I)
    # No <script src="..."> — only inline <script>...</script>.
    assert not re.search(r"<script[^>]+src=", html, re.I)
    # No remote <img src="http(s)?://..."> — inline data: URIs are OK.
    assert not re.search(r'<img[^>]+src=["\']https?://', html, re.I)
    # No CSS @import or url() pointing at a remote host.
    assert not re.search(r"@import\s+url\(\s*['\"]?https?://", html, re.I)
    assert not re.search(r"url\(\s*['\"]?https?://", html, re.I)


def test_render_includes_filter_input_for_host() -> None:
    html = html_batch_reporter.render(
        [_row_ok()],
        policy="agid_2026",
        sensitivity=10,
        enforce=True,
    )
    # A host filter input is what makes this useful at scale (50+ rows).
    # The page MUST expose at least one <input> element wired to a
    # filter handler — we don't pin the exact id, but we do require
    # the substring "filter".
    assert "<input" in html
    assert "filter" in html.lower()


def test_render_includes_csv_download_button() -> None:
    html = html_batch_reporter.render(
        [_row_ok()],
        policy="agid_2026",
        sensitivity=10,
        enforce=True,
    )
    # A "Scarica CSV" button keeps the deliverable useful as input
    # to a spreadsheet workflow.
    assert "CSV" in html


def test_render_handles_empty_rows() -> None:
    html = html_batch_reporter.render([], policy="agid_2026", sensitivity=10, enforce=True)
    # Even with 0 hosts the page is still a valid document. We
    # don't want a stack trace and we don't want an empty file.
    assert "<html" in html
    assert "</html>" in html


def test_render_marks_high_hndl_rows_visually() -> None:
    """Rows with HNDL >= 80 must carry a CSS class so the doc
    surfaces "this is the bad one" without reading the number."""
    rows = [_row_ok(hndl=80), _row_ok(hndl=20)]
    html = html_batch_reporter.render(rows, policy="agid_2026", sensitivity=10, enforce=True)
    # Some marker on at least one row that ties to severity.
    # We accept either a row class or a cell class; we just want
    # a stable hook.
    assert "hndl-high" in html or "row-critical" in html
