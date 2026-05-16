"""PDF reporter — turns the executive Markdown into a printable PDF.

This reporter is a thin wrapper around :mod:`pqc_audit.reporters.markdown_reporter`
that converts the Markdown to HTML and then rasterizes it via WeasyPrint.

WeasyPrint is intentionally an *optional* dependency (extra ``[pdf]``).
The import is lazy: the package itself works without weasyprint as long
as the user does not invoke this reporter.

Security note (CWE-918): the HTML payload may include user-controlled
text (vulnerability descriptions, asset locations) that the optional
``markdown`` package translates into ``<img src=...>``,
``<a href=...>`` and similar. We block WeasyPrint from fetching any
URL outside ``data:`` so a tainted AuditReport cannot turn the PDF
render into an SSRF / local-file-read primitive.

Typical usage::

    from pqc_audit.reporters.pdf_reporter import render
    pdf_bytes = render(report)
    Path("report.pdf").write_bytes(pdf_bytes)
"""

from __future__ import annotations

from html import escape
from typing import Any

from pqc_audit import __version__
from pqc_audit.core.models import AuditReport
from pqc_audit.reporters.markdown_reporter import render as render_markdown

_INSTALL_HINT = "PDF rendering requires WeasyPrint. Install with: pip install pqc-audit-italia[pdf]"

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8" />
<title>pqc-audit-italia — report</title>
<style>
  @page {{ size: A4; margin: 18mm 16mm 22mm 16mm; }}
  body {{ font-family: 'DejaVu Sans', 'Helvetica', sans-serif; font-size: 10.5pt;
          color: #1a1a1a; line-height: 1.45; }}
  h1 {{ font-size: 18pt; color: #002b5b; border-bottom: 2px solid #002b5b;
        padding-bottom: 6px; margin: 0 0 12px 0; }}
  h2 {{ font-size: 13pt; color: #002b5b; margin-top: 18px;
        border-bottom: 1px solid #c8d3df; padding-bottom: 3px; }}
  h3 {{ font-size: 11.5pt; color: #324d75; margin-top: 14px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 6px 0 12px 0;
           font-size: 9.5pt; }}
  th, td {{ border: 1px solid #c8d3df; padding: 4px 6px; text-align: left;
            vertical-align: top; }}
  th {{ background: #eaf1f9; }}
  code {{ background: #f4f6f9; padding: 1px 3px; border-radius: 2px;
          font-family: 'DejaVu Sans Mono', monospace; font-size: 9.5pt; }}
  ul {{ padding-left: 18px; }}
  hr {{ border: none; border-top: 1px solid #c8d3df; margin: 18px 0; }}
  .footer {{ font-size: 8pt; color: #5a5a5a; margin-top: 24px; }}
</style>
</head>
<body>
{body}
<div class="footer">pqc-audit-italia v{version} — output generato automaticamente.</div>
</body>
</html>
"""


def _markdown_to_html(md: str) -> str:
    """Convert Markdown to HTML.

    Tries the optional ``markdown`` package first (better tables and lists),
    and falls back to a deliberately conservative inline conversion that
    handles only the constructs the MarkdownReporter actually emits:
    headers, GFM tables, bold, italic, inline code and bullet lists.
    """
    try:
        import markdown as _md  # type: ignore[import-not-found,import-untyped,unused-ignore]  # noqa: PLC0415
    except ImportError:
        return _fallback_markdown_to_html(md)
    return str(_md.markdown(md, extensions=["tables"]))


def _render_table(rows: list[list[str]]) -> list[str]:
    """Build HTML table fragments from a buffer of GFM-style rows."""
    if not rows:
        return []
    head = rows[0]
    body = rows[1:]
    if body and all(set(c.strip()) <= set("-: ") for c in body[0]):
        body = body[1:]
    out = ["<table>"]
    out.append(
        "<thead><tr>" + "".join(f"<th>{_inline(c.strip())}</th>" for c in head) + "</tr></thead>"
    )
    out.append("<tbody>")
    for row in body:
        out.append("<tr>" + "".join(f"<td>{_inline(c.strip())}</td>" for c in row) + "</tr>")
    out.append("</tbody></table>")
    return out


def _fallback_markdown_to_html(md: str) -> str:
    """Minimal Markdown-to-HTML when the ``markdown`` package is unavailable.

    Covers only the subset emitted by
    :func:`pqc_audit.reporters.markdown_reporter.render` (headers, GFM
    tables, bold, italic, inline code, bullet lists, hr).
    """
    out: list[str] = []
    in_list = False
    table_rows: list[list[str]] = []

    def _flush_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def _flush_table() -> None:
        out.extend(_render_table(table_rows))
        table_rows.clear()

    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("|") and line.endswith("|"):
            _flush_list()
            table_rows.append(list(line.strip("|").split("|")))
            continue
        if table_rows:
            _flush_table()
        if line.startswith("# "):
            _flush_list()
            out.append(f"<h1>{_inline(line[2:].strip())}</h1>")
        elif line.startswith("## "):
            _flush_list()
            out.append(f"<h2>{_inline(line[3:].strip())}</h2>")
        elif line.startswith("### "):
            _flush_list()
            out.append(f"<h3>{_inline(line[4:].strip())}</h3>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(line[2:].strip())}</li>")
        elif line.startswith("---"):
            _flush_list()
            out.append("<hr/>")
        elif not line:
            _flush_list()
            out.append("")
        else:
            _flush_list()
            out.append(f"<p>{_inline(line)}</p>")
    _flush_list()
    if table_rows:
        _flush_table()
    return "\n".join(out)


def _inline(text: str) -> str:
    """Apply minimal inline formatting (escape, then bold/italic/code)."""
    safe = escape(text)
    # Order matters: code first to avoid eating ** inside backticks
    out: list[str] = []
    i = 0
    while i < len(safe):
        if safe[i] == "`":
            j = safe.find("`", i + 1)
            if j == -1:
                out.append(safe[i:])
                break
            out.append(f"<code>{safe[i + 1 : j]}</code>")
            i = j + 1
            continue
        if safe.startswith("**", i):
            j = safe.find("**", i + 2)
            if j == -1:
                out.append(safe[i:])
                break
            out.append(f"<strong>{safe[i + 2 : j]}</strong>")
            i = j + 2
            continue
        if safe[i] == "_" and i + 1 < len(safe) and safe[i + 1].isalpha():
            j = safe.find("_", i + 1)
            if j != -1:
                out.append(f"<em>{safe[i + 1 : j]}</em>")
                i = j + 1
                continue
        out.append(safe[i])
        i += 1
    return "".join(out)


def _no_network_fetcher(url: str) -> dict[str, Any]:
    """WeasyPrint ``url_fetcher`` that refuses any non-``data:`` URL.

    The audit report can contain attacker-controlled Markdown
    (vulnerability descriptions, asset locations). The optional
    ``markdown`` package translates ``![x](http://...)`` and similar
    into HTML ``<img>``/``<link>`` nodes that WeasyPrint would happily
    fetch via the default ``url_fetcher`` (HTTP and ``file://``). That
    would turn rendering a PDF into an SSRF / local-file-read primitive
    (CWE-918 / CWE-200).

    Inline ``data:`` URIs are still allowed: they are a common way to
    embed small inline icons and carry no network exposure.

    Returns:
        Dict shaped for WeasyPrint's ``url_fetcher`` contract when the
        URL is an inline ``data:`` payload.

    Raises:
        ValueError: for any URL scheme other than ``data:``. WeasyPrint
            surfaces this as a missing-resource warning and continues
            rendering — the PDF is produced without the blocked
            resource.
    """
    if url.startswith("data:"):
        # Defer to WeasyPrint's own data: decoder so we don't have to
        # reinvent base64 / urlencoded parsing here.
        from weasyprint import (  # type: ignore[import-not-found,unused-ignore]  # noqa: I001, PLC0415
            default_url_fetcher,
        )

        result: dict[str, Any] = default_url_fetcher(url)
        return result
    raise ValueError(
        f"pqc-audit-italia: PDF reporter blocked external URL {url!r} "
        "(only data: URIs are allowed; see SECURITY.md)."
    )


def _html_to_pdf(html: str) -> bytes:
    """Convert a complete HTML document to PDF bytes via WeasyPrint.

    Lazy import so the package can be used without weasyprint installed.
    Test code monkey-patches this function to avoid requiring the optional
    dependency for unit tests.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-not-found,unused-ignore]  # noqa: PLC0415
    except ImportError as e:
        raise RuntimeError(_INSTALL_HINT) from e
    pdf_bytes = HTML(string=html, url_fetcher=_no_network_fetcher).write_pdf()
    if pdf_bytes is None:  # pragma: no cover - WeasyPrint guarantees bytes here
        raise RuntimeError("WeasyPrint returned no PDF bytes")
    return bytes(pdf_bytes)


def render(report: AuditReport) -> bytes:
    """Render an :class:`AuditReport` to PDF bytes.

    Raises:
        RuntimeError: when WeasyPrint is not installed. The error message
            tells the user how to install the ``[pdf]`` extra.
    """
    md = render_markdown(report)
    body_html = _markdown_to_html(md)
    full_html = _HTML_TEMPLATE.format(body=body_html, version=__version__)
    return _html_to_pdf(full_html)
