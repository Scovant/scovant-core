"""HTML report — one self-contained document for pasting into a browser or
attaching to a CI artifact. Derived from `Report` only, same population and
ordering rules as `report/markdown.py` so the two formats never disagree."""
from __future__ import annotations

import html
import json

from scovant_core.models import CheckResult, CheckStatus, Report
from scovant_core.report._cloud_matrix import CORE_BOUNDARY, CORE_VS_CLOUD
from scovant_core.report._common import (
    STANDARDS_FOOTER,
    capabilities_lines,
    evaluated_experimental,
    grouped_by_status,
    has_experimental,
    na_experimental,
    profile_note,
    scored_experimental,
    standards_line,
    status_counts,
    status_note,
)
from scovant_core.report._cta import CTA_TEXT, cta_url

_STATUS_LABEL = {
    CheckStatus.FAIL: "FAIL", CheckStatus.WARN: "WARN", CheckStatus.ERROR: "ERROR",
    CheckStatus.PASS: "PASS", CheckStatus.NA: "N/A",
}
_STATUS_CLASS = {
    CheckStatus.FAIL: "badge-fail", CheckStatus.WARN: "badge-warn", CheckStatus.ERROR: "badge-error",
    CheckStatus.PASS: "badge-pass", CheckStatus.NA: "badge-na",
}
_GROUP_ORDER = (CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.ERROR, CheckStatus.PASS, CheckStatus.NA)


def e(value: object) -> str:
    return html.escape(str(value), quote=True)


_CSS = """
:root { color-scheme: light dark; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial,
    sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  margin: 0; padding: 0; line-height: 1.5; color: #1a1a1a; background: #fff;
}
main { max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
h1, h2 { line-height: 1.25; }
h1 { font-size: 1.5rem; word-break: break-word; }
h2 { font-size: 1.15rem; margin-top: 2.5rem; border-bottom: 1px solid #ddd; padding-bottom: 0.35rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f5f5f5; }
.badge {
  display: inline-block; padding: 0.1rem 0.5rem; border-radius: 0.25rem; font-size: 0.8rem;
  font-weight: 600; color: #fff;
}
.badge-pass { background: #1a7f37; }
.badge-warn { background: #9a6700; }
.badge-fail { background: #cf222e; }
.badge-na { background: #6e7781; }
.badge-error { background: #57606a; }
details { margin: 0.5rem 0; border: 1px solid #ddd; border-radius: 0.25rem; padding: 0.4rem 0.6rem; }
details summary { cursor: pointer; font-weight: 600; }
pre {
  overflow-x: auto; background: #f6f8fa; padding: 0.75rem; border-radius: 0.25rem;
  font-size: 0.85rem;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
dt { font-weight: 600; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #ddd; }
a { color: #0969da; }
@media (prefers-color-scheme: dark) {
  body { color: #e6edf3; background: #0d1117; }
  h2 { border-bottom-color: #30363d; }
  th, td { border-color: #30363d; }
  th { background: #161b22; }
  details { border-color: #30363d; }
  pre { background: #161b22; }
  footer { border-top-color: #30363d; }
  a { color: #58a6ff; }
}
@media print {
  body { background: #fff; color: #000; }
  a { color: #000; text-decoration: underline; }
}
"""


def _summary_section(r: Report) -> list[str]:
    t = r.target
    counts = status_counts(r.findings)
    out = ['<section id="summary">', "<h1>Scovant Core — " + e(t.final_url or t.input_url) + "</h1>"]
    out.append(
        f"<p><strong>Profile:</strong> {e(t.resolved_profile)} "
        f"(requested {e(t.requested_profile)}, confidence {t.profile_confidence:.0%})</p>"
    )
    out.append(f"<p><strong>Core version:</strong> {e(r.core_version)}</p>")
    if scored_experimental(r):
        out.append("<p><strong>Experimental checks:</strong> scored</p>")
    if r.provenance.get("allow_private_networks"):
        out.append(
            "<p><strong>Note:</strong> private-network targets were allowed for this "
            "scan (<code>--allow-private-networks</code>).</p>"
        )
    out.append(
        "<p>"
        + ", ".join(
            f"{counts[s]} {_STATUS_LABEL[s]}"
            for s in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL, CheckStatus.NA, CheckStatus.ERROR)
        )
        + f" ({len(r.findings)} checks)</p>"
    )
    out.append("</section>")
    return out


def _score_section(r: Report) -> list[str]:
    s = r.score
    value = "—" if s.value is None else str(s.value)
    grade = s.grade or "—"
    error_count = r.metrics.get("error_count", 0)
    out = ['<section id="score">', f"<h2>{e(s.name)}</h2>"]
    out.append(f'<p style="font-size:2.5rem;font-weight:700;">{e(value)} / 100</p>')
    out.append(
        f"<p><strong>Grade:</strong> {e(grade)} &middot; <strong>Scope:</strong> {e(s.scope)} "
        f"&middot; <strong>Status:</strong> {e(s.status)} &middot; "
        f"<strong>Coverage:</strong> {s.coverage:.0%} &middot; <strong>Errors:</strong> {error_count}</p>"
    )
    note = status_note(r)
    if note:
        strong, rest = note
        out.append(f"<p><strong>{e(strong)}</strong>{e(rest)}</p>")
    p_note = profile_note(r)
    if p_note:
        out.append(f"<p><em>{e(p_note)}</em></p>")
    out.append(
        f"<p><strong>Capabilities detected</strong> (descriptive, not scored): "
        f"{e(' · '.join(capabilities_lines(r)))}</p>"
    )
    out.append(f"<p><strong>Standards:</strong> {e(standards_line(r))} — {e(STANDARDS_FOOTER)}</p>")
    out.append("</section>")
    return out


def _categories_section(r: Report) -> list[str]:
    out = ['<section id="categories">', "<h2>Categories</h2>", "<table>"]
    out.append("<tr><th>Category</th><th>Weight</th><th>Score</th><th>Evaluated / applicable</th></tr>")
    for c in r.categories.values():
        score = "n/a" if c.score is None else f"{c.score:.0f}"
        out.append(
            f"<tr><td>{e(c.title)}</td><td>{e(c.weight)}</td><td>{e(score)}</td>"
            f"<td>{c.evaluated_weight:g} / {c.applicable_weight:g}</td></tr>"
        )
    out.append("</table>")
    out.append("</section>")
    return out


def _findings_section(r: Report, scored: bool) -> list[str]:
    out = ['<section id="findings">', "<h2>Findings</h2>", "<table>"]
    out.append("<tr><th>Status</th><th>ID</th><th>Title</th><th>Severity</th><th>Summary</th></tr>")
    buckets = grouped_by_status(r.findings)
    for status in _GROUP_ORDER:
        fs = [f for f in buckets[status] if scored or not f.experimental]
        cls = _STATUS_CLASS[status]
        for f in fs:
            out.append(
                f'<tr><td><span class="badge {cls}">{e(_STATUS_LABEL[f.status])}</span></td>'
                f"<td><code>{e(f.id)}</code></td><td>{e(f.title)}</td><td>{e(f.severity.value)}</td>"
                f"<td>{e(f.summary)}</td></tr>"
            )
    out.append("</table>")
    if not scored:
        ex = evaluated_experimental(r.findings)
        na = na_experimental(r.findings)
        if ex:
            out.append("<h3>Experimental (not scored)</h3><ul>")
            for f in ex:
                out.append(f"<li><code>{e(f.id)}</code> ({e(f.status.value)}) — {e(f.summary)}</li>")
            out.append("</ul>")
        elif has_experimental(r.findings):
            out.append("<p><em>Experimental checks: not scored (run with --experimental)</em></p>")
        if na:
            # The count line in `_summary_section` counts every check, N/A
            # experimental ones included, while the table above lists only
            # scored findings and the block above lists only evaluated
            # experimental ones — an N/A experimental finding has nothing
            # to show but must still be named somewhere, or the summary's
            # own arithmetic does not reconcile (mirrors markdown.py).
            out.append("<p>N/A: " + ", ".join(f"<code>{e(f.id)}</code>" for f in na) + "</p>")
    out.append("</section>")
    return out


def _evidence_section(findings: list[CheckResult], scored: bool) -> list[str]:
    out = ['<section id="evidence">', "<h2>Evidence</h2>"]
    any_evidence = False
    for f in sorted(findings, key=lambda f: f.id):
        if not f.evidence or (f.experimental and not scored):
            continue
        any_evidence = True
        ev = json.dumps(f.evidence, indent=2, sort_keys=True, ensure_ascii=False)
        out.append(f"<details><summary><code>{e(f.id)}</code> — {e(f.title)}</summary>")
        out.append(f"<pre><code>{e(ev)}</code></pre>")
        out.append("</details>")
    if not any_evidence:
        out.append("<p>(none)</p>")
    out.append("</section>")
    return out


def _remediation_section(findings: list[CheckResult], scored: bool) -> list[str]:
    out = ['<section id="remediation">', "<h2>Remediation</h2>", "<ul>"]
    seen: set[str] = set()
    items: list[str] = []
    for f in sorted(findings, key=lambda f: f.id):
        if f.status not in (CheckStatus.FAIL, CheckStatus.WARN):
            continue
        if not f.remediation or f.id in seen or (f.experimental and not scored):
            continue
        seen.add(f.id)
        items.append(f"<li><code>{e(f.id)}</code> — {e(f.remediation)}</li>")
    out.extend(items or ["<li>(none)</li>"])
    out.append("</ul>")
    out.append("</section>")
    return out


def _limitations_section(findings: list[CheckResult], scored: bool) -> list[str]:
    out = ['<section id="limitations">', "<h2>Limitations</h2>", "<ul>"]
    seen: set[str] = set()
    items: list[str] = []
    for f in findings:
        if not f.limitations or f.limitations in seen or (f.experimental and not scored):
            continue
        seen.add(f.limitations)
        items.append(f"<li>{e(f.limitations)}</li>")
    out.extend(items or ["<li>(none)</li>"])
    out.append("</ul>")
    out.append("</section>")
    return out


def _not_tested_section(r: Report) -> list[str]:
    out = ['<section id="not-tested">', "<h2>Not tested by Scovant Core</h2>", "<ul>"]
    out.extend(f"<li>{e(n)}</li>" for n in r.not_tested)
    out.append("</ul>")
    out.append("</section>")
    return out


def _cloud_comparison_section() -> list[str]:
    out = ['<section id="cloud-comparison">', "<h2>Core vs Cloud</h2>", "<table>"]
    out.append("<tr><th>Capability</th><th>Core</th><th>Cloud</th></tr>")
    for capability, core, cloud in CORE_VS_CLOUD:
        cap_cell = f"<strong>{e(capability)}</strong>" if core == "—" and cloud == "—" else e(
            capability
        )
        out.append(f"<tr><td>{cap_cell}</td><td>{e(core)}</td><td>{e(cloud)}</td></tr>")
    out.append("</table>")
    out.append(f"<p>{e(CORE_BOUNDARY)}</p>")
    out.append("</section>")
    return out


def _methodology_section() -> list[str]:
    out = ['<section id="methodology">', "<h2>Methodology</h2>"]
    out.append(
        "<p>Category weights are 25/25/20/15/15. Each check contributes PASS&nbsp;=&nbsp;1, "
        "WARN&nbsp;=&nbsp;0.5, FAIL&nbsp;=&nbsp;0 to its category; ERROR lowers coverage "
        "(a document that could not be read counts against evidence), and N/A is excluded "
        "entirely. A scan scores INSUFFICIENT_EVIDENCE below a 60% coverage floor of its "
        "applicable weight. A full-selection scan that clears that floor but falls short of "
        "85% coverage, or that hit any ERROR, is reported as DEGRADED (a score, no letter "
        "grade) rather than being silently graded on incomplete evidence. Running with "
        "checks narrowed or widened via --include/--exclude/--experimental instead reports a "
        "NOT_CANONICAL Subset Diagnostic Score over that subset, not the full Core Score. "
        "Full reference: "
        '<a href="https://github.com/Scovant/scovant-core/blob/main/docs/methodology.md">'
        "docs/methodology.md</a>.</p>"
    )
    out.append("</section>")
    return out


def _provenance_section(r: Report) -> list[str]:
    out = ['<section id="provenance">', "<h2>Provenance</h2>", "<dl>"]
    out.append(f"<dt>scan_id</dt><dd>{e(r.scan_id)}</dd>")
    out.append(f"<dt>started_at</dt><dd>{e(r.started_at)}</dd>")
    out.append(f"<dt>completed_at</dt><dd>{e(r.completed_at)}</dd>")
    out.append(f"<dt>schema_version</dt><dd>{e(r.schema_version)}</dd>")
    for key, value in r.provenance.items():
        out.append(f"<dt>{e(key)}</dt><dd>{e(value)}</dd>")
    out.append("</dl>")
    out.append("</section>")
    return out


def render_html(report: Report, *, utm_medium: str = "html") -> str:
    scored = scored_experimental(report)
    target_label = report.target.final_url or report.target.input_url
    out = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Scovant Core — {e(target_label)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
    ]
    out += _summary_section(report)
    out += _score_section(report)
    out += _categories_section(report)
    out += _findings_section(report, scored)
    out += _evidence_section(report.findings, scored)
    out += _remediation_section(report.findings, scored)
    out += _limitations_section(report.findings, scored)
    out += _not_tested_section(report)
    out += _cloud_comparison_section()
    out += _methodology_section()
    out += _provenance_section(report)
    out += [
        "<footer>",
        f"<p>{e(CTA_TEXT)} <a href=\"{e(cta_url(utm_medium))}\">scovant.com/scan</a></p>",
        "</footer>",
        "</main>",
        "</body>",
        "</html>",
    ]
    return "\n".join(out)
