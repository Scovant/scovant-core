"""Shared report primitives over `list[CheckResult]` / `Report` — the
population and ordering rules every renderer (text, JSON, HTML, MCP) must
agree on, so "top findings" or "experimental" never drifts by renderer."""
from __future__ import annotations

from scovant_core.models import Category, CheckResult, CheckStatus, Report

_GROUP_ORDER = (
    CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.ERROR, CheckStatus.PASS, CheckStatus.NA,
)

# The one sentence every renderer prints beside the Agentic Security & Trust
# section — see docs/security.md. Core NEVER scores
# this section, and this sentence is the load-bearing disclaimer that keeps
# a reader from mistaking "passive signals only" for an overall security
# rating.
SECURITY_DISCLAIMER = (
    "This section evaluates tested AI-agent security controls and machine-facing security signals. "
    "It is not an overall website or application security rating."
)
_SECURITY_DOMAIN_TITLES = {
    "web_baseline": "Web baseline", "disclosure": "Disclosure",
    "data_exposure": "Data exposure", "prompt_surface": "Prompt surface",
}


def status_note(report: Report) -> tuple[str, str] | None:
    """A one-sentence explanation for a non-OK, non-INSUFFICIENT_EVIDENCE
    score status, split as `(strong, rest)` so each renderer can bold the
    first part in its own markup (`**{strong}**{rest}` in Markdown/the
    Action summary, `<strong>{e(strong)}</strong>{e(rest)}` in HTML) without
    three copies of the wording drifting apart. `None` when the status needs
    no extra sentence (OK, or INSUFFICIENT_EVIDENCE — already unambiguous
    from the score line itself)."""
    s = report.score
    if s.status == "NOT_CANONICAL":
        return ("Canonical Core Score: NOT CALCULATED", " — a subset of checks was selected.")
    if s.status == "DEGRADED":
        # READINESS errors only: a SECURITY-check error never degrades the
        # score (see engine.py's `readiness_error_count`), so quoting the
        # total here would name security probes as the cause of a
        # degradation they cannot produce. `security_error_count` is absent
        # on a pre-0.4.0 report, where every error was a readiness error.
        n = int(report.metrics.get("error_count", 0)) - int(report.metrics.get("security_error_count", 0) or 0)
        return ("No grade", f" — score DEGRADED (coverage {s.coverage:.0%}, {n} checks errored).")
    return None


def profile_note(report: Report) -> str | None:
    """Audit §14: an auto-detected profile below LOW_CONFIDENCE is stated on
    the report — never silently scored as if declared. None for a declared
    profile or a confident detection."""
    from scovant_core.profiles import LOW_CONFIDENCE
    t = report.target
    if t.requested_profile != "auto" or t.profile_confidence >= LOW_CONFIDENCE:
        return None
    return (f"Profile: {t.resolved_profile}? (confidence LOW, {t.profile_confidence:.2f}) "
            "— canonical comparison should specify --profile.")


def scored_experimental(report: Report) -> bool:
    """Whether this scan actually scored experimental checks (`--experimental`
    was on) — read off the report's own provenance, never guessed from the
    findings themselves."""
    return bool(report.provenance.get("experimental"))


def evaluated_experimental(findings: list[CheckResult]) -> list[CheckResult]:
    """Experimental findings that are NOT `N/A`, in id order — an `N/A`
    experimental finding evaluated nothing and carries nothing to show."""
    return sorted(
        (f for f in findings if f.experimental and f.status != CheckStatus.NA),
        key=lambda f: f.id,
    )


def na_experimental(findings: list[CheckResult]) -> list[CheckResult]:
    """Experimental findings that ARE `N/A`, in id order — the complement of
    `evaluated_experimental`. They carry nothing to *show*, but they are
    counted in a report's header line (which counts every check), so a
    renderer that omits them entirely leaves a reader with arithmetic that
    does not reconcile. Renderers list them as bare ids, never as entries."""
    return sorted(
        (f for f in findings if f.experimental and f.status == CheckStatus.NA),
        key=lambda f: f.id,
    )


def has_experimental(findings: list[CheckResult]) -> bool:
    return any(f.experimental for f in findings)


_TOP_FINDINGS_CAP = 8
# `Report.security` is never scored (see `security_summary.py`/`SecuritySummary.scored`),
# so a SECURITY-category finding never competes with a readiness finding for
# the same readiness-priority slots — it never moved the score, and a
# security FAIL must not silently displace the readiness FAIL/WARN that
# actually drove the Static Signal Score down (the 2026-09-16 top-findings
# collision: `test_an_oversized_llms_txt_is_declared_as_a_partial_read_end_to_end`
# lost CORE-ACCESS-009 off the readiness top-8 the moment SEC-WEB findings
# started competing for the same slots). Security findings are appended
# AFTER the readiness top-8, in their own capped tail, so both stay visible.
_SECURITY_TAIL_CAP = 8


def _sort_key(f: CheckResult) -> tuple:
    return (f.status != CheckStatus.FAIL, -f.weight, f.id)


def top_findings(findings: list[CheckResult], scored: bool) -> list[CheckResult]:
    """FAIL and WARN findings, FAIL before WARN, then by weight descending,
    id as the final stable tiebreak, capped at 8. An unscored experimental
    finding (`scored=False`) is excluded — it never moved the score, so it
    never belongs in "top findings". SECURITY-category findings never
    compete with readiness findings for these 8 slots (`Report.security` is
    never scored); they are appended afterward, in their own capped tail —
    see `_SECURITY_TAIL_CAP` above."""
    candidates = [
        f for f in findings
        if f.status in (CheckStatus.FAIL, CheckStatus.WARN) and (scored or not f.experimental)
    ]
    readiness = sorted((f for f in candidates if f.category != Category.SECURITY), key=_sort_key)
    security = sorted((f for f in candidates if f.category == Category.SECURITY), key=_sort_key)
    return readiness[:_TOP_FINDINGS_CAP] + security[:_SECURITY_TAIL_CAP]


def status_counts(findings: list[CheckResult]) -> dict[CheckStatus, int]:
    counts = dict.fromkeys(CheckStatus, 0)
    for f in findings:
        counts[f.status] += 1
    return counts


def capabilities_lines(report: Report) -> list[str]:
    """`Capabilities detected` rows — `<protocol>: <state>` in PROTOCOLS
    order; descriptive only (see analysis.protocol_adoption)."""
    from scovant_core.analysis.protocol_adoption import PROTOCOLS

    adoption = report.metrics.get("protocol_adoption") or {}
    return [f"{p}: {adoption.get(p, 'not_checked')}" for p in PROTOCOLS]


def standards_line(report: Report) -> str:
    """One descriptive line per third-party standard (AgentReady v1.0 today);
    never a score. Zero counts are omitted; a tier with nothing measured
    reads `none measured`."""
    from scovant_core.standards.agentready import AGENTREADY_VERSION, TIERS
    cov = (report.metrics.get("standards") or {}).get("agentready_v1") or {}
    by_tier = cov.get("by_tier") or {}
    parts = []
    for tier in TIERS:
        t = by_tier.get(tier)
        if not t:
            continue
        if t["measured"] == 0:
            parts.append(f"{tier} none measured (0/{t['requirements']})")
            continue
        counts = ", ".join(f"{t[k]} {k}" for k in ("pass", "warn", "fail") if t[k])
        parts.append(f"{tier} {t['measured']}/{t['requirements']} measured — {counts}")
    return f"AgentReady v{cov.get('version', AGENTREADY_VERSION)} (descriptive, not scored): " + " · ".join(parts)


STANDARDS_FOOTER = "Mapping: docs/standards/agentready.md"


def security_rows(report: Report) -> list[tuple[str, str]]:
    """`(label, value)` rows for the security block, shared by
    text/markdown/html — severity counts (FAIL+WARN only, mirroring
    `security_summary.build_security_summary`) then a PASS/WARN/FAIL line
    per security domain.

    A REAL scan's `SecuritySummary` always carries a full 5-key
    `findings_by_severity` dict (every `Severity`, even at 0) and at least
    one `by_domain` entry — every SECURITY check is bucketed regardless of
    its status. Both being empty therefore means no scan ever populated
    this block at all — either a report re-rendered from a pre-0.4.0
    schema-1.0 JSON (round-tripped through `SecuritySummary`'s own empty
    defaults) or a scan where no SECURITY check ran (`--exclude security`;
    see `security_summary.build_security_summary`). Neither is a scan that
    measured zero security findings, and reporting "Critical 0" for either
    would claim a measurement that never happened."""
    s = report.security
    if not s.findings_by_severity and not s.by_domain:
        return [("Security signals", "not measured (no security check ran)")]
    sev = s.findings_by_severity
    rows = [
        ("Critical", str(sev.get("critical", 0))), ("High", str(sev.get("high", 0))),
        ("Medium", str(sev.get("medium", 0))), ("Low", str(sev.get("low", 0))),
    ]
    for dom, counts in s.by_domain.items():
        title = _SECURITY_DOMAIN_TITLES.get(dom, dom)
        rows.append((title, f"PASS {counts.get('PASS', 0)}  WARN {counts.get('WARN', 0)}  FAIL {counts.get('FAIL', 0)}"))
    return rows


def security_findings(report: Report) -> list[CheckResult]:
    """SECURITY-category FAIL/WARN findings, id-sorted — the finding cards
    shown under the Agentic Security & Trust section. Never filtered by
    `scored_experimental`: the section itself is never scored (see
    `Report.security.scored`), so "was --experimental on" has no bearing on
    whether a security finding is shown."""
    return sorted(
        (f for f in report.findings if f.category == Category.SECURITY and f.status in (CheckStatus.FAIL, CheckStatus.WARN)),
        key=lambda f: f.id,
    )


def grouped_by_status(findings: list[CheckResult]) -> dict[CheckStatus, list[CheckResult]]:
    """Findings bucketed by status, FAIL/WARN/ERROR/PASS/N-A order, id-sorted
    within each bucket."""
    buckets: dict[CheckStatus, list[CheckResult]] = {status: [] for status in _GROUP_ORDER}
    for f in findings:
        buckets[f.status].append(f)
    for status in _GROUP_ORDER:
        buckets[status].sort(key=lambda f: f.id)
    return buckets
