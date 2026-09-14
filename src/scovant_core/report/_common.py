"""Shared report primitives over `list[CheckResult]` / `Report` — the
population and ordering rules every renderer (text, JSON, HTML, MCP) must
agree on, so "top findings" or "experimental" never drifts by renderer."""
from __future__ import annotations

from scovant_core.models import CheckResult, CheckStatus, Report

_GROUP_ORDER = (
    CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.ERROR, CheckStatus.PASS, CheckStatus.NA,
)


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
        n = int(report.metrics.get("error_count", 0))
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


def top_findings(findings: list[CheckResult], scored: bool) -> list[CheckResult]:
    """FAIL and WARN findings, FAIL before WARN, then by weight descending,
    id as the final stable tiebreak, capped at 8. An unscored experimental
    finding (`scored=False`) is excluded — it never moved the score, so it
    never belongs in "top findings"."""
    candidates = [
        f for f in findings
        if f.status in (CheckStatus.FAIL, CheckStatus.WARN) and (scored or not f.experimental)
    ]
    candidates.sort(key=lambda f: (f.status != CheckStatus.FAIL, -f.weight, f.id))
    return candidates[:8]


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


def grouped_by_status(findings: list[CheckResult]) -> dict[CheckStatus, list[CheckResult]]:
    """Findings bucketed by status, FAIL/WARN/ERROR/PASS/N-A order, id-sorted
    within each bucket."""
    buckets: dict[CheckStatus, list[CheckResult]] = {status: [] for status in _GROUP_ORDER}
    for f in findings:
        buckets[f.status].append(f)
    for status in _GROUP_ORDER:
        buckets[status].sort(key=lambda f: f.id)
    return buckets
