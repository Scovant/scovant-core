"""The report's `readiness.technical` block and `technical_outcomes` list."""
from __future__ import annotations

from scovant_core.models import (
    NotMeasured,
    Readiness,
    TechnicalCategory,
    TechnicalOutcome,
    TechnicalReadiness,
)
from scovant_core.r2.adapter import evidence_from_store, site_type_for
from scovant_core.r2.evaluate import technical_readiness
from scovant_core.r2.manifest import ScoreEffect
from scovant_core.r2.outcome import OutcomeState
from scovant_core.r2.technical import technical_manifest

_UNMEASURED = (OutcomeState.NOT_MEASURED, OutcomeState.UNKNOWN)

# Report-layer reasons only: the outcome objects (and the Core/Cloud parity
# that compares them) keep the generic reason the predicate gave.
_MCP_HANDSHAKE_RULES = frozenset({
    "MCP_DISCOVERY_INVALID", "SERVER-CARD-004", "SERVER-CARD-005", "AGENT-META-001",
    "AGENT-META-004", "AGENT-META-008", "MCP-OBS-001", "TOOL-RISK-001", "MCP-AUTH-001"})
# Probe name (as in `ScanEvidence.defaulted`) -> the rules whose `measure` reads it.
_PROBE_RULES: dict[str, frozenset[str]] = {
    "robots": frozenset({"AI_CRAWLER_BLOCKED", "AI-BOT-POLICY-001"}),
    "content_signals": frozenset({"CONTENT_SIGNALS_ABSENT"}),
    "sitemap": frozenset({"SITEMAP_MISSING_OR_INVALID"}),
    "llms_txt": frozenset({"LLMS_TXT_MISSING_OR_INVALID"}),
    "ucp": frozenset({"UCP_PROFILE_ABSENT", "UCP_PROFILE_INVALID", "UCP_CHECKOUT_MISSING",
                      "UCP_SIGNING_KEYS_INVALID", "AGENT_PAYMENTS_ABSENT"}),
    "mcp": frozenset({"MCP_ENDPOINT_ABSENT"}) | _MCP_HANDSHAKE_RULES,
    "agent_discovery": frozenset({"AGENT_INTERFACE_DISCOVERY_ABSENT"}),
}
# Rules reading an evidence block Core does not gather in this release.
_NOT_GATHERED_PREFIXES = ("CRAWL-GRAPH-", "MACHINE-REP-", "WEBMCP-", "LLMS-SUPPLY-", "CONTENT-NEG-")
_NOT_GATHERED_CODES = frozenset({
    "MARKDOWN_FOR_AGENTS_ABSENT", "LINK_HEADERS_ABSENT", "AGENT_PAYMENTS_ABSENT",
    "AI-BOT-POLICY-001", "SEMANTIC_HTML_ABSENT", "CITABILITY_WEAK", "CITABILITY_POOR"})


def _reason(outcome, defaulted) -> str:
    """The human-readable reason for a not-measured outcome."""
    if outcome.reason not in ("predicate", ""):
        return outcome.reason
    rule = outcome.rule_id
    probes = sorted(p for p in defaulted if rule in _PROBE_RULES.get(p, ()))
    if probes:
        return f"probe_failed:{probes[0]}"
    if rule in _MCP_HANDSHAKE_RULES:
        return "handshake_not_performed"
    if rule == "PAGE_TOKEN_BLOAT":
        return "tokenizer_unavailable"
    if rule in _NOT_GATHERED_CODES or rule.startswith(_NOT_GATHERED_PREFIXES):
        return "not_gathered_by_core"
    return "not_measured"


def technical_report(store, ctx) -> tuple[Readiness, list[TechnicalOutcome]]:
    site_type, origin = site_type_for(ctx.resolved_profile, ctx.profile_confidence, ctx.options.site_type)
    ev = evidence_from_store(store, site_type=site_type)
    run = technical_readiness(ev.pages, ev.domain, site_type=site_type, defaulted=ev.defaulted)
    manifest = technical_manifest()
    res = run.result
    no_number = res.status == "INSUFFICIENT_EVIDENCE" or res.rating is None
    evidence_state = "NOT_MEASURED" if no_number else "ESTIMATED"
    not_measured = [
        NotMeasured(rule=o.rule_id, reason=_reason(o, ev.defaulted))
        for o in run.outcomes
        if o.state in _UNMEASURED and o.rule_id in manifest
        and manifest.get(o.rule_id).maturity == "required"
        and manifest.get(o.rule_id).score_effect != ScoreEffect.DIAGNOSTIC
    ]
    block = TechnicalReadiness(
        rating=res.rating, grade=res.grade,
        # D7: a passive rating never carries the verified/top badge
        badge=None if no_number or res.badge is None else "estimated",
        status=res.status, coverage=res.coverage, model_id=res.model_id,
        evidence_state=evidence_state, site_type=site_type, site_type_origin=origin,
        categories={name: TechnicalCategory(rating=c.score, applicable=c.applicable)
                    for name, c in sorted(res.categories.items())},
        not_measured=not_measured,
    )
    outcomes = [TechnicalOutcome(rule=o.rule_id, state=o.state.value,
                                 reason=_reason(o, ev.defaulted) if o.state in _UNMEASURED else o.reason,
                                 scope=manifest.get(o.rule_id).scope.value)
                for o in run.outcomes if o.rule_id in manifest]
    return Readiness(technical=block), outcomes
