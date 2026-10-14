"""Technical Readiness: which public rules feed it, and how one scan's rule
verdicts become R2 outcomes.

The manifest is every rule in `scovant_core.rules` plus one synthetic gate
(robots.txt blocks AI crawlers). Any host that evaluates the same rules on
the same evidence through these functions gets the same outcomes and the same
model id (`model_id(technical_manifest(), PUBLIC_POLICY)`).

`scovant_core.rules` imports this package, so the rule registry is imported
inside the functions that need it, never at module level.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from scovant_core.capabilities import Capabilities, gate
from scovant_core.models import Severity
from scovant_core.r2.manifest import Manifest, RuleScope, RuleSpec, ScoreEffect
from scovant_core.r2.outcome import Outcome, OutcomeState, R2Category

# A missing optional agent capability is not a readiness defect: absent is
# N/A (the category drops out when nothing else was measured), present is a
# counted PASS. A sitemap stays a defect: baseline hygiene, not a capability.
ABSENCE_CODES: frozenset[str] = frozenset({
    "LLMS_TXT_MISSING_OR_INVALID", "MARKDOWN_FOR_AGENTS_ABSENT", "LINK_HEADERS_ABSENT",
    "CONTENT_SIGNALS_ABSENT", "UCP_PROFILE_ABSENT", "MCP_ENDPOINT_ABSENT",
    "AGENT_INTERFACE_DISCOVERY_ABSENT", "AGENT_PAYMENTS_ABSENT",
})
# Rules whose severity is a band chosen per finding: a finding in the lowest
# band is partial (WARN), not a full failure.
LOW_BAND_WARN_CODES: frozenset[str] = frozenset({"CITABILITY_WEAK", "PAGE_TOKEN_BLOAT"})
# Rules kept out of R2 because their evidence can never be produced. Empty;
# kept so the manifest's shape and model id do not change with it.
DEAD_IN_PRODUCTION: frozenset[str] = frozenset()
# Bump when the derivation below changes meaning (it is part of a host's inputs digest).
DERIVATION_VERSION = "2"
# Version of the outcome rules in `domain_outcome`/`page_outcome`.
# 5: a page whose scored content was a bot-protection wall (`content_blocked`)
#    is not measured for Technical Readiness
# 6: gated rules follow capability flags (reasons `capability_absent:<flag>` /
#    `capability_not_established:<flag>`)
BUILDER_VERSION = "6"
# Public rules whose finding is an informational marker, not a defect.
MARKER_CODES: frozenset[str] = frozenset({"AI-BOT-POLICY-001", "WEBMCP-001", "TOOL-RISK-001"})

# The one page rule that reads the bot-protection wall itself; it is never
# skipped. Under `skip_content_blocked` every other page rule skips a page whose
# scored content was a wall (it saw a challenge, not the site).
BOT_PROTECTION_RULE = "BOT_PROTECTION_BLOCKING_AGENTS"
# Page key a host sets when the fetch that produced the page's scored content
# was itself blocked. A refusal of another fetch (e.g. an agent identity)
# while the content fetch got the site is NOT this signal.
CONTENT_BLOCKED_KEY = "content_blocked"

GATE_ROBOTS = "R2-GATE-ROBOTS-BLOCKS-AGENTS"
GATE_ROBOTS_SPEC = RuleSpec(
    rule_id=GATE_ROBOTS, signal="gate:robots_blocks_ai_crawlers", category=R2Category.DISCOVERABILITY,
    severity=Severity.CRITICAL, scope=RuleScope.DOMAIN, score_effect=ScoreEffect.GATE,
    root_cause_group="agent_access_blocked")

Verdict = OutcomeState | None
_MEASURED = (OutcomeState.PASS, OutcomeState.WARN, OutcomeState.FAIL)


def rule_spec(rule: Any, *, owner: str, scope: RuleScope, marker: bool) -> RuleSpec:
    """The manifest entry for one rule (`owner` is the signal's owner, e.g. "core")."""
    return RuleSpec(
        rule_id=rule.code, signal=f"{owner}:{rule.code}", category=rule.category,
        severity=Severity(rule.severity), scope=scope,
        score_effect=ScoreEffect.DIAGNOSTIC if marker else ScoreEffect.WEIGHTED,
        maturity="required" if rule.maturity == "required" else "experimental",
        rule_version=rule.rule_version,
    )


def technical_manifest() -> Manifest:
    from scovant_core.rules import RULES  # noqa: PLC0415 (rules import this package)
    from scovant_core.rules.products import PROFILE_POLICY_ID  # noqa: PLC0415

    return Manifest(
        [rule_spec(r, owner="core", scope=RuleScope(r.scope), marker=r.code in MARKER_CODES)
         for r in RULES if r.code not in DEAD_IN_PRODUCTION and r.maturity != "deprecated"]
        + [GATE_ROBOTS_SPEC], applicability=PROFILE_POLICY_ID)


def domain_outcome(code: str, measure: Callable[[dict | None], Verdict] | None,
                   domain: dict | None, *, fired: bool, have_pages: bool,
                   caps: Capabilities | None = None) -> Outcome:
    """A domain rule's outcome: no declaration → UNKNOWN; no page evaluated →
    NOT_MEASURED; the rule's own verdict when it gives one; else FAIL iff it fired."""
    if measure is None:
        return Outcome(rule_id=code, state=OutcomeState.UNKNOWN, reason="no_declaration")
    hit = gate(code, caps)
    if hit is not None:
        return Outcome(rule_id=code, state=hit[0], reason=hit[1])
    if not have_pages:
        return Outcome(rule_id=code, state=OutcomeState.NOT_MEASURED, reason="no_pages_evaluated")
    verdict = measure(domain)
    if verdict is not None:
        return Outcome(rule_id=code, state=verdict, reason="predicate")
    return Outcome(rule_id=code, state=OutcomeState.FAIL if fired else OutcomeState.PASS)


def content_blocked(page: dict) -> bool:
    return page.get(CONTENT_BLOCKED_KEY) is True


def page_outcome(code: str, measure: Callable[[dict, dict | None], Verdict] | None,
                 pages: Sequence[dict], domain: dict | None, fired_per_page: Sequence[bool],
                 *, site_category: str | None, skip_content_blocked: bool = False,
                 caps: Capabilities | None = None) -> Outcome:
    """A page rule's outcome over the sampled pages: FAIL iff a MEASURED page failed.

    With `skip_content_blocked` (Technical Readiness), a page whose scored
    content was a wall (`content_blocked`) is not measured for any rule but the
    one that reads the wall: its evidence is a challenge page, not the site.
    Without it (Agent Readiness) every page is scored as before."""
    if measure is None:
        return Outcome(rule_id=code, state=OutcomeState.UNKNOWN, reason="no_declaration")
    hit = gate(code, caps)
    if hit is not None:
        return Outcome(rule_id=code, state=hit[0], reason=hit[1])
    measured = failed = na = blocked = 0
    for page, fired in zip(pages, fired_per_page, strict=True):
        page = page or {}
        if skip_content_blocked and code != BOT_PROTECTION_RULE and content_blocked(page):
            blocked += 1
            continue
        verdict = measure(page, domain)
        if verdict is None:
            measured += 1
            failed += bool(fired)
        elif verdict == OutcomeState.NA:
            na += 1
    if measured:
        state = OutcomeState.FAIL if failed else OutcomeState.PASS
        return Outcome(rule_id=code, state=state, pages_measured=measured, pages_failed=failed)
    if na and na == len(pages) - blocked:  # N/A on every page that was not walled
        return Outcome(rule_id=code, state=OutcomeState.NA, reason="predicate")
    if blocked:
        return Outcome(rule_id=code, state=OutcomeState.NOT_MEASURED, reason="bot_protection_blocked")
    return Outcome(rule_id=code, state=OutcomeState.NOT_MEASURED,
                   reason="predicate" if pages else "no_pages_evaluated")


def outcome_from_row(row: dict) -> Outcome:
    """An outcome row (`rule_id`, `state`, optional `pages_measured`,
    `pages_failed`, `evidence_key`, `reason`, `severity_seen`) as the
    Outcome Technical Readiness scores."""
    state = OutcomeState(row["state"])
    if row["rule_id"] in ABSENCE_CODES and state in (OutcomeState.FAIL, OutcomeState.WARN):
        return Outcome(rule_id=row["rule_id"], state=OutcomeState.NA, reason="capability_absent")
    if state == OutcomeState.FAIL and row["rule_id"] in LOW_BAND_WARN_CODES \
            and row.get("severity_seen") == "low":
        state = OutcomeState.WARN
    return Outcome(rule_id=row["rule_id"], state=state,
                   pages_measured=row.get("pages_measured"), pages_failed=row.get("pages_failed"),
                   evidence_key=row.get("evidence_key") or "", reason=row.get("reason") or "")


def derived_gate(rule_id: str, source: Outcome | None) -> Outcome:
    """A gate over a rule's verdict. A gate has no evidence of its own: when
    its source was not measured the gate is N/A, so missing evidence lowers
    coverage once (through the source), never twice."""
    if source is None:
        return Outcome(rule_id=rule_id, state=OutcomeState.UNKNOWN, reason="source_missing")
    state = source.state if source.state in _MEASURED else OutcomeState.NA
    return Outcome(rule_id=rule_id, state=state, reason=f"from:{source.rule_id}")


def technical_outcomes(by_id: dict[str, Outcome], manifest: Manifest) -> list[Outcome]:
    """The Technical outcome list: every outcome the manifest knows, plus the robots gate."""
    return [o for rid, o in by_id.items() if rid in manifest] + [
        derived_gate(GATE_ROBOTS, by_id.get("AI_CRAWLER_BLOCKED"))]
