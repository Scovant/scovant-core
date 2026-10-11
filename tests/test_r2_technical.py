"""Technical Readiness manifest and outcome functions (moved from Scovant
Cloud byte for byte: the same evidence gives the same outcomes and model id)."""
from __future__ import annotations

import pytest

from scovant_core.r2 import PUBLIC_POLICY, Outcome, OutcomeState, RuleScope, ScoreEffect, model_id
from scovant_core.r2.technical import (
    ABSENCE_CODES,
    BUILDER_VERSION,
    DERIVATION_VERSION,
    GATE_ROBOTS,
    LOW_BAND_WARN_CODES,
    MARKER_CODES,
    derived_gate,
    domain_outcome,
    outcome_from_row,
    page_outcome,
    technical_manifest,
    technical_outcomes,
)
from scovant_core.rules import RULES

S = OutcomeState


def test_manifest_digest_and_model_id_are_the_published_ones():
    m = technical_manifest()
    assert m.digest() == "3d4902ab3793"
    assert model_id(m, PUBLIC_POLICY) == "R2.1@67df90af85b0"


def test_manifest_is_every_public_rule_plus_the_robots_gate():
    m = technical_manifest()
    ids = {s.rule_id for s in m.specs}
    assert ids == {r.code for r in RULES} | {GATE_ROBOTS}
    gate = m.get(GATE_ROBOTS)
    assert gate.score_effect == ScoreEffect.GATE and gate.root_cause_group == "agent_access_blocked"
    for code in MARKER_CODES:
        assert m.get(code).score_effect == ScoreEffect.DIAGNOSTIC
    for r in RULES:
        assert m.get(r.code).scope == RuleScope(r.scope)
        assert m.get(r.code).signal == f"core:{r.code}"


def test_versions_are_pinned():
    assert (BUILDER_VERSION, DERIVATION_VERSION) == ("5", "2")
    assert {"AI-BOT-POLICY-001", "WEBMCP-001", "TOOL-RISK-001"} == MARKER_CODES
    assert {"CITABILITY_WEAK", "PAGE_TOKEN_BLOAT"} == LOW_BAND_WARN_CODES
    assert "SITEMAP_MISSING_OR_INVALID" not in ABSENCE_CODES     # baseline hygiene, a defect
    assert "LLMS_TXT_MISSING_OR_INVALID" in ABSENCE_CODES


def test_domain_outcome_order_of_questions():
    assert domain_outcome("X", None, {}, fired=True, have_pages=True).state == S.UNKNOWN
    assert domain_outcome("X", lambda d: None, {}, fired=False, have_pages=False).state == S.NOT_MEASURED
    assert domain_outcome("X", lambda d: S.NA, {}, fired=True, have_pages=True).state == S.NA
    assert domain_outcome("X", lambda d: None, {}, fired=True, have_pages=True).state == S.FAIL
    assert domain_outcome("X", lambda d: None, {}, fired=False, have_pages=True).state == S.PASS


def test_page_outcome_counts_measured_pages_only():
    pages = [{"a": 1}, {"a": 2}, {"a": 3}]
    verdicts = {1: None, 2: S.NA, 3: None}
    o = page_outcome("X", lambda p, d: verdicts[p["a"]], pages, {}, [True, True, False], site_category="other")
    assert (o.state, o.pages_measured, o.pages_failed) == (S.FAIL, 2, 1)


def test_page_outcome_all_na_and_unknown_profile_reason():
    pages = [{}, {}]
    o = page_outcome("MISSING_PRODUCT_SCHEMA", lambda p, d: S.NA, pages, {}, [False, False], site_category="unknown")
    assert (o.state, o.reason) == (S.NA, "required_capability_not_established")
    o = page_outcome("SEMANTIC_HTML_ABSENT", lambda p, d: S.NA, pages, {}, [False, False], site_category="unknown")
    assert (o.state, o.reason) == (S.NA, "predicate")
    o = page_outcome("X", lambda p, d: S.NOT_MEASURED, [], {}, [], site_category="other")
    assert (o.state, o.reason) == (S.NOT_MEASURED, "no_pages_evaluated")


def test_outcome_from_row_absence_and_low_band():
    o = outcome_from_row({"rule_id": "LLMS_TXT_MISSING_OR_INVALID", "state": "FAIL"})
    assert (o.state, o.reason) == (S.NA, "capability_absent")
    o = outcome_from_row({"rule_id": "CITABILITY_WEAK", "state": "FAIL", "severity_seen": "low"})
    assert o.state == S.WARN
    o = outcome_from_row({"rule_id": "CITABILITY_WEAK", "state": "FAIL", "severity_seen": "medium"})
    assert o.state == S.FAIL
    o = outcome_from_row({"rule_id": "SITEMAP_MISSING_OR_INVALID", "state": "FAIL", "pages_measured": None})
    assert o.state == S.FAIL


def test_derived_gate_never_double_counts_missing_evidence():
    assert derived_gate("G", None).state == S.UNKNOWN
    assert derived_gate("G", Outcome(rule_id="AI_CRAWLER_BLOCKED", state=S.NOT_MEASURED)).state == S.NA
    assert derived_gate("G", Outcome(rule_id="AI_CRAWLER_BLOCKED", state=S.FAIL)).state == S.FAIL


def test_technical_outcomes_keeps_manifest_rules_and_adds_the_gate():
    m = technical_manifest()
    by_id = {"AI_CRAWLER_BLOCKED": Outcome(rule_id="AI_CRAWLER_BLOCKED", state=S.PASS),
             "NOT-A-RULE": Outcome(rule_id="NOT-A-RULE", state=S.FAIL)}
    out = {o.rule_id: o for o in technical_outcomes(by_id, m)}
    assert set(out) == {"AI_CRAWLER_BLOCKED", GATE_ROBOTS}
    assert out[GATE_ROBOTS].state == S.PASS and out[GATE_ROBOTS].reason == "from:AI_CRAWLER_BLOCKED"


# A page whose scored content was itself a wall (O2a). `bot_protection` alone
# (an agent-only refusal while the content fetch got the site) is not the signal.
BLOCKED = {"bot_protection": {"blocked": True, "protection_type": "cloudflare"}, "content_blocked": True}
AGENT_ONLY_REFUSAL = {"bot_protection": {"blocked": True, "protection_type": "cloudflare"}}


def _po(code, measure, pages, fired, *, skip=True, site_category="other"):
    return page_outcome(code, measure, pages, {}, fired, site_category=site_category, skip_content_blocked=skip)


def test_page_outcome_all_pages_walled_is_not_measured():
    o = _po("SEMANTIC_HTML_ABSENT", lambda p, d: None, [dict(BLOCKED), dict(BLOCKED)], [True, True])
    assert (o.state, o.reason, o.pages_measured) == (S.NOT_MEASURED, "bot_protection_blocked", None)


def test_page_outcome_without_the_skip_scores_walled_pages_as_before():
    """O2b: Agent Readiness keeps v4 semantics — the default never skips."""
    o = page_outcome("X", lambda p, d: None, [dict(BLOCKED), {"a": 1}], {}, [True, False], site_category="other")
    assert (o.state, o.pages_measured, o.pages_failed) == (S.FAIL, 2, 1)


def test_page_outcome_agent_only_refusal_is_never_skipped():
    o = _po("X", lambda p, d: None, [dict(AGENT_ONLY_REFUSAL), {"a": 1}], [True, False])
    assert (o.state, o.pages_measured, o.pages_failed) == (S.FAIL, 2, 1)


def test_page_outcome_na_over_the_clean_pages_stays_na():
    """One walled page must not turn a rule the clean pages establish as N/A
    into NOT_MEASURED (that would cut coverage for a single challenge page)."""
    pages = [dict(BLOCKED), {"a": 1}]
    o = _po("X", lambda p, d: S.NA if p.get("a") else None, pages, [True, False])
    assert (o.state, o.reason) == (S.NA, "predicate")
    o = _po("MISSING_PRODUCT_SCHEMA", lambda p, d: S.NA, pages, [False, False], site_category="unknown")
    assert (o.state, o.reason) == (S.NA, "required_capability_not_established")


def test_page_outcome_walled_and_unmeasured_pages_report_the_wall():
    o = _po("X", lambda p, d: S.NOT_MEASURED, [dict(BLOCKED), {"a": 1}], [False, False])
    assert (o.state, o.reason) == (S.NOT_MEASURED, "bot_protection_blocked")


def test_page_outcome_mixed_measures_clean_pages_only():
    pages = [dict(BLOCKED), {"a": 1}, {"a": 2}]
    o = _po("X", lambda p, d: None, pages, [True, False, False])
    assert (o.state, o.pages_measured, o.pages_failed) == (S.PASS, 2, 0)
    o = _po("X", lambda p, d: None, pages, [True, True, False])
    assert (o.state, o.pages_measured, o.pages_failed) == (S.FAIL, 2, 1)


def test_page_outcome_bot_protection_rule_is_never_skipped():
    seen = []

    def measure(p, d):
        seen.append(p)
        return None

    o = _po("BOT_PROTECTION_BLOCKING_AGENTS", measure, [dict(BLOCKED), dict(BLOCKED)], [True, True])
    assert (o.state, o.pages_measured, o.pages_failed) == (S.FAIL, 2, 2)
    assert len(seen) == 2


def test_page_outcome_walled_page_is_not_passed_to_measure():
    seen = []
    _po("X", lambda p, d: seen.append(p), [dict(BLOCKED), {"a": 1}], [False, False])
    assert seen == [{"a": 1}]


def test_technical_readiness_skips_content_walled_pages(monkeypatch):
    from scovant_core.r2 import evaluate

    calls = []
    real = evaluate.page_outcome

    def spy(*a, **k):
        calls.append(k.get("skip_content_blocked"))
        return real(*a, **k)

    monkeypatch.setattr(evaluate, "page_outcome", spy)
    clean = {"_http_status": 200, "visible_text": "hello world", "headings": []}
    walled = {**clean, **BLOCKED}
    alone = {o.rule_id: o for o in evaluate.technical_readiness([clean], None, site_type="other",
                                                                defaulted=None).outcomes}
    mixed = {o.rule_id: o for o in evaluate.technical_readiness([clean, walled], None, site_type="other",
                                                                defaulted=None).outcomes}
    only = {o.rule_id: o for o in evaluate.technical_readiness([walled], None, site_type="other",
                                                               defaulted=None).outcomes}
    assert calls and all(c is True for c in calls)
    assert alone["HEADING_HIERARCHY_POOR"].state == S.NA
    assert mixed["HEADING_HIERARCHY_POOR"] == alone["HEADING_HIERARCHY_POOR"]   # the wall changed nothing
    assert (only["HEADING_HIERARCHY_POOR"].state, only["HEADING_HIERARCHY_POOR"].reason) == (
        S.NOT_MEASURED, "bot_protection_blocked")


def test_page_outcome_unequal_lengths_raise():
    with pytest.raises(ValueError):
        page_outcome("X", lambda p, d: None, [{}, {}], {}, [False], site_category="other")


def test_manifest_excludes_deprecated_rules(monkeypatch):
    victim = next(r for r in RULES if r.scope == "page")
    monkeypatch.setattr(victim, "maturity", "deprecated")
    assert victim.code not in {s.rule_id for s in technical_manifest().specs}
