"""Technical Readiness over one scan's evidence."""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.r2.evaluate import rule_rows, technical_readiness
from scovant_core.r2.technical import GATE_ROBOTS
from scovant_core.rules import RULES

S = OutcomeState


def _robots(disallow_gptbot: bool) -> dict:
    from scovant_core.parsers.robots import parse_robots_txt
    text = "User-agent: GPTBot\nDisallow: /\n" if disallow_gptbot else "User-agent: *\nAllow: /\n"
    return parse_robots_txt(text)


def test_no_evidence_is_insufficient_never_a_number():
    run = technical_readiness([], None, site_type="other", defaulted=None)
    assert run.result.rating is None and run.result.status == "INSUFFICIENT_EVIDENCE"
    assert all(o.state in (S.NOT_MEASURED, S.UNKNOWN, S.NA) for o in run.outcomes)


def test_rule_rows_cover_every_public_rule_once():
    rows = rule_rows([{}], {}, site_category="other", defaulted=None)
    assert [r["rule_id"] for r in rows] == sorted(r.code for r in RULES if r.maturity != "deprecated")


def test_robots_block_fires_the_gate():
    domain = {"robots": _robots(True), "site_type": "other", "pages_scored": 1}
    run = technical_readiness([{"visible_text": "x"}], domain, site_type="other", defaulted=None)
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["AI_CRAWLER_BLOCKED"].state == S.FAIL
    assert by_id[GATE_ROBOTS].state == S.FAIL


def test_defaulted_robots_is_not_measured_and_the_gate_is_na():
    domain = {"robots": _robots(False), "site_type": "other", "pages_scored": 1}
    run = technical_readiness([{"visible_text": "x"}], domain, site_type="other",
                              defaulted=frozenset({"robots", "content_signals"}))
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["AI_CRAWLER_BLOCKED"].state == S.NOT_MEASURED
    assert by_id[GATE_ROBOTS].state == S.NA


def test_evaluate_does_not_see_http_status_but_measure_does():
    page = {"metadata": {"robots_meta": None}, "visible_text": "x", "_http_status": 404}
    rows = {r["rule_id"]: r for r in rule_rows([page], {}, site_category="other", defaulted=None)}
    assert rows["BLOCKED_CRAWLABILITY"]["state"] == "NOT_MEASURED"
