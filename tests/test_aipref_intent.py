"""AIPREF `__usage_ai-training` group and the OAI-AdsBot intent: unscored declarations."""
from scovant_core.parsers.content_signals import parse_content_signals
from scovant_core.parsers.robots import is_allowed, parse_ai_training_usage, parse_robots_txt
from scovant_core.r2 import OutcomeState
from scovant_core.registry.ai_bots import AI_USER_AGENTS
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())


def _rule():
    return next(r for r in RULES if r.code == "AI-BOT-POLICY-006")


def _domain(robots_txt: str) -> dict:
    declared = {
        b.token: {"allowed": is_allowed(robots_txt, b.token, "/"), "intent": b.intent, "engine": b.engine}
        for b in AI_USER_AGENTS
    }
    return {
        "robots": parse_robots_txt(robots_txt),
        "content_signals": parse_content_signals(robots_txt),
        "ai_bot_policy": {"declared": declared, "declared_any": True,
                          "ai_training_usage": parse_ai_training_usage(robots_txt)},
    }


USAGE_NO = "User-agent: __usage_ai-training\nDisallow: /\n"


def test_usage_group_is_a_separate_declared_intent():
    assert parse_ai_training_usage(USAGE_NO) == {"declared": True, "allowed": False, "draft": True}
    assert parse_ai_training_usage("User-agent: __usage_ai-training\nAllow: /\n")["allowed"] is True
    d = _domain(USAGE_NO)
    assert all(v["allowed"] for v in d["ai_bot_policy"]["declared"].values())  # no vendor token changes


def test_vendor_group_precedence_over_usage_group():
    txt = USAGE_NO + "\nUser-agent: GPTBot\nAllow: /\n"
    d = _domain(txt)
    assert d["ai_bot_policy"]["declared"]["GPTBot"]["allowed"] is True
    assert d["ai_bot_policy"]["ai_training_usage"]["allowed"] is False


def test_conflict_with_google_extended_fires_006():
    txt = USAGE_NO + "\nUser-agent: Google-Extended\nAllow: /\n"
    f, = _rule().evaluate({}, _domain(txt))
    assert f.metadata["conflicting_sources"] == ["Google-Extended robots group"]
    assert f.metadata["draft"] is True


def test_conflict_with_content_signal_names_both_sources():
    txt = USAGE_NO + "\nUser-agent: *\nContent-Signal: ai-train=yes\nAllow: /\n"
    f, = _rule().evaluate({}, _domain(txt))
    assert f.metadata["conflicting_sources"] == ["Content-Signal ai-train"]


def test_agreement_and_inheritance_are_silent():
    assert _rule().evaluate({}, _domain(USAGE_NO + "\nUser-agent: Google-Extended\nDisallow: /\n")) == []
    # Google-Extended merely inheriting "*" is not a declaration to contradict
    assert _rule().evaluate({}, _domain(USAGE_NO + "\nUser-agent: *\nAllow: /\n")) == []


def test_no_usage_group_is_silent():
    d = _domain("User-agent: *\nAllow: /\n")
    assert parse_ai_training_usage("User-agent: *\nAllow: /\n") == {"declared": False, "allowed": None, "draft": True}
    assert _rule().evaluate({}, d) == []
    assert _rule().measure({}, d, CTX) is OutcomeState.NA
    assert _rule().measure({}, _domain(USAGE_NO), CTX) is None
    assert _rule().measure({}, {"robots": {}}, CTX) is OutcomeState.NOT_MEASURED


def test_contract():
    r = _rule()
    assert (r.category, r.severity, r.maturity, r.scope, r.since) == (
        "discoverability", "info", "experimental", "domain", "0.25.0")


def test_oai_adsbot_is_its_own_intent():
    bot = next(b for b in AI_USER_AGENTS if b.token == "OAI-AdsBot")
    assert (bot.engine, bot.kind, bot.intent, bot.purpose) == (
        "openai", "retrieval", "commercial_validation", "commercial_validation")
