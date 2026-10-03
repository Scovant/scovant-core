"""Wave-2 rules published in Core: robots.txt crawler policy."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())
NM = OutcomeState.NOT_MEASURED
ROBOTS = {"general": {"allow": [], "disallow": []}, "sitemaps": [],
          "GPTBot": {"allow": [], "disallow": ["/"]},
          "ClaudeBot": {"allow": [], "disallow": ["/private"]},
          "PerplexityBot": {"allow": [], "disallow": ["/"]}}
POLICY = {"declared": {"GPTBot": {"allowed": False, "intent": "training"},
                       "OAI-SearchBot": {"allowed": False, "intent": "search"},
                       "ChatGPT-User": {"allowed": True, "intent": "agent"}},
          "declared_any": True, "observed": {}}


def _rule(code):
    return next(r for r in RULES if r.code == code)


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["AI_CRAWLER_BLOCKED"] == ("discoverability", "critical", "required", "domain")
    assert got["AI-BOT-POLICY-001"] == ("discoverability", "info", "required", "domain")


def test_ai_crawler_blocked_names_only_root_disallows():
    f, = _rule("AI_CRAWLER_BLOCKED").evaluate({}, {"robots": ROBOTS})
    assert f.description == "robots.txt disallows root path for: GPTBot, PerplexityBot."
    assert f.metadata == {"blocked_agents": ["GPTBot", "PerplexityBot"]}
    assert _rule("AI_CRAWLER_BLOCKED").evaluate({}, None) == []
    assert _rule("AI_CRAWLER_BLOCKED").evaluate({}, {"robots": {}}) == []


def test_declared_policy_groups_blocked_tokens_by_intent():
    f, = _rule("AI-BOT-POLICY-001").evaluate({}, {"ai_bot_policy": POLICY})
    assert f.example == "search: OAI-SearchBot\ntraining: GPTBot"
    assert f.metadata == {"blocked_tokens": ["GPTBot", "OAI-SearchBot"],
                          "blocked_by_intent": {"training": ["GPTBot"], "search": ["OAI-SearchBot"]},
                          "blocked_count": 2}
    assert _rule("AI-BOT-POLICY-001").evaluate({}, {"ai_bot_policy": {**POLICY, "declared_any": False}}) == []
    assert _rule("AI-BOT-POLICY-001").evaluate({}, {"ai_bot_policy": {**POLICY, "declared": {}}}) == []


def test_measure():
    ai, pol = _rule("AI_CRAWLER_BLOCKED"), _rule("AI-BOT-POLICY-001")
    both = {"robots": ROBOTS, "ai_bot_policy": POLICY}
    failed_robots = MeasureCtx(site_category=None, defaulted=frozenset({"robots"}))
    assert ai.measure({}, None, CTX) is NM
    assert ai.measure({}, both, CTX) is None
    assert ai.measure({}, both, failed_robots) is NM
    assert pol.measure({}, both, failed_robots) is NM      # the declared half is parsed from robots.txt
    assert pol.measure({}, {"ai_bot_policy": POLICY}, CTX) is NM
    assert pol.measure({}, both, CTX) is None
    assert pol.measure({}, {"robots": ROBOTS, "ai_bot_policy": {**POLICY, "declared_any": False}}, CTX) \
        is OutcomeState.NA
    assert pol.measure({}, {"robots": ROBOTS, "ai_bot_policy": {**POLICY, "declared": {}}}, CTX) is NM
