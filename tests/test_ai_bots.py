from scovant_core.registry.ai_bots import AI_USER_AGENTS, classify_ua


def test_classify_ua_matches_each_known_bot():
    for bot in AI_USER_AGENTS:
        ua = f"Mozilla/5.0 (compatible; {bot.token}/1.0; +http://example.com/bot)"
        got = classify_ua(ua)
        assert got is not None and got.token == bot.token


def test_classify_ua_longest_match_wins_applebot_extended():
    got = classify_ua("Mozilla/5.0 (compatible; Applebot-Extended/1.0)")
    assert got is not None and got.token == "Applebot-Extended"


def test_classify_ua_plain_browser_and_none():
    assert classify_ua("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0") is None
    assert classify_ua(None) is None
    assert classify_ua("") is None


def test_every_bot_has_a_valid_intent():
    # The 3-way policy axis, distinct from `kind` (retrieval|training, which
    # drives inbound telemetry and has a DB column downstream).
    for bot in AI_USER_AGENTS:
        assert bot.intent in {"search", "agent", "training"}, bot.token


def test_intent_axis_specific_mappings():
    by_token = {b.token: b for b in AI_USER_AGENTS}
    assert by_token["OAI-SearchBot"].intent == "search"
    assert by_token["ChatGPT-User"].intent == "agent"
    assert by_token["GPTBot"].intent == "training"
    assert by_token["Claude-User"].intent == "agent"
    assert by_token["PerplexityBot"].intent == "search"
    assert by_token["CCBot"].intent == "training"


def test_kind_axis_unchanged():
    # kind must stay the shipped 2-way vocabulary — telemetry + DB history.
    for bot in AI_USER_AGENTS:
        assert bot.kind in {"retrieval", "training"}, bot.token
