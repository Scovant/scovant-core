"""Canonical registry of AI crawler / agent user-agent tokens.

Each entry carries two independent axes: `kind` (retrieval vs training —
what the operator does with fetched content) and `intent` (search / agent /
training — the policy class a site owner reasons about in robots.txt).
`classify_ua` matches longest token first so `Applebot-Extended` beats
`Applebot`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AiBot:
    token: str      # UA substring
    engine: str     # openai|anthropic|google|perplexity|apple|commoncrawl|duckduckgo
    kind: str       # retrieval|training — inbound-telemetry axis (has a DB column + history)
    intent: str     # search|agent|training — the policy axis (search-index
                    # crawler vs live user-triggered fetch vs model-training). A token can be
                    # kind=retrieval AND intent=agent (e.g. ChatGPT-User) — the two axes
                    # answer different questions and must not be conflated.


AI_USER_AGENTS: tuple[AiBot, ...] = (
    AiBot("OAI-SearchBot", "openai", "retrieval", "search"),
    AiBot("ChatGPT-User", "openai", "retrieval", "agent"),
    AiBot("GPTBot", "openai", "training", "training"),
    AiBot("Claude-SearchBot", "anthropic", "retrieval", "search"),
    AiBot("Claude-User", "anthropic", "retrieval", "agent"),
    AiBot("ClaudeBot", "anthropic", "training", "training"),
    AiBot("PerplexityBot", "perplexity", "retrieval", "search"),
    AiBot("Perplexity-User", "perplexity", "retrieval", "agent"),
    AiBot("DuckAssistBot", "duckduckgo", "retrieval", "agent"),
    AiBot("Applebot", "apple", "retrieval", "search"),
    AiBot("Applebot-Extended", "apple", "training", "training"),
    AiBot("Google-Extended", "google", "training", "training"),
    AiBot("CCBot", "commoncrawl", "training", "training"),
)

# longest token first so "Applebot-Extended" wins over "Applebot"
_UA_BY_LEN: tuple[AiBot, ...] = tuple(
    sorted(AI_USER_AGENTS, key=lambda b: len(b.token), reverse=True)
)


def classify_ua(ua: str | None) -> AiBot | None:
    if not ua:
        return None
    low = ua.lower()
    for bot in _UA_BY_LEN:
        if bot.token.lower() in low:
            return bot
    return None
