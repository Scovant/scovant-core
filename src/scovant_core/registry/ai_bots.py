"""Canonical registry of AI crawler / agent user-agent tokens.

Each entry carries several independent axes: `kind` (retrieval vs training —
what the operator does with fetched content), `intent` (search / agent /
training — the policy class a site owner reasons about in robots.txt), and
`purpose` (search / user_fetch / training / content_use_control — the same
policy class the audit's crawler-purpose checks and `analysis.ai_policy`
group by). `classify_ua` matches longest token first so
`Applebot-Extended` beats `Applebot`.

This module is the ONE place a literal crawler token may appear anywhere
under `checks/`, `parsers/`, or `analysis/` (see
`tests/test_registry_derivation.py::test_no_literal_identity_outside_the_registry`)
— every identity list those modules use (`checks/access/_identities.py`,
`parsers/robots.py`'s `_AI_AGENTS`) is derived from `ALL_CRAWLERS`/`by_purpose`
below, never hand-copied.
"""
from __future__ import annotations

from dataclasses import dataclass

REGISTRY_VERSION = "2026.09.13"


@dataclass(frozen=True)
class AiBot:
    token: str      # UA substring (or robots.txt-only token — see identity_type)
    engine: str     # openai|anthropic|google|perplexity|apple|commoncrawl|duckduckgo|microsoft
    kind: str       # retrieval|training — inbound-telemetry axis (has a DB column + history)
    intent: str     # search|agent|training — the policy axis (search-index
                    # crawler vs live user-triggered fetch vs model-training). A token can be
                    # kind=retrieval AND intent=agent (e.g. ChatGPT-User) — the two axes
                    # answer different questions and must not be conflated.
    purpose: str = "search"                 # search|user_fetch|training|content_use_control
    identity_type: str = "user_agent"       # user_agent|robots_token (no UA of its own)
    official_source: str = ""
    last_reviewed: str = "2026-09-13"


AI_USER_AGENTS: tuple[AiBot, ...] = (
    AiBot("OAI-SearchBot", "openai", "retrieval", "search", "search", "user_agent",
          "https://platform.openai.com/docs/bots", "2026-09-13"),
    AiBot("ChatGPT-User", "openai", "retrieval", "agent", "user_fetch", "user_agent",
          "https://platform.openai.com/docs/bots", "2026-09-13"),
    AiBot("GPTBot", "openai", "training", "training", "training", "user_agent",
          "https://platform.openai.com/docs/bots", "2026-09-13"),
    AiBot("Claude-SearchBot", "anthropic", "retrieval", "search", "search", "user_agent",
          "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler", "2026-09-13"),
    AiBot("Claude-User", "anthropic", "retrieval", "agent", "user_fetch", "user_agent",
          "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler", "2026-09-13"),
    AiBot("ClaudeBot", "anthropic", "training", "training", "training", "user_agent",
          "https://support.anthropic.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler", "2026-09-13"),
    AiBot("PerplexityBot", "perplexity", "retrieval", "search", "search", "user_agent",
          "https://docs.perplexity.ai/guides/bots", "2026-09-13"),
    AiBot("Perplexity-User", "perplexity", "retrieval", "agent", "user_fetch", "user_agent",
          "https://docs.perplexity.ai/guides/bots", "2026-09-13"),
    AiBot("DuckAssistBot", "duckduckgo", "retrieval", "agent", "user_fetch", "user_agent",
          "https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot", "2026-09-13"),
    AiBot("Applebot", "apple", "retrieval", "search", "search", "user_agent",
          "https://support.apple.com/en-us/119829", "2026-09-13"),
    AiBot("Applebot-Extended", "apple", "training", "training", "training", "robots_token",
          "https://support.apple.com/en-us/119829", "2026-09-13"),
    AiBot("Google-Extended", "google", "training", "training", "content_use_control", "robots_token",
          "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers", "2026-09-13"),
    AiBot("CCBot", "commoncrawl", "training", "training", "training", "user_agent",
          "https://commoncrawl.org/ccbot", "2026-09-13"),
)

SEARCH_ENGINE_CRAWLERS: tuple[AiBot, ...] = (
    AiBot("Googlebot", "google", "retrieval", "search", "search", "user_agent",
          "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers",
          "2026-09-13"),
    AiBot("Bingbot", "microsoft", "retrieval", "search", "search", "user_agent",
          "https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0",
          "2026-09-13"),
)

ALL_CRAWLERS: tuple[AiBot, ...] = AI_USER_AGENTS + SEARCH_ENGINE_CRAWLERS

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


def by_purpose(purpose: str) -> tuple[str, ...]:
    return tuple(b.token for b in ALL_CRAWLERS if b.purpose == purpose)
