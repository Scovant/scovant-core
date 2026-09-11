"""Search vs. training crawler identity tokens used by the CORE-ACCESS checks.

Deliberately independent from `parsers.robots._AI_AGENTS` (which extracts only
a fixed subset's per-agent directives during `parse_robots_txt`) — these
tuples list every crawler token an access check probes via `is_allowed`
against the parsed robots.txt text directly, not the narrower set
`parse_robots_txt` special-cases output for.
"""
from __future__ import annotations

SEARCH_CRAWLERS: tuple[str, ...] = ("OAI-SearchBot", "Claude-SearchBot", "PerplexityBot", "Googlebot", "Bingbot")
TRAINING_CRAWLERS: tuple[str, ...] = ("GPTBot", "ClaudeBot", "Google-Extended", "CCBot", "Applebot-Extended")
