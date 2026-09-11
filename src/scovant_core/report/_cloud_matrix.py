"""The Core-vs-Cloud capability matrix, transcribed row-for-row from
`docs/core-vs-cloud.md`'s `## Capability matrix` table. The doc is the
source; this constant is its mirror — `tests/test_docs.py` pins them equal.
If a row here is stale relative to the doc, fix the doc row, not this one."""
from __future__ import annotations

CORE_VS_CLOUD: tuple[tuple[str, str, str], ...] = (
    ("HTTP reachability", "✅", "✅"),
    ("robots.txt", "✅", "✅"),
    ("Sitemap", "✅", "✅"),
    ("llms.txt", "✅", "✅"),
    ("Structured data (JSON-LD)", "✅", "✅"),
    ("Product/Offer data", "✅", "✅"),
    ("Static crawler policy", "✅", "✅"),
    ("Content-Signal", "✅", "✅"),
    ("MCP discovery", "✅", "✅"),
    ("WebMCP static presence", "✅", "✅"),
    ("OpenAPI presence", "✅", "✅"),
    ("OAuth authorization-server / protected-resource metadata", "✅", "✅"),
    ("UCP profile validity", "✅ (experimental)", "✅"),
    (
        "Agent discovery surface (A2A cards, AI-plugin, agents.json, Agent Skills)",
        "✅ (experimental)",
        "✅",
    ),
    ("Core Score", "✅", "—"),
    ("Cloud's full compatibility score", "❌", "✅"),
    ("Cloud's full production ruleset", "❌", "✅"),
    ("Observed WAF/bot-firewall behavior", "❌", "✅"),
    ("Real crawler network access", "❌", "✅"),
    ("Browser-based agent simulation", "❌", "✅"),
    ("Multi-model execution", "❌", "✅"),
    ("MCP tool invocation", "❌", "✅"),
    ("WebMCP tool execution/state parity", "❌", "✅"),
    ("Tool/UI parity checking", "❌", "✅"),
    ("Checkout/task completion", "❌", "✅"),
    ("CAPTCHA/challenge behavior", "❌", "✅"),
    ("Verified-agent access", "❌", "✅"),
    ("Failure attribution", "❌", "✅"),
    ("Temporal stability / regressions", "❌", "✅"),
    ("Scheduled monitoring", "❌", "✅"),
    ("Alerts/webhooks", "❌", "✅"),
    ("Hosted, shareable reports", "❌", "✅"),
    ("Contextual fix plan", "❌", "✅"),
)
