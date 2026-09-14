"""The Core-vs-Cloud capability matrix, transcribed row-for-row from
`docs/core-vs-cloud.md`'s `## Capability matrix` table. The doc is the
source; this constant is its mirror — `tests/test_docs.py` pins them equal
(the doc's own `**…**` Markdown-bold markup on the sub-heading row is
normalized away for that comparison, since this constant carries the row's
plain text — HTML rendering applies its own `<strong>` instead).
If a row here is stale relative to the doc, fix the doc row, not this one."""
from __future__ import annotations

#: The boundary statement shared verbatim by README.md's `## Core vs Cloud`
#: section, docs/core-vs-cloud.md's opening line, and the HTML report's
#: Core-vs-Cloud footer — pinned byte-equal across all three by
#: `tests/test_docs.py::test_core_boundary_sentence_matches_readme_and_doc`.
CORE_BOUNDARY = (
    "Scovant Core measures passive, machine-facing signals. Scovant Cloud "
    "verifies how real agents actually behave, across providers, browser "
    "runtimes, security layers and time."
)

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
    ("Cloud = observed, reproducible, cross-provider, longitudinal", "—", "—"),
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
