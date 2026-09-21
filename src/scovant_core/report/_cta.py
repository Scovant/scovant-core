"""The one call-to-action URL builder, shared by every report renderer
(text, JSON, HTML, MCP). `medium` records which surface printed the link
(product spec's utm_medium taxonomy) — nothing else about the caller.

`"docs"` is for a committed static document (e.g. `docs/example-report.md`)
that a reader may click from a docs page rather than a live CLI/Action/MCP
run — attributing it to `"cli"` (the `render_markdown` default) would
misreport the Core-to-Cloud funnel's per-medium breakdown.

`"claude-code"` is the Claude Code plugin's MCP server (set through the
`SCOVANT_CTA_MEDIUM` environment variable, see `mcp_server._medium`)."""
from __future__ import annotations

_MEDIA = frozenset({"cli", "github", "html", "mcp", "docs", "claude-code"})
CTA_TEXT = "Verify with real agents:"


def cta_url(medium: str) -> str:
    if medium not in _MEDIA:
        raise ValueError(f"unknown utm_medium {medium!r}")
    return f"https://scovant.com/scan?utm_source=scovant-core&utm_medium={medium}&utm_campaign=oss"
