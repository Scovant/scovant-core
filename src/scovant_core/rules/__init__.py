"""Scovant Cloud rules published in Core, one contract (`CoreRule`)."""
from scovant_core.rules import (  # noqa: E402,F401  (registers the rules)
    agent_formats,
    consistency,
    crawl_graph,
    crawlability,
    discoverability,
    js_content,
    machine_rep,
    mcp,
    page_structure,
    product_terms,
    products,
    robots_policy,
    structured,
    token_bloat,
    ucp,
    webmcp,
)
from scovant_core.rules.base import (
    RULES,
    CoreRule,
    Finding,
    MeasureCtx,
    probe_measured,
    register_rule,
)

__all__ = ["RULES", "CoreRule", "Finding", "MeasureCtx", "probe_measured", "register_rule"]
