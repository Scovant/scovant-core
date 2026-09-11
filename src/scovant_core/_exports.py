"""Every public name that was relocated from Scovant Cloud into this package.

Used by the host's sync tripwires: each name must resolve here and must not
be re-defined in the host. Keep alphabetical.
"""
from __future__ import annotations

import importlib

MOVED_EXPORTS: tuple[str, ...] = (
    "AI_USER_AGENTS", "AiBot", "DISCOVERY_PROBES", "LOOKUP_BUDGET", "MAX_INTERNAL_LINKS",
    "MAX_REFERENCES", "PAYMENT_PROBES", "UnsafeURLError", "assert_safe_public_url",
    "check_agent_discovery", "check_agent_payments", "check_instruction_integrity",
    "check_link_headers", "check_machine_rep", "check_markdown_negotiation",
    "check_mcp_discovery", "check_sitemap", "check_ucp_profile", "classify_reference",
    "classify_tool_risk", "classify_ua", "detect_bot_protection", "detect_page_language",
    "extract_content_blocks", "extract_headings", "extract_internal_links",
    "extract_landmark_tags", "extract_metadata", "extract_og_meta", "extract_policy_links",
    "extract_product_data", "extract_references", "extract_schema_org",
    "extract_semantic_signals", "extract_visible_text", "find_injection_markers",
    "find_name_collisions", "find_obfuscation", "find_remote_exec_instructions",
    "has_spa_shell_marker", "is_allowed", "normalize_internal_url", "parse_content_signals",
    "parse_llms_txt", "parse_robots_txt", "probe_mcp_oauth_discovery", "probe_mcp_server_card",
    "ssrf_guard", "ssrf_guard_async", "tld_extractor",
)

_MODULES = (
    "scovant_core.security.url_safety", "scovant_core.security.tld",
    "scovant_core.registry.ai_bots", "scovant_core.parsers.robots",
    "scovant_core.parsers.content_signals", "scovant_core.parsers.llms_txt",
    "scovant_core.parsers.mcp", "scovant_core.parsers.ucp", "scovant_core.parsers.bot_protection",
    "scovant_core.parsers.html", "scovant_core.gatherers.probe_tables",
    "scovant_core.gatherers.sitemap", "scovant_core.gatherers.link_headers",
    "scovant_core.gatherers.markdown", "scovant_core.gatherers.machine_rep",
    "scovant_core.gatherers.agent_discovery", "scovant_core.gatherers.agent_payments",
    "scovant_core.gatherers.mcp_metadata", "scovant_core.gatherers.oauth",
    "scovant_core.analysis.integrity_probe", "scovant_core.analysis.instruction_integrity",
    "scovant_core.analysis.mcp_meta", "scovant_core.analysis.tool_risk",
)


def resolve(name: str):
    for mod in _MODULES:
        obj = getattr(importlib.import_module(mod), name, None)
        if obj is not None:
            return obj
    return None
