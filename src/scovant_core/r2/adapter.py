"""The CLI's gathered evidence as the documents the public rules read
(`scovant_core.rules.evidence`).

Every document is produced by Core's own gatherers: a gatherer that raised,
or a fetch that never got an answer, names its probe in `defaulted`, and
every rule reading that probe is NOT_MEASURED — never a PASS or a FAIL.
Core never performs an MCP handshake, so the handshake half of the MCP rules
is NOT_MEASURED whenever an endpoint is declared.
"""
from __future__ import annotations

from dataclasses import dataclass

from scovant_core.profiles import LOW_CONFIDENCE
from scovant_core.rules.citability import CITABILITY_TYPES
from scovant_core.rules.products import UNKNOWN_SITE_TYPE
from scovant_core.rules.token_bloat import LOW_TOKENS_DEFAULT, MEDIUM_TOKENS_DEFAULT
from scovant_core.rules.ucp import UCP_APPLICABLE_SITE_TYPES

SITE_TYPES: frozenset[str] = frozenset(UCP_APPLICABLE_SITE_TYPES | CITABILITY_TYPES | {UNKNOWN_SITE_TYPE})
_PROFILE_SITE_TYPE = {"commerce": "commerce", "saas": "saas", "api": "saas", "content": "other"}
_EMPTY_SITEMAP = {"exists": False, "valid": False, "url": None, "kind": None}
_EMPTY_DISCOVERY = {"any_found": False, "surfaces": {}}
_SITEMAP_KEYS = ("exists", "valid", "url", "kind", "fetch_status", "error")
_UCP_GATHERER_KEYS = ("status", "served_as_html", "truncated", "text", "retry_after")
_MCP_GATHERER_KEYS = ("text", "servers")
_DISCOVERY_GATHERER_KEYS = ("documents",)


def site_type_for(profile: str, confidence: float, override: str | None) -> tuple[str, str]:
    """(site_type, origin): the `--site-type` flag wins; a confident Core
    profile maps to an R2 site type; anything else is `unknown`."""
    if override:
        return override, "flag"
    if confidence < LOW_CONFIDENCE or profile not in _PROFILE_SITE_TYPE:
        return UNKNOWN_SITE_TYPE, "unknown"
    return _PROFILE_SITE_TYPE[profile], "detected"


@dataclass(frozen=True)
class ScanEvidence:
    pages: list[dict]
    domain: dict
    defaulted: frozenset[str]


def _robots_unusable(robots: dict) -> bool:
    """robots.txt that did not produce a usable document: no answer, a 5xx or
    429 (RFC 9309: the site's policy is unknown, not allow-all), or a body cut
    at the fetch cap. A 404/410 is a real "no robots.txt" and stays measured."""
    status = robots.get("status")
    return status is None or status >= 500 or status == 429 or bool(robots.get("truncated"))


def _without(record: dict, keys: tuple[str, ...]) -> dict:
    return {k: v for k, v in record.items() if k not in keys}


def evidence_from_store(store, *, site_type: str) -> ScanEvidence:
    from scovant_core.parsers.content_signals import parse_content_signals  # noqa: PLC0415
    from scovant_core.parsers.llms_txt import parse_llms_txt  # noqa: PLC0415
    from scovant_core.parsers.mcp import check_mcp_discovery  # noqa: PLC0415
    from scovant_core.parsers.robots import parse_robots_txt  # noqa: PLC0415
    from scovant_core.parsers.ucp import check_ucp_profile  # noqa: PLC0415

    defaulted: set[str] = set()
    domain: dict = {}

    robots = store.try_get("robots_txt")
    if robots is None or _robots_unusable(robots):
        defaulted |= {"robots", "content_signals"}
        domain["robots"], domain["content_signals"] = parse_robots_txt(""), parse_content_signals("")
    else:
        domain["robots"], domain["content_signals"] = robots["parsed"], robots["content_signals"]

    sitemap = store.try_get("sitemap_urls")
    if sitemap is None:
        defaulted.add("sitemap")
        domain["sitemap"] = dict(_EMPTY_SITEMAP)
    else:
        domain["sitemap"] = {k: sitemap[k] for k in _SITEMAP_KEYS if k in sitemap}

    llms = store.try_get("llms")
    if llms is None or llms.get("status") is None:
        defaulted.add("llms_txt")
        domain["llms_txt"] = parse_llms_txt("", 0)
    else:
        domain["llms_txt"] = llms["parsed"]

    ucp = store.try_get("ucp")
    if ucp is None or ucp.get("status") is None:
        defaulted.add("ucp")
        domain["ucp"] = check_ucp_profile(None, 0)
    else:
        domain["ucp"] = _without(ucp, _UCP_GATHERER_KEYS)

    mcp = store.try_get("mcp_discovery")
    if mcp is None or mcp.get("status") is None:
        defaulted.add("mcp")
        domain["mcp"] = check_mcp_discovery(None, 0)
    else:
        domain["mcp"] = _without(mcp["discovery"], _MCP_GATHERER_KEYS)

    discovery = store.try_get("agent_discovery_surface")
    if discovery is None:
        defaulted.add("agent_discovery")
        domain["agent_discovery"] = dict(_EMPTY_DISCOVERY)
    else:
        domain["agent_discovery"] = _without(discovery, _DISCOVERY_GATHERER_KEYS)

    gathered = store.try_get("pages") or {}
    pages = [{**p["parsed"], "_http_status": p.get("status")}
             for p in gathered.get("pages", []) if p.get("parsed")]

    domain["site_type"] = site_type
    domain["pages_scored"] = len(pages)
    if site_type in CITABILITY_TYPES:
        domain["content_pages_scored"] = sum(1 for p in pages if p.get("content_blocks"))
    domain["token_bloat_settings"] = {
        "enabled": True, "low": LOW_TOKENS_DEFAULT, "medium": MEDIUM_TOKENS_DEFAULT}
    return ScanEvidence(pages=pages, domain=domain, defaulted=frozenset(defaulted))
