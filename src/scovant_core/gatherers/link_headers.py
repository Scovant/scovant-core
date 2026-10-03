"""RFC 8288 `Link:` response-header probe."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_TIMEOUT, _transport_error

if TYPE_CHECKING:
    import httpx

# RFC 8288 link relations that advertise an agent-consumable machine
# interface: api-catalog (RFC 9727), service-desc / service-doc (RFC 8631).
_AGENT_RELEVANT_LINK_RELS = frozenset({"api-catalog", "service-desc", "service-doc"})


def check_link_headers(client: httpx.Client, domain: str) -> dict[str, Any]:
    """Homepage-only `Link:` response-header check (RFC 8288).

    Returns:
        {"present": bool,           # any Link header on the homepage response
         "rels": list[str],         # all relation types, lowercased, deduped
         "agent_relevant": bool,    # any rel in _AGENT_RELEVANT_LINK_RELS
         "fetch_status": "ok" | "error",  # "error": the homepage never answered
         "error": str | None}       # that transport failure, when there was one
    """
    result: dict[str, Any] = {"present": False, "rels": [], "agent_relevant": False,
                              "fetch_status": "ok", "error": None}
    try:
        resp = client.get(f"{domain}/", timeout=_PROBE_TIMEOUT)
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:
        return {**result, "fetch_status": "error", "error": _transport_error(exc)}
    try:
        links = resp.links  # httpx's RFC 8288 parser (handles quoted params)
        if not links:
            return result
        rels: list[str] = []
        for link in links.values():
            # rel is a whitespace-separated list of relation types (RFC 8288 §3.3)
            for rel in (link.get("rel") or "").lower().split():
                if rel not in rels:
                    rels.append(rel)
    except Exception:
        # an unparseable Link header: the site answered, nothing usable in it
        return {"present": False, "rels": [], "agent_relevant": False,
                "fetch_status": "ok", "error": None}
    result["present"] = True
    result["rels"] = rels
    result["agent_relevant"] = any(r in _AGENT_RELEVANT_LINK_RELS for r in rels)
    return result
