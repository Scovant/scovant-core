"""MCP server-card discovery probe."""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from scovant_core.compat import SoftTimeLimitExceeded
from scovant_core.parsers.mcp import _MCP_SERVER_CARD_PATHS, is_server_card, parse_ai_catalog
from scovant_core.security.url_safety import UnsafeURLError, assert_safe_public_url

from ._http import _PROBE_TIMEOUT, _json_answer, _probe_json, _ProbeClient, _transport_error

# Redirect hops the catalog/card probe follows itself. The host's crawl
# client may not follow redirects (Cloud's domain client does not), and a
# catalog behind `www.` or `https://` canonicalisation is common.
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def probe_mcp_server_card(client: _ProbeClient, domain: str) -> dict[str, Any]:
    """Probe both candidate server-card paths.

    Returns `{"exists": bool | None, "truncated": bool}`:

    - `exists=True` on a JSON object shaped like a server card
      (`is_server_card`) at EITHER path (a truncated read
      at the OTHER path doesn't change this — a confirmed positive beats an
      inconclusive read elsewhere).
    - `exists=False` only when EVERY path gave a definitive non-JSON/absent
      answer (no truncation anywhere in the sequence).
    - `exists=None` when no path confirmed presence AND at least one path's
      body was cut off at the fetch cap — "we could not tell", never a
      claimed absence. This replaces the previous plain `bool` return,
      which collapsed a truncated-but-possibly-present server card into the
      same `False` as a genuinely absent one.
    """
    any_truncated = False
    for path in _MCP_SERVER_CARD_PATHS:
        data, truncated = _probe_json(client, f"{domain}{path}")
        any_truncated = any_truncated or truncated
        if is_server_card(data):
            return {"exists": True, "truncated": truncated}
    return {"exists": None if any_truncated else False, "truncated": any_truncated}


def probe_ai_catalog(client: _ProbeClient, origin: str, *, max_cards: int = 3) -> dict[str, Any]:
    """GET `/.well-known/ai-catalog.json` and follow up to `max_cards` MCP
    server-card entries (cross-origin allowed, https + public hosts only).

    `fetch_status` is "error" when the catalog request never got a usable
    HTTP answer — no answer at all, a 429 or any 5xx; `status` records the
    catalog's HTTP status (`None` without an answer). A 404 or 403 is a real
    answer: "ok" with `valid` False. A followed card URL with no answer, a
    429 or a 5xx increments `card_fetch_errors`; unsafe/non-https URLs are
    skipped silently. A card body cut at the probe cap that did not parse
    as a card increments `cards_truncated`. Both GETs follow up to
    `_MAX_REDIRECTS` redirects themselves (https + public hosts per hop; an
    unsafe target is the site's answer, a chain that never ends is no
    answer). Hosts are checked structurally here (no DNS); the guarded probe
    client resolves and re-checks at connection time.
    """
    catalog_url = f"{origin}/.well-known/ai-catalog.json"
    data, truncated, error, status, catalog_url = _probe_json_following(client, catalog_url)
    unanswered = bool(error) or _unusable_status(status)
    out: dict[str, Any] = {
        "fetch_status": "error" if unanswered else "ok",
        "status": status,
        "valid": False,
        "card_entries": 0,
        "cards_found": 0,
        "card_fetch_errors": 0,
        "cards_truncated": 0,
        "truncated": truncated,
    }
    if unanswered:
        return out
    parsed = parse_ai_catalog(data)
    out["valid"] = parsed["valid"]
    out["card_entries"] = parsed["card_entries"]
    out["cards_found"] = parsed["inline_cards"]
    for raw in parsed["card_urls"][:max_cards]:
        url = urljoin(catalog_url, raw)
        try:
            assert_safe_public_url(url, require_https=True, resolve=False)
        except UnsafeURLError:
            continue
        card, card_truncated, card_error, card_status, _final = _probe_json_following(client, url)
        out["truncated"] = out["truncated"] or card_truncated
        if card_error or _unusable_status(card_status):
            out["card_fetch_errors"] += 1
        elif is_server_card(card):
            out["cards_found"] += 1
        elif card_truncated:
            # Cut at the probe cap before it parsed: whether it is a card is
            # unknown, so it can never stand for a measured absence.
            out["cards_truncated"] += 1
    return out


def _unusable_status(status: int | None) -> bool:
    """An answer that says nothing about the document: rate-limited or a
    server error. Absence cannot be read from it."""
    return status is not None and (status == 429 or status >= 500)


def _probe_json_following(
    client: _ProbeClient, url: str,
) -> tuple[Any, bool, str | None, int | None, str]:
    """`_probe_json_status` plus the final URL, following redirects hop by
    hop (relative URLs in the document resolve against the final URL). A
    redirect to a non-https or non-public URL stops there and returns the
    3xx status (a real answer that is not the document); more than
    `_MAX_REDIRECTS` hops or a 3xx without a Location is reported as a
    transport error."""
    for _hop in range(_MAX_REDIRECTS + 1):
        try:
            resp = client.get(url, timeout=_PROBE_TIMEOUT)
        except SoftTimeLimitExceeded:
            raise
        except Exception as exc:
            return None, False, _transport_error(exc), None, url
        if resp.status_code not in _REDIRECT_STATUSES:
            return (*_json_answer(resp), url)
        location = resp.headers.get("location")
        if not location:
            return None, False, "redirect without Location", None, url
        target = urljoin(url, location)
        try:
            assert_safe_public_url(target, require_https=True, resolve=False)
        except UnsafeURLError:
            return None, False, None, resp.status_code, url
        url = target
    return None, False, "too many redirects", None, url
