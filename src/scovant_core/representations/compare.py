"""Compare an agent-oriented representation (Markdown, `.md` mirror,
Prefer-consolidated) with the page's HTML. Pure, I/O-free.

Prices use Core's conservative matcher (`analysis.prices`): only `$ € £ ¥` and
a short list of ISO codes are recognised, so a page in another currency has no
recognised price and the price sub-check is not applicable, never a finding.
"""
from __future__ import annotations

import json
import math
import re
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from scovant_core.analysis.prices import (
    _CURRENCY_CODES,
    find_visible_prices,
    parse_price_value,
)

MAX_EXAMPLES = 5
LINK_PASS = 90.0
LINK_WARN = 70.0
ENTITY_PASS = 90.0
# Both sides are read in full for prices: `find_visible_prices`' default cap of
# 20 keeps each side's FIRST 20, and chrome removal on the HTML side shifts the
# order, so a price the Markdown does carry could read missing. A side that
# still reaches this limit was not read in full: the price sub-check is then
# not applicable rather than a verdict on a partial read.
PRICE_SCAN_LIMIT = 10_000

# JSON-LD prices are kept only in the currencies the visible-price matcher
# recognises (analysis/prices.py `_CURRENCY_CODES`), so both sides judge the
# same population: a price in any other currency is not applicable.
_MATCHED_CURRENCIES = frozenset(_CURRENCY_CODES.split("|"))
_CHROME_TAGS = ("nav", "header", "footer", "aside")
_MD_LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^)\s>]+)")
_MD_AUTOLINK = re.compile(r"<(https?://[^>\s]+)>|(?<![(\[<])\bhttps?://[^\s)\]>]+")
_MD_HEADING = re.compile(r"^#{1,3}[ \t]+(.+?)[ \t]*#*[ \t]*$", re.MULTILINE)


def _norm_url(href: str | None, base: str) -> str | None:
    if not href:
        return None
    h = href.strip()
    if not h or h.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    parts = urlsplit(urljoin(base, h))
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def _norm_text(s: str) -> str:
    return " ".join(re.sub(r"[^\w\s]", " ", s.lower()).split())


def _jsonld_walk(node: Any, names: set[str], prices: set[float]) -> None:
    if isinstance(node, list):
        for item in node:
            _jsonld_walk(item, names, prices)
        return
    if not isinstance(node, dict):
        return
    name = node.get("name")
    if isinstance(name, str) and name.strip():
        names.add(_norm_text(name))
    types = node.get("@type")
    types = types if isinstance(types, list) else [types]
    currency = node.get("priceCurrency")
    matched = isinstance(currency, str) and currency.strip().upper() in _MATCHED_CURRENCIES
    if matched and any(t in ("Offer", "AggregateOffer") for t in types):
        for key in ("price", "lowPrice"):
            v = parse_price_value(str(node.get(key))) if node.get(key) is not None else None
            if v is not None:
                prices.add(v)
    for value in node.values():
        if isinstance(value, (dict, list)):
            _jsonld_walk(value, names, prices)


def _visible_prices(text: str) -> tuple[set[float], bool]:
    """(prices, capped) — `capped` when the scan reached PRICE_SCAN_LIMIT."""
    found = find_visible_prices(text, limit=PRICE_SCAN_LIMIT)
    prices = {v for v in (parse_price_value(s) for s in found) if v is not None}
    return prices, len(found) >= PRICE_SCAN_LIMIT


def _attr(tag: Any, name: str) -> str | None:
    """A tag attribute as one string (BeautifulSoup may return a value list)."""
    value = tag.get(name)
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value) or None
    return None


def html_facts(html: str, page_url: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    names: set[str] = set()
    struct_prices: set[float] = set()
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            _jsonld_walk(json.loads(tag.string or ""), names, struct_prices)
        except (ValueError, TypeError):
            continue
    canonical = None
    for link in soup.find_all("link", href=True):
        if "canonical" in [r.lower() for r in link.get_attribute_list("rel")]:
            canonical = _norm_url(_attr(link, "href"), page_url)
            break
    for tag in soup.find_all(_CHROME_TAGS):
        tag.decompose()
    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        tag.decompose()
    headings = {_norm_text(h.get_text(" ")) for h in soup.find_all(["h1", "h2", "h3"])}
    links = {u for a in soup.find_all("a", href=True) if (u := _norm_url(_attr(a, "href"), page_url))}
    text = _norm_text(soup.get_text(" "))
    visible, capped = _visible_prices(soup.get_text(" "))
    return {
        "links": links,
        "entities": {e for e in names | headings if e},
        "prices": visible | struct_prices,
        "prices_capped": capped,
        "text": text,
        "bytes": len(html.encode("utf-8", errors="replace")),
        "canonical": canonical,
        "mentions": links,
    }


def markdown_facts(md: str, page_url: str) -> dict:
    raw_links = [m.group(1) for m in _MD_LINK.finditer(md)]
    raw_links += [m.group(1) or m.group(0) for m in _MD_AUTOLINK.finditer(md)]
    links = {u for u in (_norm_url(h, page_url) for h in raw_links) if u}
    headings = {_norm_text(h) for h in _MD_HEADING.findall(md)}
    prices, capped = _visible_prices(md)
    return {
        "links": links,
        "entities": {h for h in headings if h},
        "prices": prices,
        "prices_capped": capped,
        "text": _norm_text(md),
        "bytes": len(md.encode("utf-8", errors="replace")),
        "canonical": None,
        "mentions": links,
    }


def _coverage(base: set, present) -> tuple[float | None, list]:
    if not base:
        return None, []
    missing = sorted(x for x in base if not present(x))
    return round(100.0 * (len(base) - len(missing)) / len(base), 1), missing[:MAX_EXAMPLES]


def compare(base: dict, alt: dict, *, token_chars_ratio: int = 4) -> dict:
    link_pct, link_missing = _coverage(base["links"], lambda u: u in alt["links"])
    ent_pct, ent_missing = _coverage(
        base["entities"], lambda e: e in alt["entities"] or e in alt["text"])
    capped = bool(base.get("prices_capped") or alt.get("prices_capped"))
    applicable = bool(base["prices"]) and not capped
    missing_prices = sorted(base["prices"] - alt["prices"]) if applicable else []
    page = base["canonical"]
    attribution = bool(page) and (page in alt["mentions"] or page in alt["text"])
    ratio = max(int(token_chars_ratio), 1)
    return {
        "links": {"base_n": len(base["links"]), "alt_n": len(alt["links"]),
                  "covered_pct": link_pct, "missing_examples": link_missing},
        "entities": {"base_n": len(base["entities"]), "alt_n": len(alt["entities"]),
                     "covered_pct": ent_pct, "missing_examples": ent_missing},
        "prices": {"base": sorted(base["prices"])[:MAX_EXAMPLES],
                   "alt": sorted(alt["prices"])[:MAX_EXAMPLES],
                   "missing": missing_prices[:MAX_EXAMPLES], "applicable": applicable,
                   "capped": capped},
        "bytes": {"base": base["bytes"], "alt": alt["bytes"]},
        "bytes_ratio": round(alt["bytes"] / base["bytes"], 3) if base["bytes"] else None,
        "est_tokens": {"base": math.ceil(base["bytes"] / ratio), "alt": math.ceil(alt["bytes"] / ratio)},
        "attribution": attribution,
    }


def classify(compared: dict, *, content_type_ok: bool) -> str:
    links = compared["links"]["covered_pct"]
    ents = compared["entities"]["covered_pct"]
    if compared["prices"]["missing"] or (links is not None and links < LINK_WARN):
        return "FAIL"
    if (links is not None and links < LINK_PASS) or (ents is not None and ents < ENTITY_PASS) \
            or not content_type_ok:
        return "WARN"
    return "PASS"
