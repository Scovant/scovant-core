"""Product and Offer evidence helpers shared by the structured-data and
consistency rules, and the commerce gate.

`schema_org` is the list of JSON-LD / Microdata entities extracted from a
page (`parsers.html.extract_schema_org`, which already lifts a top-level
`@graph` into the list). A Product is an entity whose `@type` is exactly
the string "Product".
"""
from __future__ import annotations

import re
from typing import Any

# Site types that never transact: the commerce-gated rules do not apply on
# them, so a scan of such a site measures nothing for those rules.
NON_TRANSACTING_SITE_TYPES: frozenset[str] = frozenset({
    "blog", "news", "docs", "documentation", "media", "portfolio", "saas", "education",
    "real_estate",
})
# Rules published in Core that only apply to a site that may transact.
COMMERCE_GATED_CODES: frozenset[str] = frozenset({
    "MISSING_PRODUCT_SCHEMA", "MISSING_OFFER_DATA", "PRICE_MISSING_INVALID",
    "MISSING_AVAILABILITY", "VARIANT_INFO_MISSING", "PRICE_MISMATCH",
    "MISSING_RETURNS_POLICY", "SHIPPING_INFO_UNAVAILABLE",
})
# Words in a product page's visible text that suggest it offers variants.
VARIANT_KEYWORDS: frozenset[str] = frozenset({"size", "color", "colour", "variant", "style", "material"})

_PRICE_RE = re.compile(r"\$(\d+\.?\d*)")


def commerce_gated(code: str, site_category: str | None) -> bool:
    """True when `code` only applies to a transacting site and this one
    never transacts (unknown and unlisted site types may transact)."""
    return code in COMMERCE_GATED_CODES and site_category in NON_TRANSACTING_SITE_TYPES


def find_products(schema_org: list[dict]) -> list[dict]:
    """Return all Product entities from schema_org list (including @graph).
    `None` (nothing extracted) and non-object entries read as no products."""
    products: list[dict] = []
    for entity in schema_org if isinstance(schema_org, list) else []:
        if not isinstance(entity, dict):
            continue
        if entity.get("@type") == "Product":
            products.append(entity)
        # Handle @graph wrapper
        graph = entity.get("@graph")
        if isinstance(graph, list):
            for item in graph:
                if isinstance(item, dict) and item.get("@type") == "Product":
                    products.append(item)
    return products


def get_offers(product: dict) -> list[dict]:
    """Return offers from a Product entity as a list of dicts."""
    raw = product.get("offers")
    if raw is None:
        return []
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [o for o in raw if isinstance(o, dict)]
    return []


def is_valid_price(price: Any) -> bool:
    """A positive number, or a string that parses as one ("29.99", not "$29.99")."""
    if price is None:
        return False
    try:
        value = float(price)
    except (ValueError, TypeError):
        return False
    return value > 0


def mentions_variant_keywords(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in VARIANT_KEYWORDS)


def extract_visible_price(text: str) -> str | None:
    """Return first price string (without $) found in visible text, or None."""
    m = _PRICE_RE.search(text)
    return m.group(1) if m else None


def schema_offer_price(schema_org: list[dict]) -> str | None:
    """Return the price from the first Offer of the first Product, or None."""
    products = find_products(schema_org)
    if not products:
        return None
    offers = get_offers(products[0])
    if not offers:
        return None
    price = offers[0].get("price")
    return str(price) if price is not None else None


def normalize_price(price_str: str) -> float | None:
    try:
        return float(price_str)
    except (ValueError, TypeError):
        return None
