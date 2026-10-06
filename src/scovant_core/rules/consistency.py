"""Consistency rules published from Scovant Cloud — page-scoped: whether a
page's structured data agrees with itself and with what the page shows.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. A rule that
needs two things to compare is not applicable when one of them is missing
(one Product entity, or no price on one side). PRICE_MISMATCH is
commerce-gated (`products.NON_TRANSACTING_SITE_TYPES`); the visible price is
the first "$<number>" in the page text, so it compares dollar prices only.
"""
from __future__ import annotations

import json

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule
from scovant_core.rules.products import (
    commerce_gated,
    extract_visible_price,
    find_products,
    get_offers,
    normalize_price,
    schema_offer_price,
)


def _hashable(value):
    """A set member for a JSON-LD value: scalars as they are, containers by
    their canonical JSON text."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return value

NA = OutcomeState.NA
NM = OutcomeState.NOT_MEASURED


def _two_products_measured(page: dict) -> OutcomeState | None:
    if "schema_org" not in page:
        return NM
    return None if len(find_products(page.get("schema_org") or [])) >= 2 else NA


@register_rule
class PriceMismatch(CoreRule):
    code = "PRICE_MISMATCH"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "consistency"
    severity = "high"
    title = "Price mismatch: visible vs structured data"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        visible_text: str = page.get("visible_text", "") or ""

        visible_price_str = extract_visible_price(visible_text)
        if visible_price_str is None:
            return []

        structured_price_str = schema_offer_price(schema_org)
        if structured_price_str is None:
            return []

        visible_val = normalize_price(visible_price_str)
        structured_val = normalize_price(structured_price_str)
        if visible_val is None or structured_val is None:
            return []

        if visible_val != structured_val:
            return [
                Finding(
                    title="Price mismatch: visible vs structured data",
                    description=(
                        f"Visible price (${visible_price_str}) differs from "
                        f"schema.org Offer.price ({structured_price_str})."
                    ),
                    remediation_hint=(
                        "Update your JSON-LD Offer.price to exactly match the price displayed on "
                        "the page. If prices change dynamically (e.g., sales, A/B tests, currency "
                        "conversion), ensure your structured data is updated at the same time as the "
                        "visible price — ideally from the same data source. Price mismatches are a "
                        "trust signal for AI agents: if the structured data says $49 but the page "
                        "shows $39, the agent cannot determine which price is correct and may avoid "
                        "recommending the product altogether."
                    ),
                    example=(
                        "<!-- UI label and JSON-LD must agree -->\n"
                        '<span class="price">$29.99</span>\n'
                        "// JSON-LD\n"
                        '"offers": {"price": "29.99", "priceCurrency": "USD"}'
                    ),
                    metadata={
                        "visible_price": visible_price_str,
                        "structured_price": structured_price_str,
                    },
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if commerce_gated(self.code, ctx.site_category):
            return NA
        if "schema_org" not in page or "visible_text" not in page:
            return NM
        v = extract_visible_price(page.get("visible_text") or "")
        s = schema_offer_price(page.get("schema_org") or [])
        if v is None or s is None or normalize_price(v) is None or normalize_price(s) is None:
            return NA  # nothing comparable on one side: no mismatch to measure
        return None


@register_rule
class InconsistentStructuredData(CoreRule):
    code = "INCONSISTENT_STRUCTURED_DATA"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "consistency"
    severity = "medium"
    title = "Inconsistent structured data blocks"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        products = find_products(schema_org)
        if len(products) < 2:
            return []

        prices: list[float] = []
        for product in products:
            for offer in get_offers(product):
                price = offer.get("price")
                val = normalize_price(str(price)) if price is not None else None
                if val is not None:
                    prices.append(val)
                    break  # one price per product

        if len(prices) >= 2 and len(set(prices)) > 1:
            return [
                Finding(
                    title="Inconsistent structured data blocks",
                    description="Multiple JSON-LD Product blocks have conflicting prices.",
                    example=(
                        "// One coherent @graph; nested types reference shared @id nodes\n"
                        "{\n"
                        '  "@context": "https://schema.org",\n'
                        '  "@graph": [\n'
                        '    {"@type": "Organization", "@id": "https://example.com/#org", "name": "Acme"},\n'
                        '    {"@type": "Product", "@id": "https://example.com/widget#product",\n'
                        '     "brand": {"@id": "https://example.com/#org"}}\n'
                        "  ]\n"
                        "}"
                    ),
                    remediation_hint=(
                        "Merge your multiple JSON-LD Product blocks into a single, authoritative "
                        "Product entity. If your page has separate <script type=\"application/ld+json\"> "
                        "tags from different plugins or templates, consolidate them. Use one Product "
                        "with one offers array. If different blocks were generated by different tools "
                        "(e.g., a CMS plugin and a tag manager), disable the duplicate source. "
                        "Conflicting structured data forces AI agents to guess which block is "
                        "authoritative, often leading to incorrect information being surfaced."
                    ),
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _two_products_measured(page)


@register_rule
class DuplicateConflictingEntities(CoreRule):
    code = "DUPLICATE_CONFLICTING_ENTITIES"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "consistency"
    severity = "medium"
    title = "Duplicate conflicting Product entities"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        products = find_products(schema_org)
        if len(products) < 2:
            return []

        # JSON-LD values are whatever the page published; a list or object
        # where a name/id string belongs is compared by its JSON text.
        names = {_hashable(p.get("name")) for p in products if p.get("name")}
        ids = {_hashable(p.get("@id")) for p in products if p.get("@id")}
        product_ids = {_hashable(p.get("productID")) for p in products if p.get("productID")}

        has_conflicting_names = len(names) > 1
        has_conflicting_ids = len(ids) > 1 or len(product_ids) > 1

        if has_conflicting_names or has_conflicting_ids:
            return [
                Finding(
                    title="Duplicate conflicting Product entities",
                    description="Multiple Product entities with different names or identifiers found.",
                    example=(
                        "<!-- Keep ONE Product block per page under a single @id; delete the conflicting copy -->\n"
                        '{"@type": "Product", "@id": "https://example.com/widget#product", "name": "Widget Pro"}'
                    ),
                    remediation_hint=(
                        "Reduce to a single primary Product entity per product page. If the page "
                        "represents one product, there should be exactly one Product JSON-LD block "
                        "with a unique @id and consistent name/productID. Remove or merge duplicate "
                        "Product entities that have different names or identifiers. For collection "
                        "pages listing multiple products, use an ItemList containing individual "
                        "Product references instead of separate top-level Product blocks. Duplicate "
                        "entities with conflicting identifiers make it impossible for AI agents to "
                        "determine which product the page actually represents."
                    ),
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _two_products_measured(page)
