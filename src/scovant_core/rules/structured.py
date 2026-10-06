"""Product structured-data rules published from Scovant Cloud — page-scoped:
evaluated once per sampled page, over the page's schema.org entities.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. Every rule
here is commerce-gated: on a site type that never transacts
(`products.NON_TRANSACTING_SITE_TYPES`) it measures nothing. The findings
themselves do not depend on the site type — a host that knows it decides
whether to keep them.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule
from scovant_core.rules.product_terms import mentions_add_to_cart
from scovant_core.rules.products import (
    commerce_gated,
    find_products,
    get_offers,
    is_valid_price,
    mentions_variant_keywords,
)

NA = OutcomeState.NA
NM = OutcomeState.NOT_MEASURED


def _products_measured(code: str, page: dict, ctx: MeasureCtx, *,
                       need_offers: bool = False) -> OutcomeState | None:
    """Measured on a page with Product entities (and, when asked, an Offer);
    not applicable on a page without them."""
    if commerce_gated(code, ctx.site_category):
        return NA
    if "schema_org" not in page:
        return NM
    products = find_products(page.get("schema_org") or [])
    if not products:
        return NA
    if need_offers and not any(get_offers(p) for p in products):
        return NA
    return None


@register_rule
class MissingProductSchema(CoreRule):
    code = "MISSING_PRODUCT_SCHEMA"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "high"
    title = "Missing Product schema"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        if not find_products(schema_org):
            return [
                Finding(
                    title="Missing Product schema",
                    description="No schema.org Product entity found on this page.",
                    example=(
                        '<script type="application/ld+json">\n'
                        "{\n"
                        '  "@context": "https://schema.org",\n'
                        '  "@type": "Product",\n'
                        '  "name": "Widget Pro",\n'
                        '  "image": "https://example.com/widget.jpg",\n'
                        '  "sku": "WP-001",\n'
                        '  "brand": {"@type": "Brand", "name": "Acme"}\n'
                        "}\n"
                        "</script>"
                    ),
                    remediation_hint=(
                        "Add a schema.org Product entity to this page using JSON-LD (recommended) "
                        "or Microdata. Insert a <script type=\"application/ld+json\"> block in the "
                        "<head> containing at minimum: @type, name, description, image, and an "
                        "offers array. Example:\n\n"
                        "{\"@context\": \"https://schema.org\", \"@type\": \"Product\", "
                        "\"name\": \"...\", \"offers\": {\"@type\": \"Offer\", \"price\": \"...\", "
                        "\"priceCurrency\": \"USD\"}}\n\n"
                        "Without Product markup, AI agents cannot reliably extract product details "
                        "like name, price, or availability — they must guess from unstructured HTML, "
                        "which leads to inaccurate recommendations."
                    ),
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        # Only a product page can lack Product schema. Without schema, an
        # add-to-cart control is the page-type signal: the extractor's flag,
        # or any of the add-to-cart wordings in the visible text.
        if commerce_gated(self.code, ctx.site_category):
            return NA
        if "schema_org" not in page:
            return NM
        if find_products(page.get("schema_org") or []):
            return None
        if "semantic_signals" not in page:
            return NM
        signals = page.get("semantic_signals") or {}
        if signals.get("add_to_cart_found") or mentions_add_to_cart(page.get("visible_text") or ""):
            return None
        return NA


@register_rule
class MissingOfferData(CoreRule):
    code = "MISSING_OFFER_DATA"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "high"
    title = "Missing Offer data in Product schema"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        products = find_products(schema_org)
        if not products:
            return []
        for product in products:
            if not get_offers(product):
                return [
                    Finding(
                        title="Missing Offer data in Product schema",
                        description="Product entity found but no Offer data is present.",
                        example=(
                            "// Add an offers block to the Product JSON-LD\n"
                            '"offers": {\n'
                            '  "@type": "Offer",\n'
                            '  "price": "29.99",\n'
                            '  "priceCurrency": "USD",\n'
                            '  "availability": "https://schema.org/InStock"\n'
                            "}"
                        ),
                        remediation_hint=(
                            "Add an 'offers' property to your Product JSON-LD with at least one Offer "
                            "object. Each Offer should include: @type (\"Offer\"), price, priceCurrency, "
                            "availability (e.g., \"https://schema.org/InStock\"), and optionally url. "
                            "If the product has multiple variants, include one Offer per variant. "
                            "Without Offer data, AI agents can see that a product exists but cannot "
                            "determine its price or whether it can be purchased — making it impossible "
                            "for shopping agents to recommend or compare your products."
                        ),
                    )
                ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _products_measured(self.code, page, ctx)


@register_rule
class PriceMissingOrInvalid(CoreRule):
    code = "PRICE_MISSING_INVALID"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "critical"
    title = "Price missing or invalid in Offer"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        products = find_products(schema_org)
        if not products:
            return []
        for product in products:
            offers = get_offers(product)
            if not offers:
                continue
            for offer in offers:
                price = offer.get("price")
                if not is_valid_price(price):
                    return [
                        Finding(
                            title="Price missing or invalid in Offer",
                            description="Offer.price is absent, zero, or non-numeric.",
                            example=(
                                "// Publish a numeric price + ISO currency\n"
                                '"offers": {"@type": "Offer", "price": "29.99", "priceCurrency": "USD"}'
                            ),
                            remediation_hint=(
                                "Set the 'price' field in your Offer to a valid positive numeric value "
                                "(e.g., \"29.99\", not \"$29.99\" or \"0\"). Also include 'priceCurrency' "
                                "(e.g., \"USD\") so agents know the currency. If the price is dynamic or "
                                "varies by region, use the base price and add 'priceValidUntil' for "
                                "time-sensitive pricing. A missing or invalid price is the most critical "
                                "structured data issue — AI shopping agents will skip products entirely "
                                "if they cannot determine the price programmatically."
                            ),
                            metadata={"price": str(price)},
                        )
                    ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _products_measured(self.code, page, ctx, need_offers=True)


@register_rule
class AvailabilityMissing(CoreRule):
    code = "MISSING_AVAILABILITY"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "critical"
    title = "Availability missing from Offer"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        products = find_products(schema_org)
        if not products:
            return []
        for product in products:
            offers = get_offers(product)
            if not offers:
                continue
            for offer in offers:
                if not offer.get("availability"):
                    return [
                        Finding(
                            title="Availability missing from Offer",
                            description="Product has an Offer but no availability field is set.",
                            example=(
                                "// Declare stock state with a schema.org availability URL\n"
                                '"offers": {"@type": "Offer", "availability": "https://schema.org/InStock"}'
                            ),
                            remediation_hint=(
                                "Add an 'availability' field to each Offer in your Product JSON-LD. Use the "
                                "full schema.org URL values: \"https://schema.org/InStock\", "
                                "\"https://schema.org/OutOfStock\", \"https://schema.org/PreOrder\", or "
                                "\"https://schema.org/BackOrder\". Keep this field synchronized with your "
                                "actual inventory status in real time. AI shopping agents use availability "
                                "to filter search results — products without availability data are treated "
                                "as uncertain and ranked lower or excluded from purchase recommendations."
                            ),
                        )
                    ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _products_measured(self.code, page, ctx, need_offers=True)


@register_rule
class VariantInfoMissing(CoreRule):
    code = "VARIANT_INFO_MISSING"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "medium"
    title = "Variant information missing from structured data"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        schema_org = page.get("schema_org", [])
        products = find_products(schema_org)
        if not products:
            return []
        visible_text: str = page.get("visible_text", "") or ""

        for product in products:
            # Skip if structured variant data already present
            if product.get("hasVariant") or product.get("additionalProperty"):
                continue

            has_multiple_offers = len(get_offers(product)) > 1
            has_variant_keywords = mentions_variant_keywords(visible_text)

            if has_multiple_offers or has_variant_keywords:
                return [
                    Finding(
                        title="Variant information missing from structured data",
                        description=(
                            "Product appears to have variants (multiple offers or variant "
                            "keywords in visible text) but no structured hasVariant or "
                            "additionalProperty data."
                        ),
                        example=(
                            "// Group variants under a ProductGroup\n"
                            "{\n"
                            '  "@type": "ProductGroup",\n'
                            '  "name": "Widget Pro",\n'
                            '  "hasVariant": [\n'
                            '    {"@type": "Product", "sku": "WP-S", "name": "Widget Pro S"},\n'
                            '    {"@type": "Product", "sku": "WP-M", "name": "Widget Pro M"}\n'
                            "  ]\n"
                            "}"
                        ),
                        remediation_hint=(
                            "Add variant information to your Product JSON-LD using either 'hasVariant' "
                            "(an array of ProductModel objects) or 'additionalProperty' (an array of "
                            "PropertyValue objects for attributes like size, color, material). Each "
                            "variant should have its own Offer with the correct price and availability. "
                            "Example: \"hasVariant\": [{\"@type\": \"ProductModel\", \"name\": \"Large / Blue\", "
                            "\"offers\": {...}}]. Without structured variant data, AI agents cannot help "
                            "users select the right size or color and may present incomplete or incorrect "
                            "product options."
                        ),
                    )
                ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if commerce_gated(self.code, ctx.site_category):
            return NA
        if "schema_org" not in page or "visible_text" not in page:
            return NM
        return None if find_products(page.get("schema_org") or []) else NA
