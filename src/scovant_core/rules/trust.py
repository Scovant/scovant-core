"""Trust rules published from Scovant Cloud — page-scoped: evaluated once per
sampled page, over the page's policy links, schema.org entities and
OpenGraph meta.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. The returns
and shipping rules are commerce-gated: on a site type that never transacts
(`products.NON_TRANSACTING_SITE_TYPES`) they measure nothing. The findings
themselves do not depend on the site type — a host that knows it decides
whether to keep them.

`measure` asks whether the extractor's field is PRESENT on the page, while
`evaluate` reads it leniently (a missing or null field is "nothing found"):
a page recorded before the field existed is reported as not measured, never
as a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule
from scovant_core.rules.products import commerce_gated

NA = OutcomeState.NA
NM = OutcomeState.NOT_MEASURED


def has_structured_shipping(schema_org: list[dict]) -> bool:
    """True when any entity's Offer (one Offer or a list of them) carries
    `shippingDetails`. Every entity counts, not only Products."""
    for entity in schema_org:
        offers_raw = entity.get("offers")
        offers: list[dict] = []
        if isinstance(offers_raw, dict):
            offers = [offers_raw]
        elif isinstance(offers_raw, list):
            offers = offers_raw
        for offer in offers:
            if isinstance(offer, dict) and offer.get("shippingDetails"):
                return True
    return False


def _policy_measured(code: str, page: dict, ctx: MeasureCtx, *, schema_too: bool = False) -> OutcomeState | None:
    if commerce_gated(code, ctx.site_category):
        return NA
    if "policy_links" not in page or (schema_too and "schema_org" not in page):
        return NM
    return None


@register_rule
class ReturnPolicyUnavailable(CoreRule):
    code = "MISSING_RETURNS_POLICY"
    since = "0.11.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "trust"
    severity = "medium"
    title = "Return policy unavailable"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        policy_links: dict = page.get("policy_links") or {}
        if policy_links.get("returns_policy_url") is None:
            return [
                Finding(
                    title="Return policy unavailable",
                    description="No returns or refund policy page was found or linked.",
                    example=(
                        "// Attach a MerchantReturnPolicy to the Product/Offer\n"
                        '"hasMerchantReturnPolicy": {\n'
                        '  "@type": "MerchantReturnPolicy",\n'
                        '  "returnPolicyCategory": "https://schema.org/MerchantReturnFiniteReturnWindow",\n'
                        '  "merchantReturnDays": 30,\n'
                        '  "returnMethod": "https://schema.org/ReturnByMail"\n'
                        "}"
                    ),
                    remediation_hint=(
                        "Add a clearly labeled link to your returns/refund policy page in your site "
                        "footer, product pages, and checkout flow. Use standard anchor text like "
                        "\"Return Policy\", \"Refund Policy\", or \"Returns & Exchanges\" so AI agents "
                        "can identify it reliably. The policy page itself should include: return window "
                        "(e.g., 30 days), conditions for returns, refund method (original payment, "
                        "store credit), and who pays return shipping. AI shopping agents check for "
                        "return policies before recommending purchases — a missing policy is a trust "
                        "red flag that can cause agents to deprioritize your products."
                    ),
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _policy_measured(self.code, page, ctx)


@register_rule
class ShippingInfoUnavailable(CoreRule):
    code = "SHIPPING_INFO_UNAVAILABLE"
    since = "0.11.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "trust"
    severity = "medium"
    title = "Shipping information unavailable"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        policy_links: dict = page.get("policy_links") or {}
        schema_org: list[dict] = page.get("schema_org") or []

        if policy_links.get("shipping_policy_url") is not None:
            return []
        if has_structured_shipping(schema_org):
            return []
        return [
            Finding(
                title="Shipping information unavailable",
                description=(
                    "No shipping policy page link and no structured shipping data found."
                ),
                example=(
                    "// Expose shipping cost + timeline in the Offer\n"
                    '"shippingDetails": {\n'
                    '  "@type": "OfferShippingDetails",\n'
                    '  "shippingRate": {"@type": "MonetaryAmount", "value": "0", "currency": "USD"},\n'
                    '  "deliveryTime": {"@type": "ShippingDeliveryTime",\n'
                    '    "transitTime": {"@type": "QuantitativeValue", "minValue": 1, "maxValue": 3, "unitCode": "DAY"}}\n'
                    "}"
                ),
                remediation_hint=(
                    "Add shipping information in at least one of two ways: (1) Create a dedicated "
                    "shipping policy page and link to it from your footer and product pages with "
                    "standard anchor text like \"Shipping Policy\" or \"Delivery Information\". "
                    "(2) Add structured shippingDetails to your Offer JSON-LD using the "
                    "OfferShippingDetails schema type, including shippingRate, deliveryTime, and "
                    "shippingDestination. Including both is ideal. Shipping details should cover: "
                    "delivery timeframes, shipping costs (or free shipping thresholds), geographic "
                    "availability, and carrier information. AI agents use this data to answer "
                    "\"how much is shipping?\" and \"when will it arrive?\" — common pre-purchase "
                    "questions that directly influence buying decisions."
                ),
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _policy_measured(self.code, page, ctx, schema_too=True)


@register_rule
class MissingOgMeta(CoreRule):
    code = "MISSING_OG_META_FOR_CITATION"
    since = "0.11.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "trust"
    severity = "medium"
    title = "Missing OpenGraph meta for citation"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        og_meta = page.get("og_meta")
        if og_meta is None:
            return []

        missing_fields: list[str] = []
        if og_meta.get("og_title") is None:
            missing_fields.append("og:title")
        if og_meta.get("og_description") is None:
            missing_fields.append("og:description")

        if missing_fields:
            return [
                Finding(
                    title="Missing OpenGraph meta for citation",
                    description=(
                        f"Required OpenGraph fields are missing: {', '.join(missing_fields)}."
                    ),
                    example=(
                        "<!-- Add OpenGraph + Twitter card meta to <head> -->\n"
                        '<meta property="og:title" content="Widget Pro — Acme">\n'
                        '<meta property="og:description" content="Buy Widget Pro online.">\n'
                        '<meta property="og:image" content="https://example.com/widget.jpg">\n'
                        '<meta name="twitter:card" content="summary_large_image">'
                    ),
                    remediation_hint=(
                        "Add the missing OpenGraph meta tags to your page's <head> section. At "
                        "minimum, include:\n\n"
                        "<meta property=\"og:title\" content=\"Your Page Title\" />\n"
                        "<meta property=\"og:description\" content=\"A concise description\" />\n\n"
                        "Also recommended: og:image, og:url, and og:type. These tags serve as a "
                        "structured summary that AI models use for citation and brand attribution "
                        "when referencing your content. Without them, AI-generated answers may cite "
                        "your content without proper attribution, or use inaccurate titles and "
                        "descriptions pulled from arbitrary page text."
                    ),
                    metadata={"missing_fields": missing_fields},
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return NM if page.get("og_meta") is None else None
