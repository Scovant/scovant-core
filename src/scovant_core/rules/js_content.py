"""JS-only critical content, published from Scovant Cloud: what an agent that
reads the raw HTML (without running JavaScript) can see on one page.

The finding's text and metadata are the ones Scovant Cloud has always
reported for this code; `measure` says when silence is a pass. Three
conditions, checked in order, one finding at most: almost no visible text
(an SPA shell), a product page whose add-to-cart control is missing from
the static HTML, and too few interactive elements with an accessible name.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule

# Below this many characters of visible text a page is read as an SPA shell.
MIN_VISIBLE_TEXT_CHARS = 100
# Below this share of labelled interactive elements the controls are opaque.
MIN_LABELED_SHARE = 0.3

_REMEDIATION = (
    "Implement server-side rendering (SSR) or static site generation (SSG) so "
    "that critical content — product details, prices, descriptions, and interactive "
    "elements — is present in the initial HTML response without requiring JavaScript "
    "execution. Add aria-label attributes to all buttons, links, and form fields so "
    "AI agents can understand their purpose. For SPAs using React, Vue, or Angular, "
    "consider frameworks like Next.js, Nuxt, or Angular Universal. AI agents "
    "typically fetch raw HTML without executing JavaScript, so JS-only content is "
    "invisible to them."
)
_SSR_EXAMPLE = (
    "<!-- Before: price exists only after JS runs -->\n"
    '<div id="price"></div><script>renderPrice()</script>\n\n'
    "<!-- After: server-render the value, hydrate in place -->\n"
    '<div id="price">$29.99</div>'
)


@register_rule
class JsOnlyCriticalContent(CoreRule):
    code = "JS_ONLY_CRITICAL_CONTENT"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "actionability"
    severity = "high"
    title = "JS-only critical content"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        visible_text: str = page.get("visible_text", "") or ""
        product_data = page.get("product_data")
        signals: dict = page.get("semantic_signals") or {}

        labeled = signals.get("labeled_elements_count", 0)
        interactive = signals.get("interactive_elements_count", 0)
        add_to_cart = signals.get("add_to_cart_found", True)

        # Condition 1: SPA shell — very little text
        if len(visible_text) < MIN_VISIBLE_TEXT_CHARS:
            return [
                Finding(
                    title="JS-only critical content",
                    description=(
                        "Page has less than 100 characters of visible text — likely a "
                        "JavaScript-rendered SPA shell with no static content."
                    ),
                    example=_SSR_EXAMPLE,
                    remediation_hint=_REMEDIATION,
                )
            ]

        # Condition 2: Product page missing add-to-cart in static HTML
        if product_data is not None and not add_to_cart:
            return [
                Finding(
                    title="JS-only critical content",
                    description=(
                        "Product page found but add-to-cart functionality is not "
                        "accessible in static HTML."
                    ),
                    example=_SSR_EXAMPLE,
                    remediation_hint=_REMEDIATION,
                )
            ]

        # Condition 3: Low labeled-to-interactive ratio
        if interactive > 0 and (labeled / interactive) < MIN_LABELED_SHARE:
            return [
                Finding(
                    title="JS-only critical content",
                    description=(
                        f"Only {labeled}/{interactive} interactive elements have accessible "
                        "labels in static HTML."
                    ),
                    example=(
                        "<!-- Add an accessible label to every interactive element -->\n"
                        '<button aria-label="Add Widget Pro to cart">Add to cart</button>\n'
                        '<input aria-label="Search products" placeholder="Search..." />'
                    ),
                    remediation_hint=_REMEDIATION,
                    metadata={"labeled_elements_count": labeled, "interactive_elements_count": interactive},
                )
            ]

        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if "visible_text" not in page or "semantic_signals" not in page:
            return OutcomeState.NOT_MEASURED
        return None
