"""Page-structure rules published from Scovant Cloud — page-scoped: the
heading outline and the HTML5 landmarks an agent uses to map a page.

Both apply only to a content-bearing page (`MIN_CONTENT_CHARS` of visible
text or more). A finding carries 1/N of the rule's penalty, N = the pages the
host sampled (`pages_scored` in the domain evidence; 1 when absent), so a
site is not penalised N times for one template. The findings' text and
metadata are the ones Scovant Cloud has always reported for these codes;
`measure` says when silence is a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule

# Visible-text length from which a page counts as content-bearing.
MIN_CONTENT_CHARS = 300

NA = OutcomeState.NA
NM = OutcomeState.NOT_MEASURED


def page_share(domain: dict | None) -> float:
    """1/N of the penalty for one page, N = sampled pages (at least 1)."""
    pages = max(int((domain or {}).get("pages_scored") or 1), 1)
    return 1.0 / pages


@register_rule
class HeadingHierarchyPoor(CoreRule):
    code = "HEADING_HIERARCHY_POOR"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "low"
    title = "Poor heading hierarchy"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if len(page.get("visible_text") or "") < MIN_CONTENT_CHARS:
            return []
        headings = page.get("headings") or []
        levels = [int(h["level"][1]) for h in headings
                  if isinstance(h.get("level"), str) and h["level"][:1] == "h" and h["level"][1:].isdigit()]
        defects: list[str] = []
        h1_count = levels.count(1)
        if h1_count == 0:
            defects.append("no <h1> heading")
        elif h1_count > 1:
            defects.append(f"multiple <h1> headings ({h1_count})")
        prev = None
        for lv in levels:
            if prev is not None and lv > prev + 1:
                defects.append(f"heading level skip (h{prev} → h{lv})")
                break
            prev = lv
        if not defects:
            return []
        return [
            Finding(
                title="Poor heading hierarchy",
                description="Heading structure defects: " + "; ".join(defects) + ". "
                            "Agents and AI crawlers use the heading outline to map page content.",
                remediation_hint=(
                    "Use exactly one <h1> per page and keep heading levels sequential "
                    "(h1 → h2 → h3) without skipping levels."
                ),
                example=(
                    "<h1>Widget Pro Overview</h1>\n"
                    "<h2>Features</h2>\n"
                    "<h3>Performance</h3>\n"
                    "<h2>Pricing</h2>"
                ),
                metadata={"defects": defects},
                weight_multiplier=page_share(domain),
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if "visible_text" not in page or "headings" not in page:
            return NM
        return NA if len(page.get("visible_text") or "") < MIN_CONTENT_CHARS else None


@register_rule
class SemanticHtmlAbsent(CoreRule):
    code = "SEMANTIC_HTML_ABSENT"
    since = "0.9.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "structured"
    severity = "info"
    title = "No semantic HTML5 landmarks"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if len(page.get("visible_text") or "") < MIN_CONTENT_CHARS:
            return []
        tags = page.get("landmark_tags")
        if tags is None:  # evidence recorded before landmarks were extracted
            return []
        if any(tags.get(t, 0) > 0 for t in tags):
            return []
        return [
            Finding(
                title="No semantic HTML5 landmarks",
                description=(
                    "The page uses no semantic landmark tags (main, article, nav, "
                    "section, header, footer, aside). Agents segment pages by these "
                    "landmarks; a div-only layout is harder to navigate reliably."
                ),
                example=(
                    "<main>\n"
                    "  <article>\n"
                    "    <h1>Article Title</h1>\n"
                    "    <p>Content...</p>\n"
                    "  </article>\n"
                    "</main>\n"
                    "<nav>Navigation links</nav>"
                ),
                remediation_hint=(
                    "Wrap primary content in <main>, self-contained items in "
                    "<article>, and navigation in <nav>."
                ),
                weight_multiplier=page_share(domain),
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if "visible_text" not in page or page.get("landmark_tags") is None:
            return NM
        return NA if len(page.get("visible_text") or "") < MIN_CONTENT_CHARS else None
