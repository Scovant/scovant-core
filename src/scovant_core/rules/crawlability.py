"""Page crawlability rule published from Scovant Cloud — the first
page-scoped rule in Core: evaluated once per sampled page.

The findings' text and metadata are the ones Scovant Cloud has always
reported for this code; `measure` says when silence is a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, register_rule


@register_rule
class BlockedCrawlability(CoreRule):
    code = "BLOCKED_CRAWLABILITY"
    maturity = "required"
    rule_version = "1.0"
    scope = "page"
    category = "discoverability"
    severity = "high"
    title = "Page crawlability blocked"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        robots_meta: str | None = (page.get("metadata") or {}).get("robots_meta")
        http_status: int | None = page.get("http_status")

        noindex = robots_meta is not None and "noindex" in robots_meta.lower()
        bad_status = http_status is not None and http_status != 200

        if noindex or bad_status:
            reason = "noindex directive in robots meta" if noindex else f"HTTP status {http_status}"
            return [
                Finding(
                    title="Page crawlability blocked",
                    description=f"Page is not accessible to crawlers: {reason}.",
                    remediation_hint=(
                        "If the page has a noindex directive, remove it from the <meta name=\"robots\"> "
                        "tag or the X-Robots-Tag HTTP header. If the page returns a non-200 status code, "
                        "investigate the cause — common issues include misconfigured redirects, "
                        "authentication walls, or geo-blocking. AI agents treat non-200 responses and "
                        "noindex pages as inaccessible, meaning this content will never appear in "
                        "AI-generated answers or agent workflows."
                    ),
                    example=(
                        "<!-- Allow indexing in the page <head> -->\n"
                        '<meta name="robots" content="index, follow">\n\n'
                        "# ...or via HTTP response header:\n"
                        "X-Robots-Tag: index, follow"
                    ),
                    metadata={"robots_meta": robots_meta, "http_status": http_status},
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        # Stored page evidence usually carries no `http_status` of its own,
        # so only the noindex half can fire; on an error page (the fetch's
        # status, `_http_status`) the true verdict is invisible to the rule.
        if "metadata" not in page:
            return OutcomeState.NOT_MEASURED
        status = page.get("_http_status")
        return OutcomeState.NOT_MEASURED if status is not None and status != 200 else None
