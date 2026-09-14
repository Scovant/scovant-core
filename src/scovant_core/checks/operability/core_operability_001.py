"""CORE-OPERABILITY-001: server-rendered core content. Reads the entry
page's already-fetched-and-parsed record (`pages[0]`) — no browser
rendering, this is a static-HTML signal only (product spec §14: browser
rendering is explicitly out of scope for this check)."""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity
from scovant_core.parsers.html import has_spa_shell_marker
from scovant_core.security.url_safety import display_url

_MIN_VISIBLE_CHARS = 200


class ServerRenderedCoreContent(CoreCheck):
    id = "CORE-OPERABILITY-001"
    title = "Server-rendered core content"
    category = Category.OPERABILITY
    weight = 3
    severity_on_fail = Severity.MEDIUM
    references = ("https://developer.chrome.com/docs/lighthouse/performance/",)
    why_it_matters = (
        "Most agent HTTP clients never execute JavaScript — if the core content only appears after "
        "client-side rendering, an agent reading the raw response sees an empty shell."
    )
    limitations = "Static-HTML signal only: the raw fetched response is inspected, never rendered in a browser, so a site that hydrates real content very quickly may still be flagged here."
    cloud_extension = "Scovant Cloud renders a sample of pages in a real headless browser and compares the rendered content against the static fetch."
    standards = ("AR-READ-01", "AR-READ-03")

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        entry = pages[0] if pages else None
        if entry is None or entry.get("parsed") is None:
            return self.error("the entry page could not be parsed.", {"entry_url": display_url(ctx.final_url)})

        visible_text = entry["parsed"]["visible_text"] or ""
        chars = len(visible_text)
        shell_marker = has_spa_shell_marker(entry.get("html") or "")
        ev = {"entry_url": display_url(ctx.final_url), "visible_text_chars": chars, "spa_shell_marker": shell_marker}
        # Both `visible_text` and the SPA-shell marker are read out of the
        # entry page's own body; a page cut off at the fetch cap may show
        # artificially few visible chars (a false WARN) or an incomplete
        # shell-marker match, so every verdict below must say so.
        note, truncated = record_truncation(entry, ev, document="entry page")
        conf = truncated_confidence(truncated)

        if chars >= _MIN_VISIBLE_CHARS and not shell_marker:
            return self.result(CheckStatus.PASS, f"The entry page's static HTML carries {chars} chars of visible text." + note,
                               evidence=ev, confidence=conf)
        if shell_marker:
            return self.result(
                CheckStatus.WARN, "The entry page's static HTML shows a client-render (SPA-shell) signal." + note,
                evidence=ev, confidence=conf,
                remediation="Server-render (or statically pre-render) the core content so an agent's plain HTTP fetch sees it.",
            )
        return self.result(
            CheckStatus.WARN, f"The entry page's static HTML carries only {chars} chars of visible text (< {_MIN_VISIBLE_CHARS})." + note,
            evidence=ev, confidence=conf,
            remediation="Server-render (or statically pre-render) the core content so an agent's plain HTTP fetch sees it.",
        )
