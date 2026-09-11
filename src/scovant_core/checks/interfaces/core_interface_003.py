"""CORE-INTERFACE-003: static WebMCP presence. This is a STATIC check — it
scans already-fetched HTML for a marker that a page registers
`navigator.modelContext`, it never runs a browser and never observes
whether registration actually succeeds at runtime."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Confidence, Severity

_MARKER_RE = re.compile(r"navigator\.modelContext|modelcontext", re.I)


def _has_marker(html: str) -> bool:
    soup = BeautifulSoup(html, "lxml")
    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        text = script.string or script.get_text()
        if text and _MARKER_RE.search(text):
            return True
    for link in soup.find_all("link", rel=True):
        rel = link.get("rel")
        rel_str = " ".join(rel) if isinstance(rel, list) else str(rel)
        if "modelcontext" in rel_str.lower():
            return True
    for meta in soup.find_all("meta", attrs={"name": True}):
        if str(meta.get("name", "")).lower() == "webmcp":
            return True
    return False


class WebMcpStaticPresence(CoreCheck):
    id = "CORE-INTERFACE-003"
    title = "WebMCP static presence"
    category = Category.INTERFACES
    weight = 3
    severity_on_fail = Severity.LOW
    references = ("https://github.com/webmachinelearning/webmcp",)
    why_it_matters = (
        "A static WebMCP marker (an inline registration script, or a "
        "`<link rel=\"modelcontext\">`/`<meta name=\"webmcp\">` declaration) signals "
        "the page intends to expose in-browser tools to an agent."
    )
    limitations = (
        "This is a static text scan of already-fetched HTML for a marker string; the "
        "browser-side registration was not executed, so a marker's presence does not "
        "confirm the tools actually register or work."
    )
    cloud_extension = "Scovant Cloud enumerates WebMCP tools in a real browser and checks state parity."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        htmled = [p for p in pages if p.get("html")]
        if not htmled:
            return self.error("no page on this site could be read.")

        found_on = [p["url"] for p in htmled if _has_marker(p["html"])]
        ev = {"pages_scanned": len(htmled), "pages_with_marker": found_on}
        # A static marker is read out of each sampled page's raw HTML; a
        # page cut off at the fetch cap may be hiding a marker that sat
        # past it, so neither the PASS nor the "no marker found" verdict
        # can claim full confidence when any scanned page was only read in
        # part. Confidence here is already capped at LOW independent of
        # truncation, so `truncated_confidence` is a no-op on the level but
        # keeps this check consistent with the shared contract.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in htmled)}, ev)
        conf = truncated_confidence(truncated, default=Confidence.LOW)

        if found_on:
            return self.result(
                CheckStatus.PASS, "A static WebMCP marker is present." + note, evidence=ev, confidence=conf,
            )
        return self.result(
            CheckStatus.NA, "No static WebMCP marker was found on the sampled pages." + note, evidence=ev,
            confidence=conf, severity=Severity.INFO,
        )
