"""CORE-INTERFACE-004 (EXPERIMENTAL): WebMCP tool declaration quality. Reads
the static `registerTool(...)` extraction (`analysis/webmcp_static.py`,
surfaced per-page as `parsed.webmcp_tools`/`parsed.webmcp_parse_errors`) —
a tool declaration an agent cannot validate against a schema, or cannot
tell apart from another by its description, is unusable even though the
page registered it."""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_SHORT_DESCRIPTION_MAX_LEN = 20


class WebMcpToolQuality(CoreCheck):
    id = "CORE-INTERFACE-004"
    title = "WebMCP tool declaration quality"
    category = Category.INTERFACES
    weight = 2
    experimental = True
    severity_on_fail = Severity.LOW
    references = ("https://github.com/webmachinelearning/webmcp",)
    why_it_matters = (
        "A WebMCP tool without a validated input schema, or without a description an agent "
        "can use to tell it apart from another, is unusable even though it registered."
    )
    limitations = (
        "Static extraction of `registerTool(` calls in already-fetched HTML on the sampled "
        "pages; a runtime-only or dynamically-constructed tool definition is not seen."
    )
    promotion_criteria = (
        "≥ 300 canonical scans of sites that statically register at least one WebMCP tool; "
        "a false-positive review of the static `registerTool(` extraction against tools enumerated "
        "at runtime, so a dynamically-built declaration is not counted as a missing one; a WebMCP "
        "tool-declaration shape that stayed stable across two consecutive specification revisions; "
        "then a scored weight and a RULESET_VERSION bump."
    )
    cloud_extension = "Scovant Cloud enumerates WebMCP tools live in a real browser, seeing runtime-only definitions this static scan cannot."

    def evaluate(self, store, ctx):
        pages = store.get("pages")["pages"]
        parsed_pages = [p for p in pages if p.get("parsed")]
        if not parsed_pages:
            return self.error("no page on this site could be parsed.")

        tools: list[dict] = []
        parse_errors = 0
        for p in parsed_pages:
            tools.extend(p["parsed"].get("webmcp_tools") or [])
            parse_errors += p["parsed"].get("webmcp_parse_errors") or 0

        ev = {"pages_scanned": len(parsed_pages), "tool_count": len(tools), "parse_errors": parse_errors}
        pages_unread = len(pages) - len(parsed_pages)
        if pages_unread > 0:
            # Only recorded when non-zero, so a fully-readable fixture (the common
            # case) keeps a byte-identical evidence shape and its golden untouched.
            ev["pages_total"] = len(pages)
            ev["pages_unread"] = pages_unread

        # A `registerTool(...)` declaration is read out of each sampled
        # page's raw HTML; a page cut off at the fetch cap may be hiding a
        # tool (or a field of one) that sat past it, so every verdict below
        # must say so.
        note, truncated = record_truncation({"truncated": any(p.get("truncated") for p in parsed_pages)}, ev)
        conf = truncated_confidence(truncated)

        if not tools and not parse_errors:
            return self.result(CheckStatus.NA, "No WebMCP tool registration was found on the sampled pages." + note,
                               evidence=ev, confidence=conf, severity=Severity.INFO)

        if not tools:
            return self.result(
                CheckStatus.WARN,
                "A WebMCP `registerTool(` call was found, but its declaration could not be parsed." + note,
                evidence=ev, confidence=conf,
                remediation="Ensure each registerTool({...}) argument is a well-formed object literal.",
            )

        no_schema = [t.get("name") for t in tools if not t.get("has_schema")]
        if no_schema:
            ev["missing_schema"] = no_schema
            return self.result(
                CheckStatus.FAIL,
                f"{len(no_schema)} of {len(tools)} declared WebMCP tool(s) have no input schema." + note,
                evidence=ev, confidence=conf,
                remediation="Declare an inputSchema (type/properties) for every registered tool.",
            )

        short_description = [
            t.get("name") for t in tools
            if len((t.get("description") or "").strip()) < _SHORT_DESCRIPTION_MAX_LEN
        ]
        if short_description:
            ev["short_description"] = short_description
            return self.result(
                CheckStatus.WARN,
                f"{len(short_description)} of {len(tools)} declared WebMCP tool(s) have a too-short description." + note,
                evidence=ev, confidence=conf,
                remediation="Write a real description (20+ characters) for every registered tool.",
            )

        return self.result(
            CheckStatus.PASS,
            "Every declared WebMCP tool has an input schema and a real description." + note,
            evidence=ev, confidence=conf,
        )
