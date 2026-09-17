from __future__ import annotations

from scovant_core.checks._document import document_status
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Confidence, Severity


class McpDiscoveryPresence(CoreCheck):
    id = "CORE-INTERFACE-001"
    title = "MCP discovery presence"
    category = Category.INTERFACES
    verification_mode = "DECLARED"
    weight = 3
    severity_on_fail = Severity.MEDIUM
    references = ("https://modelcontextprotocol.io/",)
    why_it_matters = (
        "A published MCP discovery file (or server card) is how an agent finds this site's "
        "own tool interface instead of falling back to browser-shaped scraping."
    )
    limitations = "Only `/.well-known/mcp.json` and the two candidate server-card paths are probed; a custom discovery location is not found."
    cloud_extension = "Scovant Cloud performs a live MCP handshake and enumerates the tool list, not just discovery-file presence."
    standards = ("AR-ACT-03",)

    def evaluate(self, store, ctx):
        mcp = store.get("mcp_discovery")
        discovery = mcp["discovery"]
        server_card = mcp["server_card"]
        status = mcp["status"]
        ev = {
            "resource": f"{ctx.origin}/.well-known/mcp.json",
            "http_status": status,
            "exists": discovery["exists"],
            "valid": discovery["valid"],
            "server_card": server_card,
        }
        # Two documents feed this verdict — the discovery file and the
        # separately-probed server card (`gatherers/mcp_discovery.py`) —
        # and the record's own `truncated` is an OR across both, so it
        # cannot be attributed to either one by name (the CORE-ACCESS-009
        # lesson: `mcp_discovery` is a FOLDED record). The generic wording
        # is used instead, true regardless of which was cut off.
        note, truncated = record_truncation(mcp, ev)
        conf = truncated_confidence(truncated)

        if not discovery["exists"] and not server_card:
            # `document_status` widens ERROR coverage beyond the old "status
            # is None" check to every genuinely unreadable non-200/non-404/
            # 410 status (5xx, 401/403) — a real 404/410 keeps the check's
            # own "not published" text below.
            v = document_status({"status": status}, what="the MCP discovery file")
            if v and v.status is CheckStatus.ERROR:
                # No note/confidence here: `self.error()` is already LOW
                # confidence and its summary claims nothing about the
                # document's content (only that it could not be read at
                # all), so there is no over-claim for the truncation note
                # to guard against.
                return self.error("the MCP discovery file could not be read.", ev)
            if server_card is None:
                # CARRY-FORWARD: the discovery file is
                # confirmed absent, but the SEPARATE server-card probe's
                # own read was cut off before it could tell whether a card
                # exists at all — `exists=None` there means "could not
                # determine", never a claimed `False`
                # (`gatherers/mcp_metadata.probe_mcp_server_card`). `not
                # server_card` is True for both `False` and `None`, so
                # without this branch a truncated-and-undetermined server
                # card fell into "No MCP discovery file is published" —
                # asserting an absence that was never actually confirmed. A
                # document we could not read is not a document that is
                # absent. No note/confidence here either, same reasoning as
                # the ERROR branch above: `self.error()` is already LOW
                # confidence and its summary already says the document
                # could not be read.
                return self.error("the MCP server card could not be read.", ev)
            return self.result(CheckStatus.NA, "No MCP discovery file is published." + note, evidence=ev,
                               confidence=conf, severity=Severity.INFO)

        if discovery["exists"] and discovery["valid"]:
            ev["endpoints"] = discovery["endpoints"]
            ev["declared_name"] = discovery["declared_name"]
            return self.result(CheckStatus.PASS, "An MCP discovery file is published and well-formed." + note,
                               evidence=ev, confidence=conf)

        if discovery["exists"] and not discovery["valid"]:
            return self.result(
                CheckStatus.WARN, "A discovery file is present but malformed." + note, evidence=ev, confidence=conf,
                remediation="Publish /.well-known/mcp.json with an `mcpServers` object naming at least one server URL.",
            )

        # Not exists, server_card True: a server card without a discovery file.
        return self.result(
            CheckStatus.PASS, "An MCP server card is present." + note, evidence=ev,
            confidence=truncated_confidence(truncated, default=Confidence.MEDIUM),
        )
