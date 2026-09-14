"""CORE-INTERFACE-002: MCP server declaration quality. Distinct from
CORE-INTERFACE-001 (which asks whether an MCP discovery file/server card is
published at all) — this asks whether each server DECLARED inside a
published `mcpServers` object is well-formed enough for an agent to act on
without guessing."""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_GENERIC_DESCRIPTION_MAX_LEN = 10


def _missing_fields(server: dict) -> list[str]:
    missing = []
    if not server.get("name"):
        missing.append("name")
    if not server.get("url"):
        missing.append("url")
    if not server.get("transport"):
        missing.append("transport")
    return missing


class McpServerDeclarationQuality(CoreCheck):
    id = "CORE-INTERFACE-002"
    title = "MCP server declaration quality"
    category = Category.INTERFACES
    weight = 2
    severity_on_fail = Severity.LOW
    references = ("https://modelcontextprotocol.io/",)
    why_it_matters = (
        "An agent choosing among declared MCP servers needs a name, a URL, a transport, "
        "and a real description for each one — a bare, undescribed entry forces the agent "
        "to guess how to connect and why it should bother."
    )
    limitations = "Only the `mcpServers` object at /.well-known/mcp.json is parsed; a server card is not covered by this check."
    cloud_extension = "Scovant Cloud performs a live handshake against each declared server and checks the declaration against the server's own runtime-reported identity."
    standards = ("AR-ACT-03",)

    def evaluate(self, store, ctx):
        mcp = store.get("mcp_discovery")
        discovery = mcp["discovery"]
        servers = discovery.get("servers") or []
        status = mcp["status"]

        ev: dict = {}
        # `servers` is parsed out of the discovery-file body only (the
        # server-card probe never contributes to it), but `mcp["truncated"]`
        # is an OR across BOTH reads (`mcp_discovery` is a FOLDED record —
        # see CORE-INTERFACE-001) with no finer-grained flag exposed for
        # the discovery-file read alone. The generic wording stays honest
        # either way (still true whenever EITHER read was cut off).
        note, truncated = record_truncation(mcp, ev)
        conf = truncated_confidence(truncated)

        if not servers:
            if status is None:
                # No note/confidence here: `self.error()` is already LOW
                # confidence and its summary claims nothing about the
                # document's content (only that it could not be read at
                # all), so there is no over-claim for the truncation note
                # to guard against.
                return self.error("the MCP discovery file could not be read.", ev)
            return self.result(CheckStatus.NA, "No MCP server is declared." + note, evidence=ev, confidence=conf,
                               severity=Severity.INFO)

        ev["servers_count"] = len(servers)

        incomplete = [
            {"name": s.get("name"), "missing": _missing_fields(s)}
            for s in servers if _missing_fields(s)
        ]
        if incomplete:
            ev["incomplete_servers"] = incomplete
            return self.result(
                CheckStatus.WARN,
                f"{len(incomplete)} of {len(servers)} declared server(s) are missing a name, url, or transport." + note,
                evidence=ev, confidence=conf,
                remediation="Publish a name, url, and transport for every entry in mcpServers.",
            )

        all_generic = all(
            len((s.get("description") or "").strip()) <= _GENERIC_DESCRIPTION_MAX_LEN
            for s in servers
        )
        if all_generic:
            return self.result(
                CheckStatus.WARN,
                "Every declared MCP server has no description, or only a generic one." + note,
                evidence=ev, confidence=conf,
                remediation="Add a real description explaining what each declared MCP server does.",
            )

        return self.result(
            CheckStatus.PASS,
            "Every declared MCP server has a name, url, transport, and a real description." + note,
            evidence=ev, confidence=conf,
        )
