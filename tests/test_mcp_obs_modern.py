"""MCP-OBS-001 is not applicable to a server probed in the 2026-07-28 era."""
from scovant_core.rules.base import MeasureCtx
from scovant_core.rules.mcp import NA, McpObservabilityMissingProtocolVersionHeader

CTX = MeasureCtx(site_category="other", defaulted=frozenset())


def _domain(era):
    iface = {"attempted": True, "ok": True, "response_headers": {"content-type": "application/json"},
             "init_status": 200, "tools": []}
    if era:
        iface["probe_era"] = era
    return {"mcp": {"exists": True, "endpoints": ["https://example.com/mcp"], "declared_name": "x",
                    "handshake": {"attempted": True, "ok": True}, "interface": iface}}


def test_modern_era_no_finding():
    assert McpObservabilityMissingProtocolVersionHeader().evaluate({}, _domain("modern")) == []


def test_legacy_and_unmarked_still_fire():
    for era in ("legacy", None):
        assert McpObservabilityMissingProtocolVersionHeader().evaluate({}, _domain(era))


def test_modern_era_measures_not_applicable():
    assert McpObservabilityMissingProtocolVersionHeader().measure({}, _domain("modern"), CTX) is NA


def test_legacy_era_is_measured():
    assert McpObservabilityMissingProtocolVersionHeader().measure({}, _domain("legacy"), CTX) is None
