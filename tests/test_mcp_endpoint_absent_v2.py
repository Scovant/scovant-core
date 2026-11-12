"""MCP_ENDPOINT_ABSENT 2.0: judged on real MCP surfaces — a valid discovery
file, a card-shaped server card at the old paths, or a server card reached
through the AI Catalog. A catch-all 200 at /.well-known/mcp.json no longer
counts. Every evidence block comes from the real producers
(`check_mcp_discovery`, `probe_mcp_server_card`, `probe_ai_catalog`)."""
from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers the gatherers
from scovant_core.checks.interfaces.core_interface_001 import McpDiscoveryPresence
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers.mcp_metadata import probe_ai_catalog, probe_mcp_server_card
from scovant_core.models import CheckStatus
from scovant_core.parsers.mcp import check_mcp_discovery
from scovant_core.profiles import apply_profile
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx
from scovant_core.rules.mcp import mcp_surface_found

from .conftest import make_client

ORIGIN = "https://example.com"
CARD_T = "application/mcp-server-card+json"
CARD = {"name": "io.example/srv", "version": "1.0.0", "remotes": []}
VALID_FILE = json.dumps({"mcpServers": {"shop": {"url": "https://example.com/mcp"}}})
NM = OutcomeState.NOT_MEASURED


def _rule():
    return next(r for r in RULES if r.code == "MCP_ENDPOINT_ABSENT")


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _not_found(_request):
    return httpx.Response(404)


def _catalog(handler=_not_found) -> dict:
    return probe_ai_catalog(_client(handler), ORIGIN)


def _domain(body: str | None, status: int, *, catalog: dict | None = None,
            card_handler=_not_found, site_type: str = "commerce") -> dict:
    mcp = check_mcp_discovery(body, status)
    mcp["server_card"] = probe_mcp_server_card(_client(card_handler), ORIGIN)["exists"]
    mcp["ai_catalog"] = catalog if catalog is not None else _catalog()
    return {"site_type": site_type, "mcp": mcp}


def _measure(domain, defaulted=frozenset(), site_type="commerce"):
    return _rule().measure({}, domain, MeasureCtx(site_type, defaulted))


def _catalog_with_card():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json={"specVersion": "1.0",
                                             "entries": [{"type": CARD_T, "url": "/mcp/server-card"}]})
        return httpx.Response(200, json=CARD)
    return _catalog(handler)


def test_rule_version_is_two():
    assert _rule().rule_version == "2.0"
    assert _rule().since == "0.10.0"


def test_catchall_mcp_json_no_longer_suppresses():
    d = _domain("<!doctype html><html><body>shop</body></html>", 200)
    assert d["mcp"]["exists"] is True and d["mcp"]["json_object"] is False
    assert mcp_surface_found(d["mcp"]) is False
    finding, = _rule().evaluate({}, d)
    assert finding.metadata == {"site_type": "commerce", "discovery_file": "not_discovery"}
    assert "answers, but not with an MCP discovery document" in finding.description
    assert "HTML" in finding.description
    assert "ai-catalog.json" in finding.remediation_hint
    assert _measure(d) is None


def test_json_without_servers_fires_with_json_wording():
    d = _domain(json.dumps({"gpc": True}), 200)
    finding, = _rule().evaluate({}, d)
    assert finding.metadata["discovery_file"] == "not_discovery"
    assert "JSON without an `mcpServers` server" in finding.description


def test_absent_file_keeps_the_old_wording():
    d = _domain(None, 404)
    finding, = _rule().evaluate({}, d)
    assert finding.metadata == {"site_type": "commerce", "discovery_file": "absent"}
    assert finding.description.startswith("No /.well-known/mcp.json")


def test_valid_file_suppresses():
    d = _domain(VALID_FILE, 200)
    assert _rule().evaluate({}, d) == []
    assert _measure(d) is None


def test_card_shaped_old_path_suppresses():
    d = _domain(None, 404, card_handler=lambda r: httpx.Response(200, json=CARD))
    assert d["mcp"]["server_card"] is True
    assert _rule().evaluate({}, d) == []
    assert _measure(d) is None


def test_non_card_json_at_old_path_does_not_suppress():
    d = _domain(None, 404, card_handler=lambda r: httpx.Response(200, json={"gpc": True}))
    assert len(_rule().evaluate({}, d)) == 1


def test_catalog_card_suppresses():
    d = _domain(None, 404, catalog=_catalog_with_card())
    assert d["mcp"]["ai_catalog"]["cards_found"] == 1
    assert _rule().evaluate({}, d) == []
    assert _measure(d) is None


def test_legacy_snapshot_without_catalog_is_judged_on_the_rest():
    absent = _domain(None, 404)
    del absent["mcp"]["ai_catalog"]
    assert len(_rule().evaluate({}, absent)) == 1
    assert _measure(absent) is None  # measured, D1
    valid = _domain(VALID_FILE, 200)
    del valid["mcp"]["ai_catalog"]
    assert _rule().evaluate({}, valid) == []
    assert _measure(valid) is None


def test_card_transport_error_without_positive_is_not_measured():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json={"specVersion": "1.0",
                                             "entries": [{"type": CARD_T, "url": "/card"}]})
        raise httpx.ConnectError("boom")
    d = _domain(None, 404, catalog=_catalog(handler))
    assert d["mcp"]["ai_catalog"]["card_fetch_errors"] == 1
    assert _measure(d) is NM


def test_catalog_transport_error_without_positive_is_not_measured():
    def handler(r):
        raise httpx.ConnectError("boom")
    d = _domain(None, 404, catalog=_catalog(handler))
    assert d["mcp"]["ai_catalog"]["fetch_status"] == "error"
    assert _measure(d) is NM


def test_ai_catalog_defaulted_is_not_measured():
    d = _domain(None, 404)
    assert _measure(d, defaulted=frozenset({"ai_catalog"})) is NM


def test_catalog_error_with_valid_file_is_measured_pass():
    def handler(r):
        raise httpx.ConnectError("boom")
    d = _domain(VALID_FILE, 200, catalog=_catalog(handler))
    assert _rule().evaluate({}, d) == []
    assert _measure(d) is None
    # even when the host named the catalog probe as defaulted
    assert _measure(d, defaulted=frozenset({"ai_catalog"})) is None


def test_outside_commerce_and_saas_is_na():
    d = _domain(None, 404, site_type="blog")
    assert _rule().evaluate({}, d) == []
    assert _measure(d, site_type="blog") is OutcomeState.NA


def test_mcp_block_defaulted_is_not_measured():
    d = _domain(None, 404)
    assert _measure(d, defaulted=frozenset({"mcp"})) is NM


# ── CORE-INTERFACE-001 ──────────────────────────────────────────────────

_INDEX = (
    "<!doctype html><html><head><title>Test</title></head><body>"
    "<h1>Test</h1><p>Minimal page with enough visible text for the parser "
    "to treat this as real content rather than an empty shell.</p></body></html>"
)


def test_core_interface_001_catalog_pass():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json={"specVersion": "1.0",
                                             "entries": [{"type": CARD_T, "data": CARD}]})
        return httpx.Response(404, text="not found")

    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    result = McpDiscoveryPresence().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.summary.startswith("An MCP server card is published through an AI Catalog.")
    assert result.evidence["ai_catalog"] == {"fetch_status": "ok", "valid": True, "cards_found": 1}


def test_core_interface_001_limitations_name_the_catalog():
    assert "ai-catalog.json" in McpDiscoveryPresence.limitations


# ── Core's own R2 adapter (D4) ──────────────────────────────────────────

def _adapter_evidence(catalog_handler):
    from scovant_core.r2.adapter import evidence_from_store  # noqa: PLC0415

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/.well-known/ai-catalog.json":
            return catalog_handler(request)
        return httpx.Response(404, text="not found")

    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    return evidence_from_store(store, site_type="commerce", root="https://example.com/")


def test_adapter_names_ai_catalog_defaulted_on_our_failure():
    def boom(request):
        raise httpx.ConnectError("boom", request=request)
    ev = _adapter_evidence(boom)
    assert "ai_catalog" in ev.defaulted
    assert ev.domain["mcp"]["ai_catalog"]["fetch_status"] == "error"
    assert _rule().measure({}, ev.domain, MeasureCtx("commerce", ev.defaulted)) is NM


def test_adapter_leaves_a_real_404_measured():
    ev = _adapter_evidence(lambda r: httpx.Response(404))
    assert "ai_catalog" not in ev.defaulted
    assert _rule().measure({}, ev.domain, MeasureCtx("commerce", ev.defaulted)) is None
    assert len(_rule().evaluate({}, {**ev.domain, "site_type": "commerce"})) == 1


def test_probe_rules_name_the_catalog_probe():
    from scovant_core.r2.readiness import _PROBE_RULES  # noqa: PLC0415
    assert _PROBE_RULES["ai_catalog"] == frozenset({"MCP_ENDPOINT_ABSENT"})


def test_catalog_card_wins_when_mcp_json_probe_failed():
    mcp = check_mcp_discovery(None, 0)
    mcp["ai_catalog"] = _catalog_with_card()
    d = {"site_type": "commerce", "mcp": mcp}
    assert _rule().evaluate({}, d) == []
    assert _measure(d, defaulted=frozenset({"mcp"})) is None
    # no surface + mcp probe failed stays NOT_MEASURED
    assert _measure(_domain(None, 0), defaulted=frozenset({"mcp"})) is NM
    # a missing or non-dict mcp block is no surface
    assert mcp_surface_found(None) is False and mcp_surface_found("x") is False
    assert _measure({"site_type": "commerce"}) is NM


def test_adapter_keeps_catalog_when_mcp_json_failed():
    def catalog(request):
        return httpx.Response(200, json={"specVersion": "1.0",
                                         "entries": [{"type": CARD_T, "url": "/mcp/server-card"}]})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(503)
        if request.url.path == "/mcp/server-card":
            return httpx.Response(200, json=CARD)
        return _adapter_routes(request, catalog)

    ev = _adapter_evidence_with(handler)
    assert "mcp" in ev.defaulted and "ai_catalog" not in ev.defaulted
    assert ev.domain["mcp"]["ai_catalog"]["cards_found"] == 1
    assert _rule().measure({}, ev.domain, MeasureCtx("commerce", ev.defaulted)) is None
    assert _rule().evaluate({}, {**ev.domain, "site_type": "commerce"}) == []


def test_adapter_failed_mcp_json_and_failed_catalog_is_not_measured():
    def boom(request):
        raise httpx.ConnectError("boom", request=request)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(503)
        return _adapter_routes(request, boom)

    ev = _adapter_evidence_with(handler)
    assert {"mcp", "ai_catalog"} <= ev.defaulted
    assert _rule().measure({}, ev.domain, MeasureCtx("commerce", ev.defaulted)) is NM


def _adapter_routes(request, catalog_handler):
    path = request.url.path
    if path == "/":
        return httpx.Response(200, content=_INDEX.encode(), headers={"content-type": "text/html"})
    if path == "/.well-known/ai-catalog.json":
        return catalog_handler(request)
    return httpx.Response(404, text="not found")


def _adapter_evidence_with(handler):
    from scovant_core.r2.adapter import evidence_from_store  # noqa: PLC0415

    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    return evidence_from_store(store, site_type="commerce", root="https://example.com/")


# ── unusable answers and a cut catalog (final review D1/D2) ─────────────

def _status(code):
    return lambda r: httpx.Response(code)


def test_catalog_429_without_positive_is_not_measured():
    d = _domain(None, 404, catalog=_catalog(_status(429)))
    assert _measure(d) is NM


def test_catalog_503_without_positive_is_not_measured():
    d = _domain(None, 404, catalog=_catalog(_status(503)))
    assert _measure(d) is NM


def test_catalog_403_with_nothing_else_is_a_measured_fail():
    d = _domain(None, 404, catalog=_catalog(_status(403)))
    assert _measure(d) is None
    assert len(_rule().evaluate({}, d)) == 1


def test_card_503_without_positive_is_not_measured():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json={"specVersion": "1.0",
                                             "entries": [{"type": CARD_T, "url": "/card"}]})
        return httpx.Response(503)
    d = _domain(None, 404, catalog=_catalog(handler))
    assert d["mcp"]["ai_catalog"]["card_fetch_errors"] == 1
    assert _measure(d) is NM


def test_truncated_catalog_without_positive_is_not_measured():
    big = '{"specVersion":"1.0","entries":[' + "1," * 400_000 + "1]}"
    d = _domain(None, 404, catalog=_catalog(lambda r: httpx.Response(200, text=big)))
    assert d["mcp"]["ai_catalog"]["truncated"] is True
    assert _measure(d) is NM
    # a surface found elsewhere wins over a cut catalog
    assert _measure(_domain(VALID_FILE, 200,
                            catalog=_catalog(lambda r: httpx.Response(200, text=big)))) is None


def test_adapter_names_ai_catalog_defaulted_on_a_503_catalog():
    ev = _adapter_evidence(_status(503))
    assert "ai_catalog" in ev.defaulted
    assert _rule().measure({}, ev.domain, MeasureCtx("commerce", ev.defaulted)) is NM


def test_adapter_keeps_old_path_card_when_mcp_json_failed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/mcp.json":
            return httpx.Response(503)
        if request.url.path == "/.well-known/mcp/server-card.json":
            return httpx.Response(200, json=CARD)
        return _adapter_routes(request, _not_found)

    ev = _adapter_evidence_with(handler)
    assert "mcp" in ev.defaulted
    assert ev.domain["mcp"]["server_card"] is True
    assert _rule().measure({}, ev.domain, MeasureCtx("commerce", ev.defaulted)) is None
    assert _rule().evaluate({}, {**ev.domain, "site_type": "commerce"}) == []
