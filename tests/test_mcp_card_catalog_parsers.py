"""SEP-2127 server-card predicate, AI Catalog parser, discovery json_object."""
from __future__ import annotations

import json
from pathlib import Path

from scovant_core.parsers.mcp import (
    CARD_MEDIA_TYPE,
    check_mcp_discovery,
    is_server_card,
    parse_ai_catalog,
)

CARD = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp_server_card.json").read_text()
)


def test_server_card_shapes():
    assert is_server_card(CARD)
    assert is_server_card({"serverInfo": {"name": "x"}, "capabilities": {}})
    for bad in (
        {"gpc": True, "lastUpdate": "x"},
        {"ip": "address", "city": "x"},
        {"error": "not found"},
        [],
        "x",
        {"name": ""},
        {"name": "only-a-name"},
    ):
        assert not is_server_card(bad), bad


def _entry(i, type_=CARD_MEDIA_TYPE):
    return {"identifier": f"i{i}", "type": type_, "url": f"https://example.com/c{i}.json"}


def test_catalog_parse():
    cat = {"specVersion": "1.0", "entries": [_entry(i) for i in range(5)]}
    out = parse_ai_catalog(cat)
    assert out["valid"] and out["spec_version"] == "1.0" and out["entries"] == 5
    assert len(out["card_urls"]) == 3
    assert out["card_urls"][0] == "https://example.com/c0.json"
    assert out["inline_cards"] == 0
    assert parse_ai_catalog({"entries": []})["valid"] is False
    assert parse_ai_catalog([])["valid"] is False


def test_catalog_inline_cards():
    e = _entry(0)
    del e["url"]
    e["data"] = CARD
    out = parse_ai_catalog({"specVersion": "1.0", "entries": [e, {**_entry(1), "data": {"x": 1}}]})
    assert out["inline_cards"] == 1


def test_card_entry_type_ignores_case_and_parameters():
    t = "Application/MCP-Server-Card+JSON; charset=utf-8"
    out = parse_ai_catalog({"specVersion": "1.0", "entries": [_entry(0, t), _entry(1, "text/html")]})
    assert out["card_urls"] == ["https://example.com/c0.json"]


def test_discovery_json_object_flag():
    html = check_mcp_discovery("<html></html>", 200)
    assert html["exists"] and not html["json_object"]
    empty = check_mcp_discovery("{}", 200)
    assert empty["json_object"] and not empty["valid"]
    ok = check_mcp_discovery('{"mcpServers":{"a":{"url":"https://example.com/mcp"}}}', 200)
    assert ok["json_object"] and ok["valid"]
    assert check_mcp_discovery(None, 404)["json_object"] is False
    assert check_mcp_discovery("[]", 200)["json_object"] is False
