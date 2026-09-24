from __future__ import annotations

import json

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.parsers.html import extract_hidden_text

from .conftest import make_client

HTML = """<!doctype html><html><head><title>T</title><meta name="description" content="Meta says hello">
<script type="application/ld+json">{"@type":"Product","description":"JSON-LD says hi"}</script></head>
<body><h1>Visible</h1><p>Visible paragraph with enough words to be content for the parser here.</p>
<div style="display:none">Hidden block text</div><span aria-hidden="true">aria hidden text</span>
<p style="position:absolute;left:-9999px">offscreen text</p></body></html>"""


def test_extract_hidden_text_collects_display_none_aria_hidden_and_offscreen():
    t = extract_hidden_text(HTML)
    assert "Hidden block text" in t and "aria hidden text" in t and "offscreen text" in t
    assert "Visible paragraph" not in t


def test_extract_hidden_text_handles_nested_hidden_elements_without_crashing():
    """A `display:none` wrapper containing a `hidden`-attr child and an
    aria-hidden child: `decompose()` on the outer element also decomposes
    its descendants, but they are still in the pre-materialised
    `find_all(True)` list — regression for AttributeError on the second
    hit."""
    nested_html = (
        '<html><body><div style="display:none">'
        '<span hidden>inner hidden span</span>'
        '<em aria-hidden="true">inner aria span</em>'
        "wrapper text"
        "</div></body></html>"
    )
    t = extract_hidden_text(nested_html)
    assert "inner hidden span" in t
    assert "wrapper text" in t


def _store(handler, url="https://example.com/"):
    client = make_client(handler)
    ctx = ScanContext(url, ScanOptions())
    return EvidenceStore(client, ctx)


def test_machine_text_collects_surfaces_without_new_fetches():
    def handler(req: httpx.Request):
        p = req.url.path
        if p == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=HTML)
        if p == "/llms.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text="# Site\n> summary\n")
        if p == "/.well-known/mcp.json":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                text=json.dumps(
                    {"mcpServers": {"s": {"url": "https://example.com/mcp", "transport": "http", "description": "Server desc"}}}
                ),
            )
        return httpx.Response(404, text="nf")

    store = _store(handler)
    store.get("http")
    store.get("llms")
    store.get("mcp_discovery")
    requests_before = len(store.client.requests)
    mt = store.get("machine_text")
    assert len(store.client.requests) == requests_before
    kinds = {s["kind"] for s in mt["surfaces"]}
    assert {"llms_txt", "mcp_discovery", "mcp_server_description", "json_ld", "meta_description", "hidden_dom"} <= kinds
    assert any(s["text"] == "Server desc" for s in mt["surfaces"] if s["kind"] == "mcp_server_description")
    assert mt["capped"] is False


def test_machine_text_reads_only_already_gathered_stores():
    store = _store(lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=HTML))
    store.get("http")
    mt = store.get("machine_text")
    assert {s["kind"] for s in mt["surfaces"]} == {"json_ld", "meta_description", "hidden_dom"}


def test_machine_text_caps_total_chars():
    big = "x" * 300_000

    def handler(req):
        if req.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=HTML)
        if req.url.path == "/llms.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=big)
        return httpx.Response(404, text="nf")

    store = _store(handler)
    store.get("http")
    store.get("llms")
    mt = store.get("machine_text")
    assert mt["capped"] is True and mt["total_chars"] <= 256 * 1024


def test_machine_text_isolates_a_failing_html_extractor(monkeypatch):
    """One extractor raising on a malformed page must not blank the whole
    record: the other surfaces are still gathered and the failure is
    recorded in `errors` (never swallowed, never fatal)."""
    from scovant_core.gatherers import machine_text as mt_mod

    def boom(html):  # noqa: ARG001
        raise ValueError("not enough values to unpack (expected 2, got 1)")

    monkeypatch.setattr(mt_mod, "extract_webmcp_tools", boom)
    client = make_client(lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=HTML))
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    store.try_get("http")
    mt = store.get("machine_text")
    assert {s["kind"] for s in mt["surfaces"]} >= {"json_ld", "meta_description"}
    assert mt["errors"] == [{"surface": "webmcp_tool", "kind": "ValueError",
                             "message": "not enough values to unpack (expected 2, got 1)"}]
