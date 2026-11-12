"""AI Catalog follow + card-shaped old paths (MCP discovery correctness)."""
import httpx

from scovant_core.gatherers.mcp_metadata import probe_ai_catalog, probe_mcp_server_card

ORIGIN = "https://example.com"
CARD_T = "application/mcp-server-card+json"
CARD = {"name": "io.example/srv", "version": "1.0.0", "remotes": []}


def _client(handler):
    seen: list[str] = []

    def wrapped(request):
        seen.append(str(request.url))
        return handler(request)

    return httpx.Client(transport=httpx.MockTransport(wrapped)), seen


def _cat(*entries):
    return {"specVersion": "1.0", "entries": list(entries)}


def test_old_path_non_card_json_is_not_a_card():
    c, _ = _client(lambda r: httpx.Response(200, json={"gpc": True}))
    assert probe_mcp_server_card(c, ORIGIN)["exists"] is False


def test_old_path_real_card_still_detected():
    c, _ = _client(lambda r: httpx.Response(200, json=CARD))
    assert probe_mcp_server_card(c, ORIGIN)["exists"] is True


def test_catalog_card_resolves_relative_cross_origin_and_inline():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json=_cat(
                {"type": CARD_T, "url": "/mcp/server-card"},
                {"type": CARD_T, "url": "https://mcp.example.net/mcp/server-card"},
                {"type": CARD_T, "data": CARD},
            ))
        return httpx.Response(200, json=CARD)

    c, seen = _client(handler)
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok" and out["valid"] is True
    assert out["card_entries"] == 3
    assert out["cards_found"] == 3
    assert "https://example.com/mcp/server-card" in seen
    assert "https://mcp.example.net/mcp/server-card" in seen


def test_catalog_404_is_ok_not_error():
    c, _ = _client(lambda r: httpx.Response(404))
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok"
    assert out["valid"] is False and out["cards_found"] == 0


def test_catalog_transport_error_is_error():
    def handler(r):
        raise httpx.ConnectError("boom")

    c, _ = _client(handler)
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "error"
    assert out["cards_found"] == 0


def test_card_transport_error_counts():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json=_cat({"type": CARD_T, "url": "/card"}))
        raise httpx.ConnectError("boom")

    c, _ = _client(handler)
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok"
    assert out["card_fetch_errors"] == 1 and out["cards_found"] == 0


def test_unsafe_or_plain_http_card_urls_are_skipped_not_errors():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json=_cat(
                {"type": CARD_T, "url": "http://example.com/card"},
                {"type": CARD_T, "url": "https://10.0.0.5/"},
                {"type": CARD_T, "url": "https://localhost/"},
            ))
        return httpx.Response(200, json=CARD)

    c, seen = _client(handler)
    out = probe_ai_catalog(c, ORIGIN)
    assert seen == ["https://example.com/.well-known/ai-catalog.json"]
    assert out["card_fetch_errors"] == 0 and out["cards_found"] == 0


def test_catalog_fetches_at_most_three_cards_and_caps_the_body():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json=_cat(
                *[{"type": CARD_T, "url": f"/c{i}"} for i in range(1000)]))
        return httpx.Response(200, json=CARD)

    c, seen = _client(handler)
    out = probe_ai_catalog(c, ORIGIN)
    assert len(seen) == 4 and out["cards_found"] == 3
    assert out["card_entries"] == 1000

    big = '{"specVersion":"1.0","entries":[' + "1," * 400_000 + "1]}"
    c2, _ = _client(lambda r: httpx.Response(200, text=big))
    out2 = probe_ai_catalog(c2, ORIGIN)
    assert out2["truncated"] is True and out2["valid"] is False


# ── unusable answers (final review D1) ──────────────────────────────────

def test_catalog_status_is_recorded():
    c, _ = _client(lambda r: httpx.Response(404))
    assert probe_ai_catalog(c, ORIGIN)["status"] == 404

    def boom(r):
        raise httpx.ConnectError("boom")
    c2, _ = _client(boom)
    assert probe_ai_catalog(c2, ORIGIN)["status"] is None


def test_catalog_429_and_5xx_are_unanswered():
    for status in (429, 500, 503):
        c, seen = _client(lambda r, s=status: httpx.Response(s))
        out = probe_ai_catalog(c, ORIGIN)
        assert out["fetch_status"] == "error" and out["status"] == status, status
        assert len(seen) == 1


def test_catalog_403_is_an_answered_absence():
    c, _ = _client(lambda r: httpx.Response(403))
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok" and out["status"] == 403 and out["valid"] is False


def test_card_429_or_5xx_counts_as_a_fetch_error_but_404_does_not():
    def handler(r):
        if r.url.path == "/.well-known/ai-catalog.json":
            return httpx.Response(200, json=_cat({"type": CARD_T, "url": "/a"},
                                                 {"type": CARD_T, "url": "/b"},
                                                 {"type": CARD_T, "url": "/c"}))
        return httpx.Response({"/a": 503, "/b": 429, "/c": 404}[r.url.path])

    c, _ = _client(handler)
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok" and out["status"] == 200
    assert out["card_fetch_errors"] == 2 and out["cards_found"] == 0


def _redirecting(routes):
    """routes: url -> Response; anything else 404."""
    def handler(r):
        return routes.get(str(r.url), httpx.Response(404))
    return _client(handler)


def test_catalog_behind_a_redirect_is_followed():
    c, seen = _redirecting({
        f"{ORIGIN}/.well-known/ai-catalog.json": httpx.Response(
            301, headers={"location": "https://www.example.com/.well-known/ai-catalog.json"}),
        "https://www.example.com/.well-known/ai-catalog.json": httpx.Response(
            200, json=_cat({"type": CARD_T, "url": "/mcp/server-card"})),
        "https://www.example.com/mcp/server-card": httpx.Response(
            308, headers={"location": "/mcp/card.json"}),
        "https://www.example.com/mcp/card.json": httpx.Response(200, json=CARD),
    })
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok" and out["status"] == 200 and out["valid"] is True
    assert out["cards_found"] == 1 and out["card_fetch_errors"] == 0
    assert "https://www.example.com/mcp/card.json" in seen


def test_redirect_to_plain_http_stops_and_is_an_answer():
    c, seen = _redirecting({
        f"{ORIGIN}/.well-known/ai-catalog.json": httpx.Response(
            302, headers={"location": "http://example.com/.well-known/ai-catalog.json"}),
    })
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "ok" and out["status"] == 302 and out["valid"] is False
    assert seen == [f"{ORIGIN}/.well-known/ai-catalog.json"]


def test_redirect_loop_is_no_answer():
    url = f"{ORIGIN}/.well-known/ai-catalog.json"
    c, seen = _redirecting({url: httpx.Response(302, headers={"location": url})})
    out = probe_ai_catalog(c, ORIGIN)
    assert out["fetch_status"] == "error" and out["status"] is None
    assert len(seen) == 6


def test_redirect_without_location_is_no_answer():
    c, _ = _redirecting({f"{ORIGIN}/.well-known/ai-catalog.json": httpx.Response(301)})
    assert probe_ai_catalog(c, ORIGIN)["fetch_status"] == "error"


def test_truncated_card_in_a_valid_catalog_is_counted_not_absent():
    from scovant_core.gatherers._http import _PROBE_BODY_CAP
    from scovant_core.rules.mcp import ai_catalog_unanswered

    big = '{"name": "io.example/srv", "pad": "' + "x" * _PROBE_BODY_CAP + '"}'
    c, _ = _redirecting({
        f"{ORIGIN}/.well-known/ai-catalog.json": httpx.Response(
            200, json=_cat({"type": CARD_T, "url": "/mcp/server-card"})),
        f"{ORIGIN}/mcp/server-card": httpx.Response(200, text=big),
    })
    out = probe_ai_catalog(c, ORIGIN)
    assert out["valid"] is True and out["cards_found"] == 0
    assert out["cards_truncated"] == 1 and out["card_fetch_errors"] == 0
    assert ai_catalog_unanswered({"exists": False, "ai_catalog": out}) is True


def test_untruncated_non_card_in_a_valid_catalog_is_a_measured_absence():
    from scovant_core.rules.mcp import ai_catalog_unanswered

    c, _ = _redirecting({
        f"{ORIGIN}/.well-known/ai-catalog.json": httpx.Response(
            200, json=_cat({"type": CARD_T, "url": "/mcp/server-card"})),
        f"{ORIGIN}/mcp/server-card": httpx.Response(200, json={"gpc": True}),
    })
    out = probe_ai_catalog(c, ORIGIN)
    assert out["cards_truncated"] == 0
    assert ai_catalog_unanswered({"exists": False, "ai_catalog": out}) is False
