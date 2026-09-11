"""Network gatherer probes: httpx.MockTransport-based unit tests.

Each gatherer takes an httpx.Client (already wired up by the caller) and a
domain, issues one or more bounded-timeout GETs/POSTs, and never raises
except to propagate SoftTimeLimitExceeded (the host's cooperative-cancel
signal, threaded through scovant_core.compat) — every other failure degrades
to an inert/empty result shape.
"""
import httpx
import pytest

from scovant_core.compat import SoftTimeLimitExceeded
from scovant_core.gatherers._http import _PROBE_TIMEOUT
from scovant_core.gatherers.agent_discovery import check_agent_discovery
from scovant_core.gatherers.agent_payments import check_agent_payments
from scovant_core.gatherers.link_headers import check_link_headers
from scovant_core.gatherers.machine_rep import check_machine_rep
from scovant_core.gatherers.markdown import check_markdown_negotiation
from scovant_core.gatherers.mcp_metadata import probe_mcp_server_card
from scovant_core.gatherers.oauth import probe_mcp_oauth_discovery
from scovant_core.gatherers.probe_tables import PAYMENT_PROBES
from scovant_core.gatherers.sitemap import check_sitemap

DOMAIN = "https://example.com"


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


# ── check_sitemap ─────────────────────────────────────────────────────────

_URLSET = '<?xml version="1.0"?><urlset xmlns="https://example.com/schemas/sitemap/0.9"><url><loc>https://example.com/</loc></url></urlset>'
_INDEX = '<?xml version="1.0"?><sitemapindex xmlns="https://example.com/schemas/sitemap/0.9"><sitemap><loc>https://example.com/s1.xml</loc></sitemap></sitemapindex>'


def test_sitemap_urlset_at_default_path():
    def handler(request):
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text=_URLSET, headers={"content-type": "application/xml"})
        return httpx.Response(404)

    r = check_sitemap(_client(handler), DOMAIN, [])
    assert r == {"exists": True, "valid": True, "url": f"{DOMAIN}/sitemap.xml", "kind": "urlset",
                 "truncated": False}


def test_sitemap_robots_directive_takes_priority():
    def handler(request):
        if request.url.path == "/custom-map.xml":
            return httpx.Response(200, text=_INDEX, headers={"content-type": "application/xml"})
        return httpx.Response(404)

    r = check_sitemap(_client(handler), DOMAIN, [f"{DOMAIN}/custom-map.xml"])
    assert r["valid"] is True and r["kind"] == "sitemapindex"


def test_sitemap_html_response_invalid():
    def handler(request):
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text="<html>soft 404</html>")
        return httpx.Response(404)

    r = check_sitemap(_client(handler), DOMAIN, [])
    assert r["exists"] is True and r["valid"] is False


def test_sitemap_nothing_found():
    r = check_sitemap(_client(lambda req: httpx.Response(404)), DOMAIN, [])
    assert r == {"exists": False, "valid": False, "url": None, "kind": None, "truncated": False}


# ── check_link_headers ────────────────────────────────────────────────────


def test_link_headers_absent():
    result = check_link_headers(_client(lambda r: httpx.Response(200)), DOMAIN)
    assert result == {"present": False, "rels": [], "agent_relevant": False}


def test_link_headers_present_but_not_agent_relevant():
    def handler(request):
        return httpx.Response(
            200,
            headers=[("link", '</style.css>; rel=preload; as=style'),
                     ("link", '</next>; rel="next"')],
        )

    result = check_link_headers(_client(handler), DOMAIN)
    assert result["present"] is True
    assert "preload" in result["rels"] and "next" in result["rels"]
    assert result["agent_relevant"] is False


@pytest.mark.parametrize("rel", ["api-catalog", "service-desc", "service-doc"])
def test_link_headers_agent_relevant_rels(rel):
    def handler(request):
        return httpx.Response(
            200, headers={"link": f'</.well-known/{rel}>; rel="{rel}"'}
        )

    result = check_link_headers(_client(handler), DOMAIN)
    assert result["present"] is True
    assert rel in result["rels"]
    assert result["agent_relevant"] is True


def test_link_headers_multi_rel_value_split():
    """rel is a whitespace-separated list of relation types (RFC 8288 §3.3)."""
    def handler(request):
        return httpx.Response(
            200, headers={"link": '</api>; rel="alternate api-catalog"'}
        )

    result = check_link_headers(_client(handler), DOMAIN)
    assert result["rels"] == ["alternate", "api-catalog"]
    assert result["agent_relevant"] is True


def test_link_headers_rel_case_insensitive():
    def handler(request):
        return httpx.Response(200, headers={"link": '</api>; rel="API-Catalog"'})

    result = check_link_headers(_client(handler), DOMAIN)
    assert result["agent_relevant"] is True


def test_link_headers_probe_hits_homepage_with_probe_timeout():
    captured = []

    def handler(request):
        captured.append((request.url.path, request.extensions.get("timeout")))
        return httpx.Response(200)

    check_link_headers(_client(handler), DOMAIN)
    assert captured == [("/", {"connect": _PROBE_TIMEOUT, "read": _PROBE_TIMEOUT,
                               "write": _PROBE_TIMEOUT, "pool": _PROBE_TIMEOUT})]


def test_link_headers_transport_error_degrades_to_absent():
    def handler(request):
        raise httpx.ConnectError("boom")

    result = check_link_headers(_client(handler), DOMAIN)
    assert result == {"present": False, "rels": [], "agent_relevant": False}


def test_link_headers_soft_time_limit_propagates():
    def handler(request):
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        check_link_headers(_client(handler), DOMAIN)


# ── probe_mcp_server_card ───────────────────────────────────────────────


@pytest.mark.parametrize("path", [
    "/.well-known/mcp/server-card.json",
    "/.well-known/mcp/server-cards.json",
])
def test_server_card_detected_on_either_path(path):
    def handler(request):
        if request.url.path == path:
            return httpx.Response(200, json={"name": "srv"})
        return httpx.Response(404)

    result = probe_mcp_server_card(_client(handler), DOMAIN)
    assert result["exists"] is True
    assert result["truncated"] is False


def test_server_card_absent_and_non_json_rejected():
    result = probe_mcp_server_card(_client(lambda r: httpx.Response(404)), DOMAIN)
    assert result["exists"] is False
    assert result["truncated"] is False

    def soft404(request):
        return httpx.Response(200, text="<html>404</html>",
                              headers={"content-type": "text/html"})

    result = probe_mcp_server_card(_client(soft404), DOMAIN)
    assert result["exists"] is False
    assert result["truncated"] is False


def test_server_card_truncated_body_reports_unknown_not_absent():
    """A body cut off at the fetch cap must not read as a confirmed
    absence — `exists` must be `None` ("could not tell"), never `False`."""
    from scovant_core.gatherers._http import _PROBE_BODY_CAP

    big = '{"name": "' + ("x" * _PROBE_BODY_CAP) + '"'  # deliberately unterminated + oversized

    def handler(request):
        if request.url.path == "/.well-known/mcp/server-card.json":
            return httpx.Response(200, text=big, headers={"content-type": "application/json"})
        return httpx.Response(404)

    result = probe_mcp_server_card(_client(handler), DOMAIN)
    assert result["exists"] is None
    assert result["truncated"] is True


# ── probe_mcp_oauth_discovery ────────────────────────────────────────────


def test_oauth_discovered_true_on_valid_resource_metadata():
    def handler(request):
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, json={
                "resource": "https://example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            })
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json={"issuer": "https://auth.example.com"})
        return httpx.Response(404)

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["attempted"] is True
    assert result["discovered"] is True
    assert result["auth_server_metadata_ok"] is True
    assert result["resource_metadata"]["authorization_servers"] == ["https://auth.example.com"]


def test_oauth_discovered_false_on_404():
    def handler(request):
        return httpx.Response(404)

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["attempted"] is True
    assert result["discovered"] is False
    assert result["error"] == "HTTP 404"


def test_oauth_discovered_false_on_malformed_json():
    def handler(request):
        return httpx.Response(200, text="not json")

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["discovered"] is False
    assert result["error"] == "response is not valid JSON"


def test_oauth_discovered_false_when_authorization_servers_missing():
    def handler(request):
        return httpx.Response(200, json={"resource": "https://example.com/mcp"})

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["discovered"] is False
    assert result["error"] == "no authorization_servers in resource metadata"


def test_oauth_discovered_false_when_authorization_servers_empty():
    def handler(request):
        return httpx.Response(200, json={"authorization_servers": []})

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["discovered"] is False


def test_oauth_discovered_true_even_if_as_metadata_fetch_fails():
    def handler(request):
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, json={
                "authorization_servers": ["https://auth.example.com"],
            })
        return httpx.Response(500)

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["discovered"] is True
    assert result["auth_server_metadata_ok"] is False


def test_oauth_never_raises_on_transport_failure():
    def handler(request):
        raise httpx.ConnectError("boom")

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["attempted"] is True
    assert result["discovered"] is False
    assert result["error"]


def test_oauth_invalid_endpoint_url_degrades_gracefully():
    def handler(request):
        return httpx.Response(200)

    result = probe_mcp_oauth_discovery(_client(handler), "not-a-url")
    assert result["attempted"] is False
    assert result["discovered"] is False
    assert result["error"] == "invalid endpoint URL"


def test_oauth_response_not_a_json_object():
    def handler(request):
        return httpx.Response(200, json=["not", "an", "object"])

    result = probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")
    assert result["discovered"] is False
    assert result["error"] == "response is not a JSON object"


def test_oauth_requests_the_endpoint_origin_well_known_path():
    seen_urls = []

    def handler(request):
        seen_urls.append(str(request.url))
        return httpx.Response(404)

    probe_mcp_oauth_discovery(_client(handler), "https://example.com/some/mcp/path")
    assert seen_urls == ["https://example.com/.well-known/oauth-protected-resource"]


def test_oauth_soft_time_limit_propagates():
    def handler(request):
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        probe_mcp_oauth_discovery(_client(handler), "https://example.com/mcp")


# ── check_agent_discovery ─────────────────────────────────────────────────


def test_discovery_probes_carry_5s_timeout():
    captured_timeouts = []

    def handler(request):
        captured_timeouts.append(request.extensions.get("timeout"))
        return httpx.Response(404)

    check_agent_discovery(_client(handler), DOMAIN)

    assert captured_timeouts, "expected at least one discovery probe request"
    expected = {"connect": _PROBE_TIMEOUT, "read": _PROBE_TIMEOUT,
                "write": _PROBE_TIMEOUT, "pool": _PROBE_TIMEOUT}
    for timeout in captured_timeouts:
        assert timeout == expected


def test_discovery_none_found():
    result = check_agent_discovery(_client(lambda r: httpx.Response(404)), DOMAIN)
    assert result["any_found"] is False
    assert all(s["exists"] is False for s in result["surfaces"].values())


def test_discovery_openapi_found():
    def handler(request):
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"openapi": "3.1.0"})
        return httpx.Response(404)

    result = check_agent_discovery(_client(handler), DOMAIN)
    assert result["surfaces"]["openapi_root"]["exists"] is True
    assert result["any_found"] is True


def test_discovery_agents_txt_html_soft404_rejected():
    def handler(request):
        if request.url.path == "/agents.txt":
            return httpx.Response(200, text="<html>404</html>",
                                  headers={"content-type": "text/html"})
        return httpx.Response(404)

    result = check_agent_discovery(_client(handler), DOMAIN)
    assert result["surfaces"]["agents_txt"]["exists"] is False


@pytest.mark.parametrize("key,path,payload", [
    ("agent_skills", "/.well-known/agent-skills/index.json",
     {"skills": [{"name": "checkout"}]}),
    ("agent_skills_legacy", "/.well-known/skills/index.json",
     {"skills": [{"name": "checkout"}]}),
])
def test_discovery_agent_skills_index_paths(key, path, payload):
    def handler(request):
        if request.url.path == path:
            return httpx.Response(200, json=payload)
        return httpx.Response(404)

    result = check_agent_discovery(_client(handler), DOMAIN)
    assert result["surfaces"][key]["exists"] is True
    assert result["any_found"] is True


def test_discovery_llms_full_txt():
    def handler(request):
        if request.url.path == "/llms-full.txt":
            return httpx.Response(200, text="# Full site content\n...",
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404)

    result = check_agent_discovery(_client(handler), DOMAIN)
    assert result["surfaces"]["llms_full_txt"]["exists"] is True
    assert result["any_found"] is True


def test_discovery_soft_time_limit_exceeded_propagates_not_swallowed():
    """SoftTimeLimitExceeded must bubble out of check_agent_discovery instead
    of being caught by the generic `except Exception` degrade-to-empty path."""
    def handler(request):
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        check_agent_discovery(_client(handler), DOMAIN)


# ── check_markdown_negotiation ────────────────────────────────────────────


def test_markdown_negotiation_probes_carry_5s_timeout():
    captured_timeouts = []

    def handler(request):
        captured_timeouts.append(request.extensions.get("timeout"))
        return httpx.Response(404)

    check_markdown_negotiation(_client(handler), DOMAIN)

    assert len(captured_timeouts) == 2  # homepage negotiation + /index.md mirror
    expected = {"connect": _PROBE_TIMEOUT, "read": _PROBE_TIMEOUT,
                "write": _PROBE_TIMEOUT, "pool": _PROBE_TIMEOUT}
    for timeout in captured_timeouts:
        assert timeout == expected


def test_markdown_negotiation_detected():
    def handler(request):
        if request.url.path == "/" and "text/markdown" in request.headers.get("accept", ""):
            return httpx.Response(200, text="# Home",
                                  headers={"content-type": "text/markdown",
                                           "x-markdown-tokens": "512",
                                           "vary": "Accept"})
        return httpx.Response(404)

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["negotiation"] is True
    assert result["markdown_tokens"] == 512
    # Raw negotiation-response shape, from the same request, no new request.
    assert result["status"] == 200
    assert result["content_type"] == "text/markdown"
    assert result["vary"] == "Accept"
    assert result["looks_markdown"] is True


def test_markdown_negotiation_empty_body_rejected():
    def handler(request):
        if request.url.path == "/" and "text/markdown" in request.headers.get("accept", ""):
            return httpx.Response(200, text="   \n  ",
                                  headers={"content-type": "text/markdown"})
        return httpx.Response(404)

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["negotiation"] is False
    assert result["markdown_tokens"] is None
    # Right content-type, but no markdown markers in the (blank) body.
    assert result["looks_markdown"] is False


def test_markdown_mirror_detected():
    def handler(request):
        if request.url.path == "/index.md":
            return httpx.Response(200, text="# Home",
                                  headers={"content-type": "text/markdown"})
        return httpx.Response(200, text="<html></html>",
                              headers={"content-type": "text/html"})

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["negotiation"] is False
    assert result["mirror"] is True
    assert result["looks_markdown"] is False


def test_markdown_nothing():
    def handler(request):
        return httpx.Response(200, text="<html></html>",
                              headers={"content-type": "text/html"})

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    # The four ORIGINAL keys keep their exact old values — a downstream rule
    # reads them unchanged. The extended keys are purely additive.
    assert result == {
        "negotiation": False, "mirror": False, "markdown_tokens": None,
        "status": 200, "content_type": "text/html", "vary": None,
        "looks_markdown": False, "body_looks_markdown": False,
        "truncated": False,
    }


def test_markdown_looks_markdown_html_content_type_lie():
    """looks_markdown branch: content-type CLAIMS markdown but the body is
    actually HTML — heuristic must say False (a lying/misconfigured server)."""
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<!DOCTYPE html><html><body>hi</body></html>",
                                  headers={"content-type": "text/markdown"})
        return httpx.Response(404)

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["content_type"] == "text/markdown"
    assert result["looks_markdown"] is False


def test_markdown_looks_markdown_text_plain_with_link_marker():
    """looks_markdown branch: text/plain content-type + a `](` link marker,
    no heading needed — either marker is sufficient."""
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="See [docs](https://example.com/docs) for more.",
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404)

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["looks_markdown"] is True


def test_markdown_looks_markdown_wrong_content_type_never_checked():
    """looks_markdown branch: content-type is neither markdown nor
    text/plain — heuristic short-circuits False even with markdown-shaped
    body content."""
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="# Heading\n\n[link](https://example.com)",
                                  headers={"content-type": "application/json"})
        return httpx.Response(404)

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["looks_markdown"] is False


def test_markdown_negotiation_transport_error_degrades():
    """A non-SoftTimeLimit exception on the negotiation GET must degrade to
    the empty extended shape, not crash — mirror probe still runs."""
    def handler(request):
        if request.url.path == "/":
            raise httpx.ConnectError("boom")
        return httpx.Response(404)

    result = check_markdown_negotiation(_client(handler), DOMAIN)
    assert result["status"] is None
    assert result["content_type"] is None
    assert result["vary"] is None
    assert result["looks_markdown"] is False
    assert result["negotiation"] is False


def test_markdown_negotiation_soft_time_limit_exceeded_propagates_not_swallowed():
    def handler(request):
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        check_markdown_negotiation(_client(handler), DOMAIN)


# ── check_machine_rep ───────────────────────────────────────────────────


def test_machine_rep_preference_applied_and_vary_recorded():
    def handler(request):
        assert request.headers.get("prefer") == "return=consolidated"
        assert "text/markdown" in request.headers.get("accept", "")
        return httpx.Response(
            200, text="# Consolidated",
            headers={"content-type": "text/markdown",
                     "preference-applied": "return=consolidated",
                     "vary": "Accept, Prefer"},
        )

    result = check_machine_rep(_client(handler), DOMAIN, homepage_html=None)
    assert result["attempted"] is True
    assert result["status"] == 200
    assert result["content_type"] == "text/markdown"
    assert result["preference_applied"] == "return=consolidated"
    assert result["vary"] == "Accept, Prefer"


def test_machine_rep_alternates_parsed_from_passed_homepage_html_not_a_new_request():
    """alternates must come from the PASSED homepage_html — not from an
    extra request. The mocked negotiated response here is markdown (no
    <link> tags of its own), proving alternates couldn't have come from it."""
    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        return httpx.Response(200, text="# md", headers={"content-type": "text/markdown"})

    homepage_html = (
        '<html><head>'
        '<link rel="alternate" type="application/rss+xml" href="/feed.xml">'
        '<link rel="alternate" type="application/json" href="/feed.json">'
        '<link rel="stylesheet" type="text/css" href="/s.css">'
        '</head></html>'
    )
    result = check_machine_rep(_client(handler), DOMAIN, homepage_html=homepage_html)
    assert result["alternates"] == ["application/rss+xml", "application/json"]
    assert call_count["n"] == 1  # exactly ONE request total


def test_machine_rep_alternates_empty_without_homepage_html_and_non_html_response():
    def handler(request):
        return httpx.Response(200, text="# md", headers={"content-type": "text/markdown"})

    result = check_machine_rep(_client(handler), DOMAIN, homepage_html=None)
    assert result["alternates"] == []


def test_machine_rep_406_degrades_gracefully_but_attempted():
    def handler(request):
        return httpx.Response(406)

    result = check_machine_rep(_client(handler), DOMAIN, homepage_html=None)
    assert result["attempted"] is True
    assert result["status"] == 406


def test_machine_rep_transport_error_degrades():
    def handler(request):
        raise httpx.ConnectError("boom")

    result = check_machine_rep(_client(handler), DOMAIN, homepage_html=None)
    assert result == {
        "attempted": False, "status": None, "content_type": None,
        "preference_applied": None, "vary": None, "alternates": [],
        "truncated": False,
    }


def test_machine_rep_soft_time_limit_exceeded_propagates_not_swallowed():
    def handler(request):
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        check_machine_rep(_client(handler), DOMAIN, homepage_html=None)


def test_machine_rep_carries_5s_timeout():
    captured_timeouts = []

    def handler(request):
        captured_timeouts.append(request.extensions.get("timeout"))
        return httpx.Response(404)

    check_machine_rep(_client(handler), DOMAIN, homepage_html=None)

    assert len(captured_timeouts) == 1
    expected = {"connect": _PROBE_TIMEOUT, "read": _PROBE_TIMEOUT,
                "write": _PROBE_TIMEOUT, "pool": _PROBE_TIMEOUT}
    assert captured_timeouts[0] == expected


# ── check_agent_payments ──────────────────────────────────────────────────


def test_payment_probes_carry_5s_timeout():
    captured_timeouts = []

    def handler(request):
        captured_timeouts.append(request.extensions.get("timeout"))
        return httpx.Response(404)

    check_agent_payments(_client(handler), DOMAIN)

    assert captured_timeouts, "expected at least one payment probe request"
    expected = {"connect": _PROBE_TIMEOUT, "read": _PROBE_TIMEOUT,
                "write": _PROBE_TIMEOUT, "pool": _PROBE_TIMEOUT}
    for timeout in captured_timeouts:
        assert timeout == expected


def test_payment_probes_soft_time_limit_exceeded_propagates_not_swallowed():
    """SoftTimeLimitExceeded must bubble out of check_agent_payments instead
    of being caught by the generic `except Exception` degrade-to-empty path."""
    def handler(request):
        raise SoftTimeLimitExceeded()

    with pytest.raises(SoftTimeLimitExceeded):
        check_agent_payments(_client(handler), DOMAIN)


def test_well_known_json_probe_detected(monkeypatch):
    """Synthetic well_known_json entry, standing in for any future
    well_known_json protocol addition — proves the extractor stays generic
    over the table rather than hardcoding a probe kind per protocol."""
    monkeypatch.setitem(
        PAYMENT_PROBES,
        "x402",
        {"kind": "well_known_json", "path": "/.well-known/x402", "json_marker": "x402Version"},
    )

    def handler(request):
        if request.url.path == "/.well-known/x402":
            return httpx.Response(200, json={"x402Version": 1})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["x402"]["detected"] is True
    assert result["any_non_ucp"] is True


def test_well_known_json_soft_404_not_detected(monkeypatch):
    """An HTML soft-404 response is not valid JSON, so it must not detect."""
    monkeypatch.setitem(
        PAYMENT_PROBES,
        "x402",
        {"kind": "well_known_json", "path": "/.well-known/x402", "json_marker": "x402Version"},
    )

    def handler(request):
        return httpx.Response(200, text="<html>Not found</html>",
                               headers={"content-type": "text/html"})

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["x402"]["detected"] is False
    assert result["any_non_ucp"] is False


def test_l402_challenge_header_detected():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(402, headers={"WWW-Authenticate": 'L402 macaroon="x"'})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["l402"]["detected"] is True
    assert result["any_non_ucp"] is True


def test_l402_no_challenge_header_not_detected():
    def handler(request):
        return httpx.Response(200)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["l402"]["detected"] is False
    assert result["any_non_ucp"] is False


def test_payment_probes_transport_error_degrades_to_not_detected():
    def handler(request):
        raise httpx.ConnectError("boom")

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["any_non_ucp"] is False
    assert all(p["detected"] is False for p in result["protocols"].values())


def test_x402_detected_via_bazaar_catalog():
    def handler(request):
        if request.url.path == "/.well-known/x402.json":
            return httpx.Response(200, json={"x402Version": 2, "items": []})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["x402"]["detected"] is True
    assert result["protocols"]["x402"]["evidence"] == "/.well-known/x402.json"
    assert result["any_non_ucp"] is True


@pytest.mark.parametrize("probe_path", ["/", "/api", "/api/v1"])
def test_x402_detected_via_402_status_with_marker(probe_path):
    def handler(request):
        if request.url.path == probe_path:
            return httpx.Response(402, json={"x402Version": 2, "accepts": []})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["x402"]["detected"] is True
    assert probe_path in result["protocols"]["x402"]["evidence"]


def test_x402_bare_402_without_marker_not_detected():
    """A generic 402 (e.g. an L402 challenge) must NOT count as x402 — the
    spec-required x402Version body field is the discriminator."""
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(402, headers={"WWW-Authenticate": 'L402 macaroon="x"'},
                                  json={"detail": "payment required"})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["x402"]["detected"] is False
    assert result["protocols"]["l402"]["detected"] is True  # still counted as L402


def test_acp_detected_via_well_known():
    def handler(request):
        if request.url.path == "/.well-known/acp.json":
            return httpx.Response(200, json={"acp_version": "2026-04-17"})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["acp"]["detected"] is True
    assert result["any_non_ucp"] is True


def test_mpp_detected_via_openapi_x_payment_info():
    spec = {"openapi": "3.1.0",
            "paths": {"/pay": {"get": {"x-payment-info": {"scheme": "mpp"}}}}}

    def handler(request):
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=spec)
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["mpp"]["detected"] is True


def test_mpp_plain_openapi_without_extension_not_detected():
    def handler(request):
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"openapi": "3.1.0", "paths": {}})
        return httpx.Response(404)

    result = check_agent_payments(_client(handler), DOMAIN)
    assert result["protocols"]["mpp"]["detected"] is False


def test_payment_probes_nothing_detected_on_404s():
    result = check_agent_payments(_client(lambda r: httpx.Response(404)), DOMAIN)
    assert result["any_non_ucp"] is False
    assert all(p["detected"] is False for p in result["protocols"].values())
    # result shape identical across every protocol
    for p in result["protocols"].values():
        assert set(p) == {"detected", "evidence"}
