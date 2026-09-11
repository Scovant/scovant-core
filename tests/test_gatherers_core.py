import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers.pages import parse_page
from tests.conftest import make_client


def _store(fixture_site, name="commerce-good"):
    client = fixture_site(name)
    ctx = ScanContext("https://example.com/", ScanOptions())
    return EvidenceStore(client, ctx), ctx


def test_http_gatherer_sets_origin_and_records_status(fixture_site):
    store, ctx = _store(fixture_site)
    http = store.get("http")
    assert http["status"] == 200 and http["error"] is None and ctx.origin == "https://example.com"


def test_robots_gatherer_parses_groups_signals_and_sitemaps(fixture_site):
    store, _ = _store(fixture_site)
    r = store.get("robots_txt")
    assert r["status"] == 200 and r["sitemaps"] == ["https://example.com/sitemap.xml"]
    assert r["parsed"]["GPTBot"]["disallow"] == ["/"] and r["content_signals"]["dimensions"]["ai-train"] == "no"
    assert r["general_disallow_all"] is False


def test_sitemap_gatherer_lists_entries_with_lastmod(fixture_site):
    store, _ = _store(fixture_site)
    s = store.get("sitemap_urls")
    assert s["valid"] and [e["loc"] for e in s["entries"]][:2] == ["https://example.com/", "https://example.com/products/widget"]
    assert s["entries"][1]["lastmod"] == "2026-08-15"


def test_pages_gatherer_selects_entry_plus_sitemap_and_product(fixture_site):
    store, _ = _store(fixture_site)
    p = store.get("pages")
    urls = [pg["url"] for pg in p["pages"]]
    assert urls[0] == "https://example.com/" and "https://example.com/products/widget" in urls
    assert len(urls) <= 5
    widget = next(pg for pg in p["pages"] if pg["url"].endswith("/products/widget"))
    assert widget["parsed"]["product_data"]["price"] == 19.99
    # widget.html carries two JSON-LD blocks since Fix round 1 (Product + a
    # BreadcrumbList, added to give CORE-MACHINE-007 a PASS path on this fixture).
    assert widget["parsed"]["raw_jsonld_count"] == 2


def test_http_gatherer_returns_error_evidence_on_unreachable(fixture_site):
    client = fixture_site("commerce-good", host="other.example.org")  # host mismatch → 404
    store = EvidenceStore(client, ScanContext("https://example.com/", ScanOptions()))
    assert store.get("http")["status"] == 404


def _store_for(handler):
    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions())
    return EvidenceStore(client, ctx), ctx


# -- fix round 1 -------------------------------------------------------------

def test_robots_gatherer_flags_soft_404_html_body(fixture_site):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<html><body><h1>Home</h1></body></html>",
                                   headers={"content-type": "text/html"})
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="<!doctype html><html><body>404 Not Found</body></html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    r = store.get("robots_txt")
    assert r["status"] == 200
    assert r["served_as_html"] is True
    assert r["text"] == ""
    assert r["parsed"]["general"]["disallow"] == []


def test_pages_gatherer_keeps_scanning_after_a_500_and_nulls_its_parse():
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text='<html><body><h1>Home</h1></body></html>',
                                   headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(404)
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?>'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    "<url><loc>https://example.com/</loc></url>"
                    "<url><loc>https://example.com/products/widget</loc></url>"
                    "</urlset>"
                ),
                headers={"content-type": "application/xml"},
            )
        if path == "/products/widget":
            return httpx.Response(500, text="internal error")
        return httpx.Response(404)

    store, _ = _store_for(handler)
    p = store.get("pages")
    widget = next(pg for pg in p["pages"] if pg["url"].endswith("/products/widget"))
    assert widget["status"] == 500
    assert widget["parsed"] is None
    entry = next(pg for pg in p["pages"] if pg["url"] == "https://example.com/")
    assert entry["status"] == 200 and entry["parsed"] is not None


def test_pages_gatherer_respects_max_pages(fixture_site):
    client = fixture_site("commerce-good")
    ctx = ScanContext("https://example.com/", ScanOptions(max_pages=2))
    store = EvidenceStore(client, ctx)
    p = store.get("pages")
    assert len(p["pages"]) == 2
    assert p["pages"][0]["url"] == "https://example.com/"


def test_pages_gatherer_excludes_cross_scheme_sitemap_entry():
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html><body><h1>Home</h1></body></html>",
                                   headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(404)
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?>'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    "<url><loc>http://example.com/products/thing</loc></url>"
                    "</urlset>"
                ),
                headers={"content-type": "application/xml"},
            )
        return httpx.Response(404)

    store, _ = _store_for(handler)
    p = store.get("pages")
    urls = [pg["url"] for pg in p["pages"]]
    assert "http://example.com/products/thing" not in urls
    assert urls == ["https://example.com/"]


def test_sitemap_gatherer_follows_sitemapindex_first_child_only():
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(404)
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?>'
                    '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    "<sitemap><loc>https://example.com/sitemap-a.xml</loc></sitemap>"
                    "<sitemap><loc>https://example.com/sitemap-b.xml</loc></sitemap>"
                    "</sitemapindex>"
                ),
                headers={"content-type": "application/xml"},
            )
        if path == "/sitemap-a.xml":
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?>'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    "<url><loc>https://example.com/one</loc></url>"
                    "<url><loc>https://example.com/two</loc></url>"
                    "</urlset>"
                ),
                headers={"content-type": "application/xml"},
            )
        return httpx.Response(404)

    store, _ = _store_for(handler)
    s = store.get("sitemap_urls")
    assert len(s["entries"]) == 2


def test_sitemap_gatherer_reports_parse_error_without_raising():
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(404)
        if path == "/sitemap.xml":
            return httpx.Response(200, text="<urlset><url><loc>broken", headers={"content-type": "application/xml"})
        return httpx.Response(404)

    store, _ = _store_for(handler)
    s = store.get("sitemap_urls")
    assert s["valid"] is False
    assert s["entries"] == []
    assert s["parse_error"]


def test_parse_page_counts_raw_vs_parsed_jsonld_from_a_graph_block():
    html = (
        "<html><head><title>t</title>"
        '<script type="application/ld+json">'
        '{"@context":"https://schema.org","@graph":['
        '{"@type":"Organization","name":"Example Shop"},'
        '{"@type":"WebSite","name":"Example Shop"},'
        '{"@type":"WebPage","name":"Home"}'
        "]}"
        "</script></head><body><h1>Home</h1></body></html>"
    )
    parsed = parse_page(html, "https://example.com/")
    assert parsed["raw_jsonld_count"] == 1
    assert parsed["parsed_jsonld_count"] == 1
    assert len(parsed["schema_org"]) >= 1


def test_pages_gatherer_samples_the_homepage_once_for_a_bare_origin_sitemap_entry():
    """A sitemap listing `https://example.com` (no path) names the same page
    as the entry URL `https://example.com/` — it must be recognised as
    already sampled, not fetched and reported a second time."""
    sitemap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.com</loc></url>"
        "<url><loc>https://example.com/about</loc></url></urlset>"
    )
    index = (
        "<!doctype html><html><head><title>t</title></head><body><h1>t</h1>"
        "<p>enough visible text content for the parser to treat this as real.</p></body></html>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=index.encode(), headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(
                200, text="User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\n",
                headers={"content-type": "text/plain"},
            )
        if path == "/sitemap.xml":
            return httpx.Response(200, text=sitemap, headers={"content-type": "application/xml"})
        if path == "/about":
            return httpx.Response(200, content=index.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    urls = [p["url"] for p in store.get("pages")["pages"]]
    assert urls.count("https://example.com/") == 1
    assert "https://example.com" not in urls


def test_parse_page_carries_html_lang_images_breadcrumb_prices_webmcp_forms_and_cost():
    html = (
        '<html lang="en"><head><title>t</title>'
        '<script type="application/ld+json">'
        '{"@type":"BreadcrumbList","itemListElement":[]}'
        "</script></head><body>"
        '<img src="/a.png" alt="A widget"><img src="/b.png" alt="">'
        '<img src="/c.png" role="presentation">'
        "<p>Only $19.99 today.</p>"
        "<form><input type=\"text\" name=\"q\"></form>"
        "<script>registerTool({name:'ping', description:'Ping'});</script>"
        "</body></html>"
    )
    parsed = parse_page(html, "https://example.com/")
    assert parsed["html_lang"] == "en"
    assert parsed["images"] == {"total": 3, "with_alt": 1, "empty_alt": 2}
    assert parsed["breadcrumb"] is True
    assert parsed["visible_prices"] == ["$19.99"]
    assert parsed["webmcp_parse_errors"] == 0
    assert parsed["webmcp_tools"][0]["name"] == "ping"
    assert parsed["forms"]["forms"] == 1 and parsed["forms"]["unlabeled_inputs"] == 1
    assert parsed["page_cost"]["text_chars"] == len(parsed["visible_text"])
    assert parsed["page_cost"]["link_count"] == 0


def test_parse_page_respects_token_chars_ratio():
    html = "<html><body><p>abcdefgh</p></body></html>"
    default = parse_page(html, "https://example.com/")
    custom = parse_page(html, "https://example.com/", token_chars_ratio=2)
    assert default["page_cost"]["estimated_tokens"] == len("abcdefgh") // 4
    assert custom["page_cost"]["estimated_tokens"] == len("abcdefgh") // 2


def test_page_metrics_gatherer_derives_from_pages_evidence(fixture_site):
    store, _ = _store(fixture_site)
    metrics = store.get("page_metrics")
    assert metrics["entry"] is not None
    urls = [pg["url"] for pg in metrics["pages"]]
    assert "https://example.com/" in urls
    assert all("html_bytes" in pg for pg in metrics["pages"])


def test_forms_gatherer_derives_from_pages_evidence(fixture_site):
    store, _ = _store(fixture_site)
    forms = store.get("forms")
    assert set(forms["totals"]) == {"forms", "inputs", "unlabeled_inputs", "unnamed_buttons", "unlabeled_selects"}
    assert all("forms" in pg for pg in forms["pages"])


def test_page_metrics_and_forms_skip_unparsed_pages():
    def handler(request):
        path = request.url.path
        if path == "/":
            return httpx.Response(200, text='<html><body><h1>Home</h1></body></html>',
                                   headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(404)
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                text=(
                    '<?xml version="1.0"?>'
                    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                    "<url><loc>https://example.com/</loc></url>"
                    "<url><loc>https://example.com/products/widget</loc></url>"
                    "</urlset>"
                ),
                headers={"content-type": "application/xml"},
            )
        if path == "/products/widget":
            return httpx.Response(500, text="internal error")
        return httpx.Response(404)

    store, _ = _store_for(handler)
    metrics = store.get("page_metrics")
    forms = store.get("forms")
    urls = [pg["url"] for pg in metrics["pages"]]
    assert not any(u.endswith("/products/widget") for u in urls)
    assert not any(pg["url"].endswith("/products/widget") for pg in forms["pages"])
