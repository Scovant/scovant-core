from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/http gatherers
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.profiles import (
    LOW_CONFIDENCE,
    PROFILE_DETECTOR_VERSION,
    PROFILES,
    apply_profile,
    resolve_profile,
)

from .conftest import make_client


def _store(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    return EvidenceStore(client, ctx), ctx


def test_profiles_tuple():
    assert PROFILES == ("auto", "content", "commerce", "saas", "api")


def test_commerce_good_fixture_resolves_commerce(fixture_site):
    client = fixture_site("commerce-good")
    store, _ = _store(client)
    profile, confidence = resolve_profile(store)
    assert profile == "commerce"
    assert confidence >= 0.8


def test_explicit_profile_option_skips_resolution_entirely():
    # No transport configured at all — apply_profile must never touch the
    # store/network when the option isn't "auto".
    client = make_client(lambda r: (_ for _ in ()).throw(AssertionError("network hit")))
    store, ctx = _store(client, ScanOptions(profile="content"))
    apply_profile(ctx, store)
    assert (ctx.resolved_profile, ctx.profile_confidence) == ("content", 1.0)


_API_HTML = (
    "<!doctype html><html><head><title>API</title></head>"
    '<body><a href="/openapi.json">spec</a> <a href="/docs">docs</a></body></html>'
)
_OPENAPI_JSON = '{"openapi":"3.1.0","info":{"title":"x","version":"1"},"paths":{}}'
_SAAS_HTML = (
    "<!doctype html><html><head><title>SaaS</title></head>"
    '<body><a href="/pricing">Pricing</a> <button>Sign up</button></body></html>'
)
_CONTENT_HTML = (
    "<!doctype html><html><head><title>Blog</title></head>"
    "<body><article><h1>A Post</h1><p>Just an article, nothing more.</p></article></body></html>"
)


def _handler(routes: dict[str, tuple[int, str, str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404)
        status, body, ctype = routes.get(request.url.path, (404, "not found", "text/plain"))
        return httpx.Response(status, text=body, headers={"content-type": ctype})
    return handler


def test_api_profile_from_openapi_doc_and_docs_link():
    routes = {
        "/": (200, _API_HTML, "text/html"),
        "/openapi.json": (200, _OPENAPI_JSON, "application/json"),
        "/docs": (200, "<html><body>docs</body></html>", "text/html"),
        "/robots.txt": (404, "", "text/plain"),
        "/sitemap.xml": (404, "", "text/plain"),
    }
    client = make_client(_handler(routes))
    store, _ = _store(client)
    profile, confidence = resolve_profile(store)
    assert profile == "api"
    assert confidence >= 0.75


def test_saas_profile_from_pricing_link_and_signup_cta():
    routes = {
        "/": (200, _SAAS_HTML, "text/html"),
        "/pricing": (200, "<html><body>pricing</body></html>", "text/html"),
        "/robots.txt": (404, "", "text/plain"),
        "/sitemap.xml": (404, "", "text/plain"),
    }
    client = make_client(_handler(routes))
    store, _ = _store(client)
    profile, confidence = resolve_profile(store)
    assert profile == "saas"
    assert confidence >= 0.8


def test_content_profile_when_nothing_signals_otherwise():
    routes = {
        "/": (200, _CONTENT_HTML, "text/html"),
        "/robots.txt": (404, "", "text/plain"),
        "/sitemap.xml": (404, "", "text/plain"),
    }
    client = make_client(_handler(routes))
    store, _ = _store(client)
    assert resolve_profile(store) == ("content", 0.5)


def test_apply_profile_auto_delegates_to_resolve_profile(fixture_site):
    client = fixture_site("commerce-good")
    store, ctx = _store(client)
    apply_profile(ctx, store)
    assert ctx.resolved_profile == "commerce"
    assert ctx.profile_confidence >= 0.8


def test_detector_version_and_threshold_constants():
    assert PROFILE_DETECTOR_VERSION == "1.0" and LOW_CONFIDENCE == 0.70


def test_profile_note_only_for_low_confidence_auto(load_expected):
    from scovant_core.report._common import profile_note
    r = load_expected("commerce-good")
    low = r.model_copy(update={"target": r.target.model_copy(update={"requested_profile": "auto", "resolved_profile": "saas", "profile_confidence": 0.6})})
    assert profile_note(low) == "Profile: saas? (confidence LOW, 0.60) — canonical comparison should specify --profile."
    edge = r.model_copy(update={"target": r.target.model_copy(update={"requested_profile": "auto", "profile_confidence": 0.70})})
    assert profile_note(edge) is None
    declared = r.model_copy(update={"target": r.target.model_copy(update={"requested_profile": "saas", "profile_confidence": 1.0})})
    assert profile_note(declared) is None


def test_low_confidence_note_rendered_in_all_formats(load_expected):
    from scovant_core.report.html import render_html
    from scovant_core.report.markdown import render_markdown
    from scovant_core.report.text import render_text
    r = load_expected("commerce-good")
    low = r.model_copy(update={"target": r.target.model_copy(update={"requested_profile": "auto", "resolved_profile": "content", "profile_confidence": 0.5})})
    for out in (render_text(low), render_markdown(low), render_html(low)):
        assert "Profile: content? (confidence LOW, 0.50)" in out
