"""CORE-OPERABILITY-008: unknown paths must answer 404, not a soft-404 200."""
import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/http/soft_404/...
from scovant_core.checks.operability.core_operability_008 import UnknownPathsReturn404
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers.soft_404 import probe_token
from scovant_core.models import CheckStatus
from scovant_core.profiles import apply_profile

from .conftest import make_client

HOME = "<!doctype html><html><head><title>Home</title></head><body><main><p>" + "Real content. " * 30 + "</p></main></body></html>"


def _scan(handler, scan_id="golden-1"):
    ctx = ScanContext("https://example.com/", ScanOptions())
    ctx.scan_id = scan_id
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    return store, ctx


def _site(unknown_status, unknown_body="<html><body>Not found</body></html>", redirect_to=None):
    token = probe_token("golden-1")
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text=HOME, headers={"content-type": "text/html"})
        if request.url.path == f"/scovant-core-probe-{token}":
            if redirect_to:
                return httpx.Response(302, headers={"location": redirect_to})
            return httpx.Response(unknown_status, text=unknown_body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="nope")
    return handler


def test_probe_token_is_deterministic_and_hex():
    assert probe_token("a") == probe_token("a") and probe_token("a") != probe_token("b")
    assert len(probe_token("x")) == 8 and int(probe_token("x"), 16) >= 0


def test_real_404_passes():
    store, ctx = _scan(_site(404))
    r = UnknownPathsReturn404().run(store, ctx)
    assert r.status is CheckStatus.PASS and r.evidence["probed_url"].endswith(f"/scovant-core-probe-{probe_token('golden-1')}")


def test_soft_404_200_fails():
    store, ctx = _scan(_site(200, HOME))
    r = UnknownPathsReturn404().run(store, ctx)
    assert r.status is CheckStatus.FAIL and r.evidence["served_html"] is True


def test_redirect_to_existing_page_warns():
    store, ctx = _scan(_site(404, redirect_to="https://example.com/"))
    r = UnknownPathsReturn404().run(store, ctx)
    assert r.status is CheckStatus.WARN and r.evidence["redirected"] is True and r.evidence["status"] == 200


def test_403_and_5xx_are_not_applicable():
    for code in (403, 401, 500, 503):
        store, ctx = _scan(_site(code))
        assert UnknownPathsReturn404().run(store, ctx).status is CheckStatus.NA


def test_network_error_is_error():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text=HOME, headers={"content-type": "text/html"})
        raise httpx.ConnectError("boom", request=request)
    store, ctx = _scan(handler)
    assert UnknownPathsReturn404().run(store, ctx).status is CheckStatus.ERROR
