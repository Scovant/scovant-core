"""CORE-OPERABILITY-009/-010: 429s carry Retry-After; challenges are not served as 200."""
import httpx

from scovant_core.checks.operability.core_operability_009 import RateLimitSignalled, collect_429s
from scovant_core.checks.operability.core_operability_010 import ChallengeServedAs200
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus
from scovant_core.profiles import apply_profile
from tests.conftest import make_client

HOME = "<!doctype html><html><head><title>Home</title></head><body><main><p>" + "Real content. " * 30 + "</p></main></body></html>"
CHALLENGE = "<!doctype html><html><head><title>Just a moment...</title></head><body><div id='cf-challenge-running'>Please verify you are human</div></body></html>"


def _ctx() -> ScanContext:
    """The scan context these tests scan with — a fixed scan id, because the
    soft-404 probe path is derived from it. A caller that has to know the probe
    path before the scan runs (tests/test_http_semantics_corpus.py) builds the
    context here and hands it back to `_scan`, so the id is never re-typed."""
    ctx = ScanContext("https://example.com/", ScanOptions())
    ctx.scan_id = "t"
    return ctx


def _scan(handler, ctx: ScanContext | None = None):
    ctx = ctx if ctx is not None else _ctx()
    store = EvidenceStore(make_client(handler), ctx)
    apply_profile(ctx, store)
    return store, ctx


def _handler(routes):
    def handler(request):
        p = request.url.path
        if p in routes:
            status, body, headers = routes[p]
            return httpx.Response(status, text=body, headers={"content-type": "text/html", **headers})
        return httpx.Response(404, text="nope")
    return handler


def test_no_429_is_na():
    store, ctx = _scan(_handler({"/": (200, HOME, {})}))
    r = RateLimitSignalled().run(store, ctx)
    assert r.status is CheckStatus.NA and collect_429s(store) == []


def test_429_without_retry_after_fails():
    store, ctx = _scan(_handler({"/": (200, HOME, {}), "/llms.txt": (429, "slow down", {})}))
    r = RateLimitSignalled().run(store, ctx)
    assert r.status is CheckStatus.FAIL and r.evidence["without_retry_after"][0]["url"].endswith("/llms.txt")


def test_429_with_retry_after_passes():
    store, ctx = _scan(_handler({"/": (200, HOME, {}), "/llms.txt": (429, "slow down", {"retry-after": "30"})}))
    r = RateLimitSignalled().run(store, ctx)
    assert r.status is CheckStatus.PASS and r.evidence["observed"][0]["retry_after"] == "30"


def test_sitemap_429_without_retry_after_fails():
    # No robots-declared Sitemap:, no `/sitemap.xml`/`/sitemap_index.xml` 200
    # — `sitemap_urls` records this under `probe_status`/`probed_url`, never
    # `status`/`url`, which is exactly the shape CORE-OPERABILITY-009 must
    # still see.
    store, ctx = _scan(_handler({"/": (200, HOME, {}), "/sitemap.xml": (429, "slow down", {})}))
    r = RateLimitSignalled().run(store, ctx)
    assert r.status is CheckStatus.FAIL
    assert r.evidence["without_retry_after"][0]["url"].endswith("/sitemap.xml")


def test_oauth_authorization_server_429_without_retry_after_fails():
    # `oauth_metadata` has no top-level status at all — only nested under
    # `authorization_server`/`protected_resource`. The gatherer always
    # probes both documents (no discovery-signal gate), so this alone is
    # enough to trigger it.
    store, ctx = _scan(_handler({
        "/": (200, HOME, {}),
        "/.well-known/oauth-authorization-server": (429, "slow down", {}),
    }))
    r = RateLimitSignalled().run(store, ctx)
    assert r.status is CheckStatus.FAIL
    assert r.evidence["without_retry_after"][0]["url"].endswith("/.well-known/oauth-authorization-server")


def test_challenge_with_200_fails():
    store, ctx = _scan(_handler({"/": (200, CHALLENGE, {"server": "cloudflare", "cf-mitigated": "challenge"})}))
    r = ChallengeServedAs200().run(store, ctx)
    assert r.status is CheckStatus.FAIL and r.evidence["pages"][0]["status"] == 200


def test_challenge_with_403_is_na():
    store, ctx = _scan(_handler({"/": (403, CHALLENGE, {"server": "cloudflare", "cf-mitigated": "challenge"})}))
    r = ChallengeServedAs200().run(store, ctx)
    assert r.status in (CheckStatus.NA, CheckStatus.ERROR)      # entry blocked honestly; never FAIL


def test_no_challenge_passes():
    store, ctx = _scan(_handler({"/": (200, HOME, {})}))
    assert ChallengeServedAs200().run(store, ctx).status is CheckStatus.PASS
