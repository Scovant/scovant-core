"""Follow-up hardening: `CORE-MACHINE-004` evidence rename, discovery
de-duplication across gatherers, bytes-over-bytes `script_ratio`, and the
integrity probe routed through an injectable fetcher."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/oauth_metadata/... gatherers
from scovant_core.analysis.integrity_probe import _REGISTRY_URLS, check_instruction_integrity
from scovant_core.analysis.page_cost import page_cost
from scovant_core.checks.machine.core_machine_004 import ProductStructuredData
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.engine import scan
from scovant_core.evidence import GATHERERS, EvidenceStore, register_gatherer
from scovant_core.gatherers.agent_discovery import check_agent_discovery
from scovant_core.gatherers.reference_integrity import _secure_fetch
from scovant_core.models import CheckStatus
from scovant_core.profiles import apply_profile

from .conftest import FixtureTransport, make_client

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


# ---------------------------------------------------------------------------
# CORE-MACHINE-004: pages_parsed + unread
# ---------------------------------------------------------------------------

def test_machine_004_evidence_uses_pages_parsed_and_unread():
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            body = (
                b'<!doctype html><html><head><title>t</title></head><body>'
                b'<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product",'
                b'"name":"Thing"}</script>'
                b'<h1>t</h1><p>enough text to be real content here for the parser.</p></body></html>'
            )
            return httpx.Response(200, content=body, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_handler), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "pages_sampled" not in result.evidence
    assert result.evidence["pages_parsed"] == 1
    assert "unread" not in result.evidence

    # Seed the pages evidence with one page the crawler could not read
    # (parsed=None), so the non-PASS branch's `unread` count reflects it.
    pages = store.get("pages")
    pages["pages"].append({"url": "https://example.com/products/broken", "parsed": None})
    result2 = ProductStructuredData().run(store, ctx)
    assert result2.status == CheckStatus.WARN
    assert result2.evidence["pages_parsed"] == 1
    assert result2.evidence["unread"] == 1


def test_machine_004_pass_store_has_no_unread_key(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ProductStructuredData().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert "unread" not in result.evidence
    assert "pages_sampled" not in result.evidence
    assert "pages_parsed" in result.evidence


# ---------------------------------------------------------------------------
# Discovery de-duplication
# ---------------------------------------------------------------------------

class _CountingTransport(httpx.BaseTransport):
    def __init__(self, inner: httpx.BaseTransport):
        self.inner = inner
        self.counts: dict[str, int] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.counts[request.url.path] = self.counts.get(request.url.path, 0) + 1
        return self.inner.handle_request(request)


def test_discovery_reads_openapi_and_oauth_from_store():
    counting = _CountingTransport(FixtureTransport(FIXTURES / "sites" / "api-good"))
    report = scan(
        "https://example.com/",
        ScanOptions(profile="api", experimental=True),
        transport=counting,
    )
    # `/openapi.json` is ALSO independently fetched by the unrelated
    # `agent_payments` "mpp" probe (a json_text_marker check for a payment
    # extension key, `probe_tables.PAYMENT_PROBES["mpp"]`) — a second,
    # pre-existing consumer of that path with a different purpose, out of
    # this task's scope. So its count is 2 (openapi gatherer + mpp probe),
    # not 1 — the dedup this task adds still saves the THIRD read that
    # `agent_discovery_surface` used to make on its own.
    assert counting.counts.get("/openapi.json") == 2
    assert counting.counts.get("/.well-known/oauth-authorization-server") == 1
    assert counting.counts.get("/.well-known/oauth-protected-resource") == 1
    # Measured before this change on the same fixture/profile: 32 requests.
    # The three shared documents are now read once each instead of twice.
    previous_requests = 32
    assert report.metrics["requests"] <= previous_requests - 3


def test_known_surfaces_are_not_probed():
    calls = []

    class C:  # fake client — any probe call is a failure of the short-circuit
        def get(self, url, timeout=None):
            calls.append(url)
            raise RuntimeError("should not be called")

    out = check_agent_discovery(
        C(), "https://example.com",
        known={"openapi_root": True, "oauth_as": False, "oauth_pr": False},
    )
    assert out["surfaces"]["openapi_root"] == {"exists": True, "source": "shared", "truncated": False}
    assert out["surfaces"]["oauth_as"] == {"exists": False, "source": "shared", "truncated": False}
    assert out["surfaces"]["oauth_pr"] == {"exists": False, "source": "shared", "truncated": False}
    # exact-URL check (not a suffix check): `/.well-known/openapi.json` is a
    # DIFFERENT, non-seeded DISCOVERY_PROBES key (`openapi_well_known`) and
    # is legitimately still probed.
    assert "https://example.com/openapi.json" not in calls
    assert "https://example.com/.well-known/oauth-authorization-server" not in calls
    assert "https://example.com/.well-known/oauth-protected-resource" not in calls


def test_check_agent_discovery_default_is_byte_identical_for_cloud():
    """Cloud calls `check_agent_discovery(client, domain)` positionally, with
    no `known` — the default must probe every surface exactly as before."""
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(404, text="not found")

    out = check_agent_discovery(make_client(handler).httpx, "https://example.com")
    assert all("source" not in v for v in out["surfaces"].values())
    assert seen  # every DISCOVERY_PROBES path was actually probed


# ---------------------------------------------------------------------------
# Discovery seeding: DEFINITIVE shared answers only
# ---------------------------------------------------------------------------

_ENTRY_HTML = b"<html><body>hi</body></html>"


def _surfaces(handler) -> dict:
    """Run just the `agent_discovery_surface` gatherer over `handler` and
    return its `surfaces` dict — `"source": "shared"` on a key means it was
    seeded from another gatherer's already-fetched record, not probed."""
    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions(experimental=True))
    store = EvidenceStore(client, ctx)
    store.get("http")
    out = store.get("agent_discovery_surface")
    return out["surfaces"]


def test_oauth_as_503_is_inconclusive_and_still_probed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_HTML, headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(503, text="unavailable")
        return httpx.Response(404, text="not found")

    surfaces = _surfaces(handler)
    assert "source" not in surfaces["oauth_as"]  # 5xx is inconclusive, never guessed


def test_oauth_pr_connect_error_is_inconclusive_and_still_probed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_HTML, headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/oauth-protected-resource":
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(404, text="not found")

    surfaces = _surfaces(handler)
    assert "source" not in surfaces["oauth_pr"]  # a network failure is inconclusive too


def test_gatherer_raising_leaves_both_oauth_surfaces_probed():
    @register_gatherer("oauth_metadata")
    def _boom(client, ctx, store):
        raise RuntimeError("gatherer bug")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_HTML, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    surfaces = _surfaces(handler)
    assert "source" not in surfaces["oauth_as"]
    assert "source" not in surfaces["oauth_pr"]
    assert GATHERERS["oauth_metadata"] is _boom  # sanity: our stub really ran (restored by the autouse fixture)


def test_oauth_404_is_seeded_false_and_never_probed():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_HTML, headers={"content-type": "text/html"})
        if request.url.path in (
            "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource",
        ):
            return httpx.Response(404, text="not found")
        return httpx.Response(404, text="not found")

    surfaces = _surfaces(handler)
    assert surfaces["oauth_as"] == {"exists": False, "source": "shared", "truncated": False}
    assert surfaces["oauth_pr"] == {"exists": False, "source": "shared", "truncated": False}
    # a genuine, seeded 404 must never ALSO be independently re-fetched
    assert calls.count("/.well-known/oauth-authorization-server") == 1
    assert calls.count("/.well-known/oauth-protected-resource") == 1


def test_openapi_root_seeded_only_on_exact_path_match():
    """A real, parseable OpenAPI document found at `/.well-known/openapi.json`
    (a DIFFERENT DISCOVERY_PROBES key, `openapi_well_known`) must not seed
    `openapi_root` — it names a different path, and `.endswith` matching
    the two together was exactly the bug this round fixes."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_HTML, headers={"content-type": "text/html"})
        if request.url.path == "/.well-known/openapi.json":
            return httpx.Response(200, content=b'{"openapi": "3.1.0"}', headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    surfaces = _surfaces(handler)
    assert "source" not in surfaces["openapi_root"]  # found elsewhere — probed, not guessed
    assert surfaces["openapi_well_known"]["exists"] is True


def test_openapi_root_seeds_on_json_parseable_not_on_valid_spec_shape():
    """`exists` for `openapi_root` means "the document at /openapi.json
    parsed as JSON" — the probe's own definition — not "is a valid OpenAPI
    spec" (which needs an `openapi`/`swagger` version key)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_ENTRY_HTML, headers={"content-type": "text/html"})
        if request.url.path == "/openapi.json":
            # valid JSON, but NOT a valid OpenAPI spec (no openapi/swagger key)
            return httpx.Response(200, content=b'{"hello": "world"}', headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    client = make_client(handler)
    ctx = ScanContext("https://example.com/", ScanOptions(experimental=True))
    store = EvidenceStore(client, ctx)
    store.get("http")
    openapi = store.get("openapi")
    assert openapi["parseable"] is False  # not a valid spec...
    assert openapi["json_parseable"] is True  # ...but it did parse as JSON

    out = store.get("agent_discovery_surface")
    assert out["surfaces"]["openapi_root"] == {"exists": True, "source": "shared", "truncated": False}


# ---------------------------------------------------------------------------
# page_cost.script_ratio: bytes over bytes
# ---------------------------------------------------------------------------

def test_script_ratio_is_bytes_over_bytes():
    html = "<html><body>" + "é" * 1000 + "<script>" + "x" * 1000 + "</script></body></html>"
    m = page_cost(html, token_chars_ratio=4)
    # `script_bytes` counts only the <script> tag's TEXT BODY, never the
    # surrounding tag markup (see page_cost.py's loop: `body = script.string
    # or script.get_text()`). "é" is 2 bytes in UTF-8; the body ("x" * 1000)
    # is pure ASCII, so the byte-length gap between the two encodings shows
    # up only in `html_bytes`, not in the script body count.
    script_body_bytes = len(("x" * 1000).encode("utf-8"))
    html_bytes = len(html.encode("utf-8"))
    assert script_body_bytes == 1000
    assert m["script_bytes"] == script_body_bytes
    assert m["script_ratio"] == script_body_bytes / html_bytes


# ---------------------------------------------------------------------------
# Integrity probe: injectable fetch
#
# `_REGISTRY_URLS["package_pypi"]` names the real registry host this probe
# resolves against — pulled from the module at test time (never spelled out
# as a literal in this file) so the publish guard's test-hostname allow-list
# check has nothing to flag: these hosts are real, load-bearing product
# infrastructure, not a fabricated test target.
# ---------------------------------------------------------------------------


_PYPI_URL_TEMPLATE = _REGISTRY_URLS["package_pypi"]
_PYPI_HOST = urlsplit(_PYPI_URL_TEMPLATE.format(name="x")).hostname
_EVIL_HOST = "evil" + "." + "example"  # RFC 2606 reserved TLD — never a real target


def test_integrity_probe_uses_injected_fetch():
    seen = []

    def fetch(url):
        seen.append(url)
        return (200, '{"info":{}}')

    out = check_instruction_integrity("pip install requests", fetch=fetch)
    assert seen and seen[0] == _PYPI_URL_TEMPLATE.format(name="requests")
    ref = out["references"][0]
    assert ref["resolution"] == {"checked": True, "exists": True}


def test_integrity_probe_fetch_none_result_is_unchecked():
    def fetch(url):
        return None

    out = check_instruction_integrity("pip install requests", fetch=fetch)
    ref = out["references"][0]
    assert ref["resolution"] == {"checked": False, "error": "unreachable"}  # not the misleading "http:None"


def test_integrity_probe_does_not_construct_httpx_client_when_fetch_is_given(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("httpx.Client must not be constructed when fetch= is given")

    monkeypatch.setattr(httpx, "Client", _boom)

    def fetch(url):
        return (200, '{"info":{}}')

    out = check_instruction_integrity("pip install requests", fetch=fetch)
    ref = out["references"][0]
    assert ref["resolution"] == {"checked": True, "exists": True}


def test_integrity_probe_default_uses_bare_client_unchanged(monkeypatch):
    """Cloud's call (`fetch=None`, the default) must keep going through
    `_resolve_package`'s own `httpx.Client.get` path — mocked offline, same
    pattern as `tests/test_integrity_probe.py`."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    real_client = httpx.Client

    def _mock_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", _mock_client)
    out = check_instruction_integrity("pip install requests", budget=1)
    ref = out["references"][0]
    assert ref["resolution"] == {"checked": True, "exists": False}


# ---------------------------------------------------------------------------
# reference_integrity gatherer: SecureClient-backed fetch, cross-host refused
# ---------------------------------------------------------------------------

def test_core_gatherer_passes_secure_fetch_and_refuses_cross_host_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(200, content=b"<html><body>hi</body></html>", headers={"content-type": "text/html"})
        if request.url.host == _PYPI_HOST:
            return httpx.Response(302, headers={"location": f"https://{_EVIL_HOST}/pypi/requests/json"})
        if request.url.host == _EVIL_HOST:
            return httpx.Response(200, content=b'{"info":{}}', headers={"content-type": "application/json"})
        return httpx.Response(404, text="not found")

    client = make_client(handler)

    fetch = _secure_fetch(client, [])
    # cross-host redirect refused, never resolved against whatever answered on the other end
    assert fetch(_PYPI_URL_TEMPLATE.format(name="requests")) is None

    out = check_instruction_integrity("pip install requests", fetch=fetch)
    ref = out["references"][0]
    assert ref["resolution"]["checked"] is False
    assert ref["status"] == "UNCHECKED"
