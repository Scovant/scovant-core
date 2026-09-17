from __future__ import annotations

import json
import mimetypes
from pathlib import Path

import httpx
import pytest

from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import GATHERERS, EvidenceStore
from scovant_core.security.client import SecureClient
from scovant_core.security.policy import SecurityPolicy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def _restore_gatherers():
    """Snapshot `GATHERERS` before each test and restore it after, so a
    test-local `register_gatherer` (e.g. test_evidence.py's `_probe_once`/
    `_boom`) can never leak into a later test even if its own cleanup is
    skipped or ordering changes."""
    before = dict(GATHERERS)
    yield
    GATHERERS.clear()
    GATHERERS.update(before)


class FixtureTransport(httpx.BaseTransport):
    """Serves a fixture site directory: `<dir>/index.html` for `/`,
    `<dir>/robots.txt` for `/robots.txt`, `<dir>/.well-known/mcp.json` …
    Unknown paths → 404. Files named `*.redirect` contain a Location target.
    A `<path>.headers` sidecar (JSON object) merges into the response
    headers when present — lets a fixture declare e.g. a custom
    `content-type` without renaming the served file.

    Scheme rule (added for the http→https downgrade probe, `http.py`'s
    `_downgrade_probe`): a request whose scheme is `http` gets a bare
    `301 → https://<host><same path>` — the site "redirects http to https,
    same path", the default a real hardened site should exhibit — UNLESS a
    file named `http-200.txt` exists directly under the fixture root, in
    which case the request is served normally (as if it were https): the
    fixture is declaring "my http:// origin answers 200 without
    redirecting"."""

    def __init__(self, root: Path, host: str = "example.com"):
        self.root, self.host = root, host

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != self.host:
            return httpx.Response(404, text="wrong host")
        if request.url.scheme == "http" and not (self.root / "http-200.txt").exists():
            return httpx.Response(301, headers={"location": "https://" + self.host + request.url.path})
        path = request.url.path
        rel = "index.html" if path == "/" else path.lstrip("/")
        f = self.root / rel
        if (self.root / (rel + ".redirect")).exists():
            return httpx.Response(301, headers={"location": (self.root / (rel + ".redirect")).read_text().strip()})
        if f.is_dir():
            f = f / "index.html"
        elif not f.exists() and not f.suffix and (f.with_suffix(".html")).exists():
            # clean-URL convenience: `/products/widget` serves `products/widget.html`
            f = f.with_suffix(".html")
        if not f.exists():
            return httpx.Response(404, text="not found")
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if f.suffix == ".txt":
            ctype = "text/plain"
        headers = {"content-type": ctype}
        sidecar = f.with_name(f.name + ".headers")
        if sidecar.exists():
            headers.update(json.loads(sidecar.read_text()))
        return httpx.Response(200, content=f.read_bytes(), headers=headers)


def make_client(handler_or_transport, **policy) -> SecureClient:
    transport = handler_or_transport if isinstance(handler_or_transport, httpx.BaseTransport) \
        else httpx.MockTransport(handler_or_transport)
    return SecureClient(SecurityPolicy(**policy), user_agent="ScovantCore/test", transport=transport)


@pytest.fixture
def fixture_site():
    def _make(name: str, host: str = "example.com") -> SecureClient:
        return make_client(FixtureTransport(FIXTURES / "sites" / name, host))
    return _make


@pytest.fixture
def load_expected():
    """Load a committed golden report by site name, as a real `Report`
    object — no re-scan needed. The golden `.json` files are exactly
    `report.model_dump(mode="json")` (see `report/json.py`), so
    `Report.model_validate` round-trips them faithfully."""
    from scovant_core.models import Report

    def _load(site: str) -> Report:
        path = FIXTURES / "sites" / "expected" / f"{site}.json"
        return Report.model_validate(json.loads(path.read_text(encoding="utf-8")))
    return _load


# ---------------------------------------------------------------------------
# Truncation-behaviour fixtures (test_truncation_behaviour.py): an
# EvidenceStore pre-loaded with real gatherer-record SHAPES, so a check's
# `evaluate()` runs unmodified against a document that either was, or was
# not, cut off at the fetch layer's body cap — without spinning up an HTTP
# transport just to flip one flag deep inside a gatherer.
def _dummy_client() -> SecureClient:
    return make_client(lambda request: httpx.Response(404, text="not found"))


def _llms_record(*, truncated: bool) -> dict:
    return {
        "status": 200,
        "parsed": {"exists": True, "valid": True, "urls": [], "raw_content": "# Example\n", "errors": []},
        "full_exists": False,
        "references": [],
        "served_as_html": False,
        "truncated": truncated,
    }


# A real, self-contained entry page — deliberately run through the REAL
# `gatherers.pages.parse_page()` (not a hand-typed `parsed` dict) so the
# fixture's shape can never drift from what the actual gatherer produces.
# A hand-typed thin `parsed` dict (the original version of this fixture)
# is exactly how CORE-MACHINE-002/003/008/009/010 ended up erroring
# identically on both sides on a `schema_org`/`metadata`/`headings`/
# `html_lang` KeyError — turned into an `EvidenceUnavailable` by
# `EvidenceStore.get`, which masked a truncation-dependent bug in any of
# those five as a passing test (both runs ERROR the same way regardless of
# what a mutated branch does, since evaluate() never reaches it).
# Real content deliberately present for every field those checks (and
# CORE-MACHINE-001/004/006/007/011/012, CORE-TRUST-001/007,
# CORE-INTERFACE-003/004, CORE-ACCESS-007 — all `pages`-derived) read: a
# `<title>`/meta description, matching OG tags, a valid `lang`, one H1 with
# no skipped levels, and both an Organization and a WebSite JSON-LD node
# with name+url — so every one of them lands on a real PASS branch instead
# of falling through to ERROR on missing data.
_ENTRY_HTML = """<html lang="en">
<head>
<title>Example Test Page</title>
<meta name="description" content="An example page used for the truncation parity fixture.">
<meta property="og:title" content="Example Test Page">
<meta property="og:description" content="An example OG description for the parity fixture.">
<script type="application/ld+json">
{"@context": "https://schema.org", "@graph": [
  {"@type": "Organization", "name": "Example Co", "url": "https://example.com/"},
  {"@type": "WebSite", "name": "Example", "url": "https://example.com/"}
]}
</script>
</head>
<body>
<h1>Welcome to Example</h1>
<p>""" + ("This is real sample body text for the truncation parity fixture. " * 5) + """</p>
</body>
</html>"""


def _pages_record(*, truncated: bool) -> dict:
    from scovant_core.gatherers.pages import parse_page

    parsed = parse_page(_ENTRY_HTML, "https://example.com/")
    page = {
        "url": "https://example.com/",
        "status": 200,
        "html": _ENTRY_HTML,
        "bot_protection": None,
        "parsed": parsed,
        "error": None,
        "truncated": truncated,
    }
    return {"pages": [page], "selection": [{"url": page["url"], "reason": "entry"}], "truncated": truncated}


def _openapi_record(*, truncated: bool) -> dict:
    return {
        "found_url": "https://example.com/openapi.json",
        "parseable": True,
        "json_parseable": True,
        "openapi_version": "3.0.0",
        "candidates": ["https://example.com/openapi.json"],
        "served_as_html": False,
        "status": 200,
        "last_served_as_html": False,
        "truncated": truncated,
    }


def _security_txt_record(*, truncated: bool) -> dict:
    return {
        "found_url": "https://example.com/.well-known/security.txt",
        "status": 200,
        "contact": True,
        "expires": None,
        "expires_valid": None,
        "served_as_html": False,
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# The remaining `truncated`-carrying gatherer records actually READ (via
# `record_truncation`) by a check that is APPLICABLE under the `ctx` fixture's
# `resolved_profile` ("auto") — i.e. not gated off by a `profiles=` restriction
# before `evaluate()` is ever reached. Widened 2026-09 after a reviewer
# mutation on CORE-ACCESS-001 (adding a truncation-dependent branch reading
# `store.get("http")`) passed the parity test unnoticed: `http` was never
# preloaded here, so both stores' `http` record came from the SAME real
# gatherer run against the SAME 404-everything dummy client and were
# structurally incapable of differing. `oauth_metadata`/`ucp`/
# `agent_discovery_surface` are deliberately NOT added here — every check
# that reads them restricts `profiles` to a set "auto" is never a member of,
# so `run()`'s `applicable()` gate short-circuits to the same NA on both
# sides before evaluate() ever touches the record; adding data for them would
# be untested by definition.
def _http_record(*, truncated: bool) -> dict:
    return {
        "input_url": "https://example.com/",
        "final_url": "https://example.com/",
        "status": 200,
        "headers": {"etag": '"v1"'},
        "redirect_chain": [],
        "html": "<html><body></body></html>",
        "bytes": 32,
        "truncated": truncated,
        "error": None,
    }


def _mcp_discovery_record(*, truncated: bool) -> dict:
    return {
        "status": 200,
        "discovery": {
            "exists": True,
            "valid": True,
            "servers": [{
                "name": "example-server", "url": "https://example.com/mcp", "transport": "http",
                "description": "A real MCP server used for integration testing.",
            }],
            "endpoints": ["https://example.com/mcp"],
            "declared_name": "Example MCP",
        },
        "server_card": None,
        "truncated": truncated,
    }


def _sitemap_urls_record(*, truncated: bool) -> dict:
    return {
        "url": "https://example.com/sitemap.xml",
        "exists": True,
        "valid": True,
        "kind": "urlset",
        "entries": [{"loc": "https://example.com/", "lastmod": None}],
        "parse_error": None,
        "probe_status": 200,
        "probe_error": None,
        "served_as_html": False,
        # `body_truncated` (NOT the top-level `truncated`, which here means
        # "the entry LIST was capped at MAX_ENTRIES") is the signal
        # CORE-ACCESS-005/006 actually read — see `gatherers/sitemap_urls.py`.
        "body_truncated": truncated,
        "truncated": False,
    }


def _reference_integrity_record(*, truncated: bool) -> dict:
    return {"attempted": True, "references": [], "remote_exec": [], "budget_exhausted": False, "truncated": truncated}


def _policy_pages_record(*, truncated: bool) -> dict:
    privacy_page = {
        "url": "https://example.com/privacy", "status": 200, "text_chars": 500,
        "served_as_html": True, "has_price_text": False, "has_structured_price": False,
        "truncated": truncated,
    }
    return {
        "pages": {"shipping": None, "returns": None, "privacy": privacy_page, "terms": None, "pricing": None},
        "truncated": truncated,
    }


@pytest.fixture
def ctx() -> ScanContext:
    scan_ctx = ScanContext("https://example.com/", ScanOptions())
    scan_ctx.set_final_url("https://example.com/")
    return scan_ctx


@pytest.fixture
def truncated_store(ctx: ScanContext) -> EvidenceStore:
    store = EvidenceStore(_dummy_client(), ctx)
    store._data["llms"] = _llms_record(truncated=True)
    store._data["pages"] = _pages_record(truncated=True)
    store._data["openapi"] = _openapi_record(truncated=True)
    store._data["security_txt"] = _security_txt_record(truncated=True)
    store._data["http"] = _http_record(truncated=True)
    store._data["mcp_discovery"] = _mcp_discovery_record(truncated=True)
    store._data["sitemap_urls"] = _sitemap_urls_record(truncated=True)
    store._data["reference_integrity"] = _reference_integrity_record(truncated=True)
    store._data["policy_pages"] = _policy_pages_record(truncated=True)
    return store


@pytest.fixture
def full_store(ctx: ScanContext) -> EvidenceStore:
    store = EvidenceStore(_dummy_client(), ctx)
    store._data["llms"] = _llms_record(truncated=False)
    store._data["pages"] = _pages_record(truncated=False)
    store._data["openapi"] = _openapi_record(truncated=False)
    store._data["security_txt"] = _security_txt_record(truncated=False)
    store._data["http"] = _http_record(truncated=False)
    store._data["mcp_discovery"] = _mcp_discovery_record(truncated=False)
    store._data["sitemap_urls"] = _sitemap_urls_record(truncated=False)
    store._data["reference_integrity"] = _reference_integrity_record(truncated=False)
    store._data["policy_pages"] = _policy_pages_record(truncated=False)
    return store


# ---------------------------------------------------------------------------
# fixture_server (test_security_suite.py): a REAL `127.0.0.1` HTTP server —
# not a `MockTransport` — for the one case that needs to prove the size cap
# survives an actual streamed HTTP response, not just an in-process fixture.
# Reuses `tests/_fixture_server.py`'s handler (already regression-tested
# against path traversal) but serves a per-test `tmp_path` directory instead
# of a fixed `fixtures/sites/<name>`, so a test can `write()` exactly the
# oversized document it needs without checking a multi-megabyte fixture file
# into the public repo tree.
class _FixtureServer:
    def __init__(self, root: Path, port: int):
        self.root, self.port = root, port

    def write(self, rel_path: str, content: bytes) -> None:
        path = self.root / rel_path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def url_for(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


@pytest.fixture
def fixture_server(tmp_path):
    import threading
    from http.server import HTTPServer

    from tests._fixture_server import FixtureRequestHandler

    (tmp_path / "index.html").write_text("<html><body>fixture</body></html>")
    server = HTTPServer(("127.0.0.1", 0), FixtureRequestHandler)
    server.root = tmp_path  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield _FixtureServer(tmp_path, server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
