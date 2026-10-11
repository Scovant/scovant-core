"""The CLI's gatherer output as the evidence the public rules read.
Fixtures are produced by the real gatherers over FixtureTransport."""
from __future__ import annotations

import pytest

from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers import _register  # noqa: F401 — registers evidence.GATHERERS
from scovant_core.profiles import apply_profile
from scovant_core.r2.adapter import SITE_TYPES, evidence_from_store, site_type_for
from scovant_core.security.client import SecureClient
from scovant_core.security.policy import SecurityPolicy
from tests.conftest import FIXTURES, FixtureTransport

URL = "https://example.com/"


def _store(site: str, transport=None):
    ctx = ScanContext(URL, ScanOptions())
    client = SecureClient(SecurityPolicy(total_budget_seconds=30), "test-agent",
                          transport=transport or FixtureTransport(FIXTURES / "sites" / site))
    store = EvidenceStore(client, ctx)
    store.try_get("http")
    apply_profile(ctx, store)
    return store, ctx, client


def test_site_type_mapping():
    assert site_type_for("commerce", 0.95, None) == ("commerce", "detected")
    assert site_type_for("api", 0.9, None) == ("saas", "detected")
    assert site_type_for("content", 1.0, None) == ("other", "detected")
    assert site_type_for("content", 0.5, None) == ("unknown", "unknown")     # ruling 3
    assert site_type_for("saas", 0.6, None) == ("unknown", "unknown")
    assert site_type_for("commerce", 0.95, "blog") == ("blog", "flag")
    assert {"commerce", "saas", "blog", "other", "unknown"} <= SITE_TYPES


def test_commerce_good_evidence_shapes():
    store, ctx, client = _store("commerce-good")
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    d = ev.domain
    assert d["site_type"] == "commerce" and d["pages_scored"] == len(ev.pages) >= 1
    assert "GPTBot" in str(d["robots"])                      # parse_robots_txt output
    assert d["mcp"]["endpoints"]                              # the declared endpoint
    # Core never handshakes: the producer's inert blocks say "not attempted",
    # which the MCP rules' `measure` reads as NOT_MEASURED.
    assert d["mcp"]["handshake"]["attempted"] is False
    assert d["mcp"]["interface"]["attempted"] is False
    assert d["sitemap"]["exists"] is True
    assert d["token_bloat_settings"] == {"enabled": True, "low": 8000, "medium": 20000}
    assert all("_http_status" in p for p in ev.pages)
    assert ev.defaulted == frozenset()


class _RobotsDown:
    """FixtureTransport, except robots.txt raises a transport error."""
    def __init__(self, inner):
        self.inner = inner

    def handle_request(self, request):
        import httpx
        if request.url.path == "/robots.txt":
            raise httpx.ConnectError("down", request=request)
        return self.inner.handle_request(request)


def test_robots_fetch_error_marks_robots_not_measured():
    import httpx

    class T(httpx.BaseTransport):
        def __init__(self):
            self.t = _RobotsDown(FixtureTransport(FIXTURES / "sites" / "commerce-good"))

        def handle_request(self, request):
            return self.t.handle_request(request)

    store, ctx, client = _store("commerce-good", transport=T())
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    assert {"robots", "content_signals"} <= ev.defaulted

    from scovant_core.r2 import OutcomeState
    from scovant_core.r2.evaluate import technical_readiness
    from scovant_core.r2.technical import GATE_ROBOTS
    run = technical_readiness(ev.pages, ev.domain, site_type="commerce", defaulted=ev.defaulted)
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["AI_CRAWLER_BLOCKED"].state == OutcomeState.NOT_MEASURED
    assert by_id[GATE_ROBOTS].state == OutcomeState.NA


def test_cli_site_type_flag(capsys):
    from scovant_core.cli import main
    with pytest.raises(SystemExit) as exc:
        main(["scan", URL, "--site-type", "not-a-type"])
    assert exc.value.code == 2
    from scovant_core.cli import _build_parser
    args = _build_parser().parse_args(["scan", URL, "--site-type", "blog"])
    assert args.site_type == "blog"


_PROBE_RULES = {
    "robots_txt": ["AI_CRAWLER_BLOCKED", "CONTENT_SIGNALS_ABSENT"],
    "sitemap_urls": ["SITEMAP_MISSING_OR_INVALID"],
    "llms": ["LLMS_TXT_MISSING_OR_INVALID"],
    "ucp": ["UCP_PROFILE_ABSENT", "UCP_PROFILE_INVALID", "UCP_CHECKOUT_MISSING",
            "UCP_SIGNING_KEYS_INVALID"],
    "mcp_discovery": ["MCP_ENDPOINT_ABSENT", "MCP_DISCOVERY_INVALID"],
    "agent_discovery_surface": ["AGENT_INTERFACE_DISCOVERY_ABSENT"],
}


def _failing_run(monkeypatch, name):
    from scovant_core import evidence
    from scovant_core.r2.evaluate import technical_readiness

    def boom(*_a, **_k):
        raise RuntimeError(f"{name} down")
    monkeypatch.setitem(evidence.GATHERERS, name, boom)
    store, _ctx, client = _store("commerce-good")
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    run = technical_readiness(ev.pages, ev.domain, site_type="commerce", defaulted=ev.defaulted)
    return ev, run


@pytest.mark.parametrize("name", sorted(_PROBE_RULES))
def test_failed_gatherer_is_never_pass_or_fail(monkeypatch, name):
    from scovant_core.r2 import OutcomeState
    ev, run = _failing_run(monkeypatch, name)
    by_id = {o.rule_id: o for o in run.outcomes}
    for rule in _PROBE_RULES[name]:
        assert by_id[rule].state in (OutcomeState.NOT_MEASURED, OutcomeState.NA), (name, rule)
    # and the rules are not NA merely because the baseline site lacks the surface
    assert any(by_id[r].state == OutcomeState.NOT_MEASURED for r in _PROBE_RULES[name]), name


def test_failed_pages_gatherer_gives_no_rating(monkeypatch):
    from scovant_core.r2 import OutcomeState
    ev, run = _failing_run(monkeypatch, "pages")
    assert ev.pages == []
    assert run.result.rating is None
    assert not [o for o in run.outcomes if o.state in (OutcomeState.PASS, OutcomeState.FAIL)]




def _robots_status_transport(status):
    import httpx

    inner = FixtureTransport(FIXTURES / "sites" / "commerce-good")

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            if request.url.path == "/robots.txt":
                return httpx.Response(status, text="")
            return inner.handle_request(request)

    return T()


def _robots_run(status):
    from scovant_core.r2.evaluate import technical_readiness
    store, _ctx, client = _store("commerce-good", transport=_robots_status_transport(status))
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    run = technical_readiness(ev.pages, ev.domain, site_type="commerce", defaulted=ev.defaulted)
    return ev, run


@pytest.mark.parametrize("status", [503, 500, 429])
def test_robots_5xx_or_429_is_not_measured(status):
    from scovant_core.r2 import OutcomeState
    from scovant_core.r2.technical import GATE_ROBOTS
    ev, run = _robots_run(status)
    assert {"robots", "content_signals"} <= ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["AI_CRAWLER_BLOCKED"].state == OutcomeState.NOT_MEASURED
    assert by_id[GATE_ROBOTS].state == OutcomeState.NA


@pytest.mark.parametrize("status", [404, 410])
def test_robots_404_is_a_real_allow_all(status):
    from scovant_core.r2 import OutcomeState
    ev, run = _robots_run(status)
    assert "robots" not in ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["AI_CRAWLER_BLOCKED"].state == OutcomeState.PASS


def _path_status_transport(path, status, body=""):
    import httpx

    inner = FixtureTransport(FIXTURES / "sites" / "commerce-good")

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            if request.url.path == path:
                return httpx.Response(status, text=body)
            return inner.handle_request(request)

    return T()


def _run_with(transport):
    from scovant_core.r2.evaluate import technical_readiness
    store, _ctx, client = _store("commerce-good", transport=transport)
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    run = technical_readiness(ev.pages, ev.domain, site_type="commerce", defaulted=ev.defaulted)
    return ev, run


@pytest.mark.parametrize("path,status,probe,rules", [
    ("/llms.txt", 503, "llms_txt", ["LLMS_TXT_MISSING_OR_INVALID"]),
    ("/.well-known/ucp", 503, "ucp", ["UCP_PROFILE_ABSENT"]),
    ("/.well-known/mcp.json", 503, "mcp", ["MCP_ENDPOINT_ABSENT"]),
    ("/.well-known/mcp.json", 429, "mcp", ["MCP_ENDPOINT_ABSENT"]),
])
def test_unusable_answer_leaves_probe_not_measured(path, status, probe, rules):
    from scovant_core.r2 import OutcomeState
    ev, run = _run_with(_path_status_transport(path, status))
    assert probe in ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    for r in rules:
        assert by_id[r].state == OutcomeState.NOT_MEASURED, r


def test_llms_404_stays_measured():
    ev, _run = _run_with(_path_status_transport("/llms.txt", 404))
    assert "llms_txt" not in ev.defaulted


def test_truncated_robots_is_defaulted():
    ev, _run = _run_with(_path_status_transport("/robots.txt", 200, "User-agent: *\nAllow: /\n" + "# pad\n" * 400000))
    assert {"robots", "content_signals"} <= ev.defaulted


def test_failed_pages_gatherer_defaults_pages(monkeypatch):
    ev, _run = _failing_run(monkeypatch, "pages")
    assert "pages" in ev.defaulted


def test_page_bot_protection_flag_only_when_blocked(monkeypatch):
    from scovant_core import evidence
    real = evidence.GATHERERS["pages"]

    def marked(*a, **k):
        out = real(*a, **k)
        for i, p in enumerate(out["pages"]):
            p["bot_protection"] = {"blocked": i == 0}
        return out

    monkeypatch.setitem(evidence.GATHERERS, "pages", marked)
    store, _ctx, client = _store("commerce-good")
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    assert ev.pages and ev.pages[0].get("_http_status") is not None
    flagged = [p for p in ev.pages if "bot_protection" in p]
    assert len(flagged) == 1 and flagged[0]["bot_protection"]["blocked"] is True
    assert flagged[0] is ev.pages[0]  # every other page is clean and carries no key
    # O2a: the pages gatherer's bot_protection IS the content fetch, so a
    # blocked one is a content wall — the shared builder's Technical skip key.
    assert flagged[0]["content_blocked"] is True
    assert not any("content_blocked" in p for p in ev.pages[1:])


def _technical_not_measured(monkeypatch, pages_gatherer):
    from scovant_core import evidence
    from scovant_core.r2.readiness import technical_report
    monkeypatch.setitem(evidence.GATHERERS, "pages", pages_gatherer)
    store, ctx, client = _store("commerce-good")
    try:
        readiness, outcomes = technical_report(store, ctx)
    finally:
        client.close()
    return readiness.technical.not_measured, outcomes


def _boom(*_a, **_k):
    raise RuntimeError("pages down")


@pytest.mark.parametrize("gatherer", [_boom, lambda *_a, **_k: {"pages": []}])
def test_no_pages_reason_is_probe_failed_pages(monkeypatch, gatherer):
    not_measured, outcomes = _technical_not_measured(monkeypatch, gatherer)
    reasons = {n.reason for n in not_measured}
    assert "probe_failed:pages" in reasons
    assert "no_pages_evaluated" not in reasons
    assert "no_pages_evaluated" not in {o.reason for o in outcomes}


# --- evidence step 1: markdown / link headers / payments / machine-rep -----------
_NEW_PROBES = {
    "markdown_agents": ["MARKDOWN_FOR_AGENTS_ABSENT", "CONTENT-NEG-002", "CONTENT-NEG-004"],
    "link_headers": ["LINK_HEADERS_ABSENT"],
    "agent_payments": ["AGENT_PAYMENTS_ABSENT"],
    "machine_rep": ["MACHINE-REP-004", "MACHINE-REP-005"],
}


def test_commerce_good_has_the_four_probe_blocks():
    store, _ctx, client = _store("commerce-good")
    try:
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    d = ev.domain
    assert set(_NEW_PROBES) <= set(d)
    assert "negotiation" in d["markdown_agents"] and "mirror" in d["markdown_agents"]
    assert {"present", "rels", "agent_relevant"} <= set(d["link_headers"])
    assert {"any_non_ucp", "protocols"} <= set(d["agent_payments"])
    assert d["machine_rep"]["attempted"] is True
    assert not set(_NEW_PROBES) & ev.defaulted


def test_new_probes_are_no_longer_not_gathered_by_core():
    from scovant_core.r2.readiness import technical_report
    store, ctx, client = _store("commerce-good")
    try:
        readiness, outcomes = technical_report(store, ctx)
    finally:
        client.close()
    reasons = {o.rule: o.reason for o in outcomes}
    for rules in _NEW_PROBES.values():
        for r in rules:
            assert reasons.get(r) != "not_gathered_by_core", r


class _RaiseOn:
    """FixtureTransport, except the listed paths raise a transport error."""

    def __init__(self, *paths, only_headers=None):
        import httpx
        self._inner = FixtureTransport(FIXTURES / "sites" / "commerce-good")
        self._paths, self._headers, self._err = set(paths), only_headers, httpx.ConnectError

    def handle_request(self, request):
        hit = request.url.path in self._paths and (
            self._headers is None or self._headers in request.headers)
        if hit:
            raise self._err("down", request=request)
        return self._inner.handle_request(request)


def _homepage_negotiation_transport(header, status=None):
    import httpx
    inner = FixtureTransport(FIXTURES / "sites" / "commerce-good")

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            if request.url.path in ("", "/") and header in request.headers:
                if status is None:
                    raise httpx.ConnectError("down", request=request)
                return httpx.Response(status, text="down")
            return inner.handle_request(request)

    return T()


@pytest.mark.parametrize("header,status,probe", [
    ("prefer", None, "machine_rep"), ("prefer", 503, "machine_rep"), ("prefer", 429, "machine_rep"),
])
def test_machine_rep_unusable_is_not_measured(header, status, probe):
    from scovant_core.r2 import OutcomeState
    ev, run = _run_with(_homepage_negotiation_transport(header, status))
    assert probe in ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    for r in _NEW_PROBES[probe]:
        assert by_id[r].state == OutcomeState.NOT_MEASURED, r


@pytest.mark.parametrize("status", [None, 503, 429])
def test_markdown_unusable_is_not_measured(status):
    from scovant_core.r2 import OutcomeState
    ev, run = _run_with(_homepage_negotiation_transport("accept", status))
    # the negotiation GET (Accept: text/markdown) is the only one answered badly
    assert "markdown_agents" in ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["MARKDOWN_FOR_AGENTS_ABSENT"].state == OutcomeState.NOT_MEASURED


def test_payments_and_link_headers_fetch_error_is_defaulted(monkeypatch):
    from scovant_core import evidence
    from scovant_core.r2 import OutcomeState
    monkeypatch.setitem(evidence.GATHERERS, "link_headers_surface", lambda *a, **k: {
        "present": False, "rels": [], "agent_relevant": False, "fetch_status": "error", "error": "x"})
    monkeypatch.setitem(evidence.GATHERERS, "agent_payments_surface", _boom)
    ev, run = _run_with(FixtureTransport(FIXTURES / "sites" / "commerce-good"))
    assert {"link_headers", "agent_payments"} <= ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    assert by_id["LINK_HEADERS_ABSENT"].state == OutcomeState.NOT_MEASURED
    assert by_id["AGENT_PAYMENTS_ABSENT"].state == OutcomeState.NOT_MEASURED


def test_404_on_the_probe_paths_stays_measured():
    ev, _run = _run_with(_path_status_transport("/index.md", 404))
    assert not set(_NEW_PROBES) & ev.defaulted
    assert set(_NEW_PROBES) <= set(ev.domain)


def test_report_reason_names_the_failed_probe(monkeypatch):
    from scovant_core import evidence
    from scovant_core.r2.readiness import technical_report
    monkeypatch.setitem(evidence.GATHERERS, "machine_rep_surface", _boom)
    store, ctx, client = _store("commerce-good")
    try:
        _readiness, outcomes = technical_report(store, ctx)
    finally:
        client.close()
    rows = {o.rule: o for o in outcomes}
    for r in _NEW_PROBES["machine_rep"]:
        assert rows[r].state == "NOT_MEASURED" and rows[r].reason == "probe_failed:machine_rep", r


@pytest.mark.parametrize("path,status,probe", [
    ("/", 503, "link_headers"), ("/", 429, "link_headers"),
    ("/.well-known/acp.json", 503, "agent_payments"), ("/.well-known/acp.json", 429, "agent_payments"),
])
def test_unusable_answer_on_status_blind_producers_is_not_measured(path, status, probe):
    from scovant_core.r2 import OutcomeState
    ev, run = _run_with(_path_status_transport(path, status))
    assert probe in ev.defaulted
    by_id = {o.rule_id: o for o in run.outcomes}
    for r in _NEW_PROBES[probe]:
        assert by_id[r].state == OutcomeState.NOT_MEASURED, r


def test_404_on_link_headers_and_payments_paths_stays_measured():
    for path in ("/", "/.well-known/acp.json"):
        ev, _run = _run_with(_path_status_transport(path, 404))
        assert not {"link_headers", "agent_payments"} & ev.defaulted, path


OFF_REQUESTS = 33


def _request_count(technical):
    from scovant_core.engine import scan
    transport = FixtureTransport(FIXTURES / "sites" / "commerce-good")
    seen = []
    orig = transport.handle_request

    def counting(request):
        seen.append(request.url.path)
        return orig(request)
    transport.handle_request = counting
    scan(URL, ScanOptions(technical=technical), transport=transport)
    return len(seen)


def test_technical_false_never_triggers_the_new_gatherers():
    off = _request_count(False)
    on = _request_count(True)
    assert off == OFF_REQUESTS
    assert on == 55


# --- evidence step 2: content blocks and landmarks --------------------------------
def test_pages_carry_blocks_and_landmarks_from_the_page_html():
    from scovant_core.parsers.html import extract_content_blocks, extract_landmark_tags
    store, _ctx, client = _store("commerce-good")
    try:
        ev = evidence_from_store(store, site_type="commerce")
        raw = store.try_get("pages")["pages"]
    finally:
        client.close()
    assert ev.pages
    htmls = [p["html"] for p in raw if p.get("parsed")]
    for page, html in zip(ev.pages, htmls, strict=True):
        assert page["content_blocks"] == extract_content_blocks(html)
        assert page["landmark_tags"] == extract_landmark_tags(html)


def _page_transport(html):
    import httpx

    inner = FixtureTransport(FIXTURES / "sites" / "commerce-good")

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            if request.url.path == "/":
                return httpx.Response(200, text=html, headers={"content-type": "text/html"})
            return inner.handle_request(request)

    return T()


_PARA = ("Our returns policy lets customers send back any unused item within thirty days "
         "of delivery for a full refund of 100 percent, and we pay the postage in 2024. ") * 4
_CONTENT = (f"<html lang='en'><head><title>Guide</title></head><body><main><article>"
            f"<h1>Returns guide</h1><h2>How long do I have?</h2><p>{_PARA}</p>"
            f"<h2>Who pays?</h2><p>{_PARA}</p></article></main></body></html>")


def _blog_outcomes(html):
    from scovant_core.r2.evaluate import technical_readiness
    store, _ctx, client = _store("commerce-good", transport=_page_transport(html))
    try:
        ev = evidence_from_store(store, site_type="blog")
    finally:
        client.close()
    run = technical_readiness(ev.pages, ev.domain, site_type="blog", defaulted=ev.defaulted)
    return ev, {o.rule_id: o for o in run.outcomes}


def test_citability_weak_measured_for_blog_with_real_blocks():
    ev, outs = _blog_outcomes(_CONTENT)
    assert any(p["content_blocks"] for p in ev.pages)
    assert ev.domain["content_pages_scored"] >= 1
    assert outs["CITABILITY_WEAK"].state.value not in ("NOT_MEASURED", "UNKNOWN")


def test_citability_weak_not_measured_when_html_yields_no_blocks():
    ev, outs = _blog_outcomes("<html><body><div>hi</div></body></html>")
    home = ev.pages[0]
    assert home["content_blocks"] == []
    assert ev.domain["content_pages_scored"] == 0
    assert outs["CITABILITY_WEAK"].state.value == "NOT_MEASURED"


def test_semantic_html_measured_on_commerce_good():
    from scovant_core.r2.readiness import technical_report
    store, ctx, client = _store("commerce-good")
    try:
        _r, outcomes = technical_report(store, ctx)
    finally:
        client.close()
    o = {x.rule: x for x in outcomes}["SEMANTIC_HTML_ABSENT"]
    assert o.reason != "not_gathered_by_core"
    assert o.state not in ("NOT_MEASURED", "UNKNOWN")


def test_page_without_html_leaves_blocks_and_landmarks_unset(monkeypatch):
    store, _ctx, client = _store("commerce-good")
    try:
        gathered = store.try_get("pages")
        for p in gathered["pages"]:
            p["html"] = ""
        ev = evidence_from_store(store, site_type="commerce")
    finally:
        client.close()
    assert ev.pages
    for page in ev.pages:
        assert "landmark_tags" not in page and "content_blocks" not in page


def test_crawl_graph_evidence_matches_pages_carrying_internal_links():
    store, ctx, client = _store("commerce-good")
    try:
        ev = evidence_from_store(store, site_type="commerce", root=URL)
    finally:
        client.close()
    graph = ev.domain["crawl_graph"]
    carrying = [p for p in ev.pages if "internal_links" in p]
    assert carrying and graph["sampled"] == len(carrying)
    assert graph["root"] == URL and graph["root_fallback"] is False


def test_crawl_graph_drops_pages_without_internal_links_and_root_falls_back():
    class _S:
        def try_get(self, name):
            if name == "pages":
                return {"pages": [
                    {"status": 200, "parsed": {"internal_links": {"urls": ["https://example.com/b"]}}, "url": "https://example.com/a"},
                    {"status": 200, "parsed": {"title": "x"}, "url": "https://example.com/b"},
                ]}
            return None
    ev = evidence_from_store(_S(), site_type="other", root="https://example.com/")
    assert ev.domain["crawl_graph"]["sampled"] == 1
