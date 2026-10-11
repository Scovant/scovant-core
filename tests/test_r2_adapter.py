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
