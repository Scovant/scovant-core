"""readiness.technical on the scan report (PR-04a)."""
from __future__ import annotations

import json

import httpx
import pytest

from scovant_core.context import ScanOptions
from scovant_core.engine import scan
from scovant_core.r2 import PUBLIC_POLICY, model_id
from scovant_core.r2.technical import technical_manifest
from scovant_core.report.json import render_json
from tests.conftest import FIXTURES, FixtureTransport

URL = "https://example.com/"
CLOCK = lambda: "2026-09-04T00:00:00Z"  # noqa: E731


def _report(site: str, options: ScanOptions | None = None, transport=None):
    t = transport or FixtureTransport(FIXTURES / "sites" / site)
    return scan(URL, options, transport=t, clock=CLOCK, scan_id="local-test")


def test_commerce_good_has_a_technical_block():
    r = _report("commerce-good")
    t = r.readiness.technical
    assert t.model_id == model_id(technical_manifest(), PUBLIC_POLICY) == "R2.1@67df90af85b0"
    assert t.label == "Technical Readiness" and t.scope == "CORE_PASSIVE"
    assert t.evidence_state in ("ESTIMATED", "NOT_MEASURED")
    assert t.badge in (None, "estimated")                 # never agent_ready
    assert set(t.categories) == {"discoverability", "structured", "consistency", "actionability",
                                 "trust", "ucp", "citability"}
    assert r.technical_outcomes and all(o.state for o in r.technical_outcomes)
    assert r.schema_version == "1.1"                      # ruling 1: additive key, no bump


def test_declared_mcp_endpoint_is_not_measured():
    t = _report("commerce-good").readiness.technical
    assert "MCP_DISCOVERY_INVALID" in {n.rule for n in t.not_measured}


def test_robots_blocking_gptbot_withholds_the_badge():
    """commerce-good disallows GPTBot: the robots gate fires (badge block)."""
    r = _report("commerce-good")
    states = {o.rule: o.state for o in r.technical_outcomes}
    assert states["R2-GATE-ROBOTS-BLOCKS-AGENTS"] == "FAIL"
    assert r.readiness.technical.badge is None


def test_failed_entry_fetch_gives_not_measured_technical():
    def boom(request):
        raise httpx.ConnectError("down", request=request)
    r = _report("commerce-good", transport=httpx.MockTransport(boom))
    t = r.readiness.technical
    assert (t.rating, t.status, t.evidence_state, t.badge) == (None, "INSUFFICIENT_EVIDENCE", "NOT_MEASURED", None)


def test_narrowed_selection_reports_the_same_technical():
    full = _report("commerce-good").readiness.technical
    narrow = _report("commerce-good", ScanOptions(include=("CORE-ACCESS-001",))).readiness.technical
    assert narrow.model_dump() == full.model_dump()


def test_site_type_flag_is_recorded():
    t = _report("commerce-good", ScanOptions(site_type="blog")).readiness.technical
    assert (t.site_type, t.site_type_origin) == ("blog", "flag")


def test_json_renders_the_block():
    data = json.loads(render_json(_report("commerce-good")))
    assert data["readiness"]["technical"]["model_id"] == "R2.1@67df90af85b0"


def test_technical_failure_does_not_abort_the_scan(monkeypatch):
    base = _report("commerce-good")

    def boom(store, ctx):
        raise RuntimeError("boom")
    monkeypatch.setattr("scovant_core.r2.readiness.technical_report", boom)
    r = _report("commerce-good")
    assert r.score == base.score
    assert r.readiness is None and r.technical_outcomes == []
    assert r.metrics["technical_readiness_error"]["kind"] == "RuntimeError"


def test_technical_gather_errors_empty_when_nothing_failed():
    assert _report("commerce-good").metrics["technical_gather_errors"] == []


def test_technical_gather_errors_lists_only_the_technical_pass(monkeypatch):
    from scovant_core.evidence import GatherError
    from scovant_core.r2 import readiness

    real = readiness.technical_report

    def failing_gatherer(store, ctx):
        out = real(store, ctx)
        store.errors["sitemap_probe"] = GatherError("sitemap_probe", "ConnectError", "dns down for secret.test")
        return out
    monkeypatch.setattr(readiness, "technical_report", failing_gatherer)
    r = _report("commerce-good")
    assert [e["name"] for e in r.metrics["technical_gather_errors"]] == ["sitemap_probe"]
    assert r.metrics["technical_gather_errors"][0]["kind"] == "ConnectError"
    assert "sitemap_probe" not in r.metrics["gather_errors"]  # the selection's own list is unchanged


def _reasons(report):
    t = report.readiness.technical
    return ({n.rule: n.reason for n in t.not_measured},
            {o.rule: o.reason for o in report.technical_outcomes})


def test_page_token_bloat_is_measured_with_the_tokenizer():
    pytest.importorskip("tiktoken")
    _, outs = _reasons(_report("commerce-good"))
    nm, _ = _reasons(_report("commerce-good"))
    assert "PAGE_TOKEN_BLOAT" not in nm and outs["PAGE_TOKEN_BLOAT"] != "tokenizer_unavailable"


def test_page_token_bloat_not_measured_without_the_tokenizer(monkeypatch):
    from scovant_core.r2 import adapter, readiness
    monkeypatch.setattr(adapter, "page_token_cost", lambda *a: None)
    monkeypatch.setattr(readiness, "tokenizer_available", lambda: False)
    nm, outs = _reasons(_report("commerce-good"))
    assert nm["PAGE_TOKEN_BLOAT"] == "tokenizer_unavailable"
    assert outs["PAGE_TOKEN_BLOAT"] == "tokenizer_unavailable"


def test_not_measured_reasons_are_human_readable():
    r = _report("commerce-good")
    nm, outs = _reasons(r)
    assert nm["MCP_DISCOVERY_INVALID"] == "handshake_not_performed"
    assert "MARKDOWN_FOR_AGENTS_ABSENT" not in nm  # gathered since PR-04b
    assert "SEMANTIC_HTML_ABSENT" not in nm  # gathered since the content-block step
    assert outs["MCP_DISCOVERY_INVALID"] == "handshake_not_performed"
    for o in r.technical_outcomes:
        if o.state in ("NOT_MEASURED", "UNKNOWN"):
            assert o.reason != "predicate", o.rule
    assert all(n.reason != "predicate" for n in r.readiness.technical.not_measured)


def test_failed_robots_names_the_probe():
    inner = FixtureTransport(FIXTURES / "sites" / "commerce-good")

    class T(httpx.BaseTransport):
        def handle_request(self, request):
            if request.url.path == "/robots.txt":
                return httpx.Response(503, text="")
            return inner.handle_request(request)

    r = _report("commerce-good", transport=T())
    nm, outs = _reasons(r)
    assert nm["AI_CRAWLER_BLOCKED"] == "probe_failed:robots"
    assert outs["AI_CRAWLER_BLOCKED"] == "probe_failed:robots"


def test_unknown_site_type_is_rejected_before_any_io():
    import pytest

    def never(request):
        raise AssertionError("network used")
    with pytest.raises(ValueError):
        scan(URL, ScanOptions(site_type="nope"), transport=httpx.MockTransport(never))
