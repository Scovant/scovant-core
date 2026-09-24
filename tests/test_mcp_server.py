"""Tests for the stdio MCP server (`scovant mcp`). Skips entirely when the
optional `mcp` extra is not installed — proves the base install has no
hidden dependency on the SDK."""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp")

pytestmark = pytest.mark.mcp

from scovant_core import mcp_server  # noqa: E402
from tests.conftest import FIXTURES, FixtureTransport  # noqa: E402


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(mcp_server, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / "commerce-good"))
    return mcp_server.build_server()


def _call(server, name, **args):
    # mcp 2.x: `call_tool` returns a `CallToolResult`; the test bodies below
    # index the content blocks (`[0].text`).
    return asyncio.run(server.call_tool(name, args)).content


def test_tool_names_and_passive_prefix(server):
    tools = asyncio.run(server.list_tools())
    assert sorted(t.name for t in tools) == ["explain_check", "get_core_score", "get_finding", "list_checks", "scan_site"]
    assert all(t.description.startswith("Passive/static only.") for t in tools)


def test_scan_site_returns_report_and_get_finding_reads_it(server):
    report = json.loads(_call(server, "scan_site", url="https://example.com/")[0].text)
    assert report["score"]["value"] == 100
    finding = json.loads(_call(server, "get_finding", scan_id=report["scan_id"], check_id="CORE-ACCESS-001")[0].text)
    assert finding["status"] == "PASS"


def test_get_finding_unknown_scan_is_an_error_not_a_rescan(server):
    with pytest.raises(Exception):  # noqa: B017 — mcp.server.fastmcp.exceptions.ToolError
        _call(server, "get_finding", scan_id="nope", check_id="CORE-ACCESS-001")


def test_list_and_explain(server):
    checks = json.loads(_call(server, "list_checks")[0].text)
    assert len(checks) == 66 and {"id", "title", "category", "weight", "profiles", "experimental"} <= set(checks[0])
    ex = json.loads(_call(server, "explain_check", check_id="CORE-MACHINE-007")[0].text)
    assert ex["id"] == "CORE-MACHINE-007" and ex["why_it_matters"] and ex["limitations"]


def test_get_core_score_shape(server):
    s = json.loads(_call(server, "get_core_score", url="https://example.com/")[0].text)
    assert {"score", "grade", "coverage", "status", "pass", "warn", "fail", "error", "na", "scan_id"} == set(s)


def test_unknown_profile_is_a_tool_error_not_a_scan(server):
    with pytest.raises(Exception):  # noqa: B017 — mcp.server.fastmcp.exceptions.ToolError
        _call(server, "scan_site", url="https://example.com/", profile="not-a-real-profile")
    # never took the single-flight lock — the bad input was rejected before
    # any scan attempt, not left held by a scan that then failed.
    assert mcp_server._SCAN_LOCK.acquire(blocking=False)
    mcp_server._SCAN_LOCK.release()


def test_single_flight_lock(server):
    assert mcp_server._SCAN_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(Exception, match="scan in progress"):
            _call(server, "get_core_score", url="https://example.com/")
    finally:
        mcp_server._SCAN_LOCK.release()


def test_cli_without_extra_gives_a_clear_message(monkeypatch, capsys):
    from scovant_core import cli

    monkeypatch.setattr(mcp_server, "_import_sdk", lambda: (_ for _ in ()).throw(ImportError("no mcp")))
    assert cli.main(["mcp"]) == 2
    assert 'pip install "scovant-core[mcp]"' in capsys.readouterr().err


def test_tool_input_schemas_are_valid_json_schema(server):
    from jsonschema import Draft202012Validator

    for t in asyncio.run(server.list_tools()):
        Draft202012Validator.check_schema(t.input_schema)


def test_scan_site_description_counts_the_registry(server):
    import scovant_core.checks  # noqa: F401
    from scovant_core.checks.registry import CHECKS

    tool = next(t for t in asyncio.run(server.list_tools()) if t.name == "scan_site")
    assert f"{len(CHECKS)} checks" in tool.description
    assert "45 checks" not in tool.description


def test_medium_defaults_to_mcp_and_accepts_claude_code(monkeypatch, capsys):
    monkeypatch.delenv("SCOVANT_CTA_MEDIUM", raising=False)
    assert mcp_server._medium() == "mcp"
    monkeypatch.setenv("SCOVANT_CTA_MEDIUM", "claude-code")
    assert mcp_server._medium() == "claude-code"
    monkeypatch.setenv("SCOVANT_CTA_MEDIUM", "carrier-pigeon")
    assert mcp_server._medium() == "mcp"          # unknown → default, never a crash
    assert "carrier-pigeon" in capsys.readouterr().err


def test_scan_site_default_format_is_findings_without_pass_bodies(server):
    out = json.loads(_call(server, "scan_site", url="https://example.com")[0].text)
    assert set(out) == {
        "scan_id", "input_url", "final_url", "profile", "score", "counts",
        "findings", "security_findings", "security_disclaimer", "passed", "cta",
    }
    assert set(out["score"]) == {"value", "grade", "coverage", "status", "scope"}
    assert out["score"]["scope"] == "CANONICAL"
    assert all(f["status"] != "PASS" for f in out["findings"])
    assert all(f["category"] != "security" for f in out["findings"])
    assert all(isinstance(i, str) and i.startswith("CORE-") for i in out["passed"])
    assert set(out["counts"]) == {"PASS", "WARN", "FAIL", "ERROR", "N/A"}
    assert out["cta"].endswith("utm_medium=mcp&utm_campaign=oss")
    # every finding kept its evidence (the agent's raw material)
    assert all("evidence" in f for f in out["findings"])


def test_scan_site_security_findings_are_split_out_and_never_scored(monkeypatch):
    """security-bad has non-PASS CORE-SECURITY-* findings; they must never
    appear in `findings` (which drives the readiness/score narrative) and
    must carry the never-scored disclaimer."""
    monkeypatch.setattr(mcp_server, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / "security-bad"))
    server = mcp_server.build_server()
    out = json.loads(_call(server, "scan_site", url="https://example.com")[0].text)
    assert out["security_findings"], "security-bad fixture is expected to carry non-PASS security findings"
    assert all(f["category"] == "security" for f in out["security_findings"])
    assert all(f["status"] != "PASS" for f in out["security_findings"])
    security_ids = {f["id"] for f in out["security_findings"]}
    assert not security_ids & {f["id"] for f in out["findings"]}
    assert all(f["category"] != "security" for f in out["findings"])
    assert out["security_disclaimer"] == (
        "Passive Agentic Security & Trust signals — never scored, not an overall security rating."
    )


def test_scan_site_json_format_is_todays_full_report(server, monkeypatch):
    """The `json` format must be exactly `render_json(report)` — not merely
    equal to whatever the same call happened to stash in the ring buffer
    (that would pass even if the json branch re-shaped the payload, since
    both sides come from the same call)."""
    captured = {}
    real_run_scan = mcp_server._run_scan

    def spy(*a, **k):
        report, data = real_run_scan(*a, **k)
        captured["report"] = report
        return report, data

    monkeypatch.setattr(mcp_server, "_run_scan", spy)
    out = _call(server, "scan_site", url="https://example.com", format="json")[0].text
    data = json.loads(out)
    expected = json.loads(mcp_server.render_json(captured["report"]))
    assert data == expected


def test_medium_only_computed_for_findings_and_markdown_formats(server, monkeypatch):
    """`_medium()` prints a stderr warning on an unrecognized
    SCOVANT_CTA_MEDIUM — that warning must fire once per relevant call, not
    once per scan_site call regardless of format."""
    calls = []
    real_medium = mcp_server._medium

    def spy():
        calls.append(1)
        return real_medium()

    monkeypatch.setattr(mcp_server, "_medium", spy)
    _call(server, "scan_site", url="https://example.com", format="json")
    _call(server, "scan_site", url="https://example.com", format="summary")
    assert calls == [], "json/summary formats never need the CTA medium"
    _call(server, "scan_site", url="https://example.com", format="findings")
    assert calls == [1]
    _call(server, "scan_site", url="https://example.com", format="markdown")
    assert calls == [1, 1]


def test_scan_site_summary_format_matches_get_core_score(server):
    summary = json.loads(_call(server, "scan_site", url="https://example.com", format="summary")[0].text)
    score = json.loads(_call(server, "get_core_score", url="https://example.com")[0].text)
    assert set(summary) == set(score)
    assert {k: v for k, v in summary.items() if k != "scan_id"} == {k: v for k, v in score.items() if k != "scan_id"}


def test_scan_site_markdown_format_carries_the_medium(server, monkeypatch):
    monkeypatch.setenv("SCOVANT_CTA_MEDIUM", "claude-code")
    out = _call(server, "scan_site", url="https://example.com", format="markdown")[0].text
    assert out.lstrip().startswith("#")
    assert "utm_medium=claude-code" in out


def test_findings_format_still_lets_get_finding_read_a_pass_check(server):
    out = json.loads(_call(server, "scan_site", url="https://example.com")[0].text)
    if not out["passed"]:
        pytest.skip("fixture has no PASS check")
    f = json.loads(_call(server, "get_finding", scan_id=out["scan_id"], check_id=out["passed"][0])[0].text)
    assert f["status"] == "PASS" and f["id"] == out["passed"][0]


def test_unknown_format_is_a_tool_error_not_a_scan(server, monkeypatch):
    called = []
    monkeypatch.setattr(mcp_server, "_run_scan", lambda *a, **k: called.append(1))
    with pytest.raises(Exception):  # noqa: B017 — mcp.server.fastmcp.exceptions.ToolError
        _call(server, "scan_site", url="https://example.com", format="yaml")
    assert called == []


def test_allow_private_networks_reaches_scan_options(server, monkeypatch):
    seen = {}

    def fake_scan(url, options, transport=None):
        seen["allow"] = options.allow_private_networks
        raise RuntimeError("stop here")

    monkeypatch.setattr(mcp_server, "scan", fake_scan)
    with pytest.raises(Exception):  # noqa: B017 — mcp.server.fastmcp.exceptions.ToolError
        _call(server, "scan_site", url="http://localhost:3000", allow_private_networks=True)
    assert seen["allow"] is True
    with pytest.raises(Exception):  # noqa: B017 — mcp.server.fastmcp.exceptions.ToolError
        _call(server, "scan_site", url="https://example.com")
    assert seen["allow"] is False


def test_mcp_server_has_no_contribute_path():
    """A private-network scan is never contributed: the CLI enforces the
    exclusion with a flag check, this server enforces it structurally —
    there is nothing here that could contribute."""
    import inspect
    assert "contribute" not in inspect.getsource(mcp_server)


def test_server_info_version_is_the_package_version(server):
    """`initialize` must advertise scovant-core's version, not the SDK's.

    mcp 1.x's FastMCP had no version argument and fell back to the SDK's own
    version (1.30.0 on the day this was noticed); 2.x's MCPServer takes it
    as a constructor kwarg and defaults it to "".
    """
    from scovant_core import __version__

    assert server.version == __version__
