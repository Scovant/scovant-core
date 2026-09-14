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
    result = asyncio.run(server.call_tool(name, args))
    # 1.28.1's FastMCP.call_tool(convert_result=True): our tools all
    # annotate `-> str`, a "primitive" return type FastMCP wraps as
    # structured output — the call returns `(content_blocks, structured)`,
    # not a bare content list or a `CallToolResult`. Unwrap to the content
    # blocks; the test bodies below then index `[0].text`.
    return result[0] if isinstance(result, tuple) else result


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
    assert len(checks) == 50 and {"id", "title", "category", "weight", "profiles", "experimental"} <= set(checks[0])
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
        Draft202012Validator.check_schema(t.inputSchema)
