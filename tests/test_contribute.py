import json

import httpx
import pytest

from scovant_core import cli, contribute
from scovant_core.contribute import build_payload, send
from tests.conftest import FIXTURES, FixtureTransport
from tests.test_report_markdown import _report

PAYLOAD_KEYS = {
    "domain", "timestamp", "core_version", "ruleset_version", "ruleset_digest",
    "profile", "experimental", "check_statuses", "score",
}


def test_payload_is_exactly_d3():
    p = build_payload(_report("commerce-good"))
    assert set(p) == PAYLOAD_KEYS and p["domain"] == "example.com"
    assert set(p["score"]) == {"value", "grade", "coverage", "status"}
    assert all(v in ("PASS", "WARN", "FAIL", "N/A", "ERROR") for v in p["check_statuses"].values())
    assert "http" not in json.dumps(p["check_statuses"])  # no URLs


def _factory(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("status,body,expect", [
    (200, {"accepted": True, "deduplicated": False}, "accepted"),
    (200, {"accepted": True, "deduplicated": True}, "deduplicated"),
    (503, {"detail": "contributions_disabled"}, "failed: contributions are not being accepted right now"),
    (422, {"detail": "unknown_check"}, "failed: rejected (422 unknown_check)"),
    (429, {}, "failed: rejected (429)"),
])
def test_send_outcomes(monkeypatch, status, body, expect):
    seen = {}

    def handler(req):
        seen["url"], seen["method"] = str(req.url), req.method
        return httpx.Response(status, json=body)

    monkeypatch.setattr(contribute, "_HTTP_FACTORY", _factory(handler))
    r = send(build_payload(_report()))
    assert seen["url"] == contribute.CONTRIBUTE_URL and seen["method"] == "POST"
    assert expect in r.message


def test_send_never_raises_on_transport_error(monkeypatch):
    def handler(req):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(contribute, "_HTTP_FACTORY", _factory(handler))
    assert send({}).ok is False


def test_cli_contribute_prints_one_line_and_keeps_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / "commerce-bad"))
    monkeypatch.setattr(
        contribute, "_HTTP_FACTORY",
        _factory(lambda r: httpx.Response(200, json={"accepted": True, "deduplicated": False})),
    )
    code = cli.main(["scan", "https://example.com/", "--contribute", "--min-score", "100"])
    assert code == 1  # threshold unchanged by contribute
    assert "contributed: example.com (accepted)" in capsys.readouterr().err


def test_cli_without_flag_never_posts(monkeypatch):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / "commerce-good"))
    monkeypatch.setattr(
        contribute, "_HTTP_FACTORY",
        _factory(lambda r: (_ for _ in ()).throw(AssertionError("posted"))),
    )
    assert cli.main(["scan", "https://example.com/"]) == 0


def test_contribute_refuses_private_targets():
    assert cli.main(["scan", "http://127.0.0.1:8000/", "--allow-private-networks", "--contribute"]) == 2


def test_profiles_are_imported_not_duplicated():
    from scovant_core.profiles import PROFILES

    assert cli._PROFILES is PROFILES
