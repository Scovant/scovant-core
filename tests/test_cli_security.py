"""`--fail-on-security` (CLI exit 6) and the Action's `security_critical`/
`security_high` outputs + gate.

`security-bad`'s only FAIL findings are at severity `medium` (CSP framing,
cookie attributes, security.txt expiry — see fixtures/PROVENANCE.md); its
one `high`-severity finding (CORE-SECURITY-013) is a WARN, which never
gates. So the FAIL/`high` case is built here, at test time, over a
`httpx.MockTransport` carrying a runtime-assembled vendor-shaped credential
(never a contiguous literal in source, same convention as
`checks/security/_secrets.py`'s `_KNOWN_EXAMPLES`) — a real vendor-shaped
secret must never sit in a committed, publish-guard-scanned fixture."""
from __future__ import annotations

import httpx

from scovant_core import action, cli
from tests.conftest import FIXTURES, FixtureTransport

CLOCK = lambda: "2026-09-16T00:00:00Z"  # noqa: E731

_MIN_HTML = (b"<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>"
             + b"words " * 40 + b"</p></body></html>")


def _run(monkeypatch, capsys, site, *extra):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / site))
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)
    code = cli.main(["scan", "https://example.com/", "--format", "json", *extra])
    return code, capsys.readouterr().out


def _security_high_transport() -> httpx.MockTransport:
    # Built at runtime, never as a contiguous literal — see the module
    # docstring and `_secrets.py`'s own `_KNOWN_EXAMPLES` comment.
    aws_key = "AKIA" + "Q7ZK2M9XJ3P6WVT4"
    llms = f'# Site\n> A shop.\n"api_key": "{aws_key}"\n'.encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": "https://example.com" + request.url.path})
        if request.url.path == "/":
            return httpx.Response(200, content=_MIN_HTML, headers={"content-type": "text/html"})
        if request.url.path == "/llms.txt":
            return httpx.Response(200, content=llms, headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    return httpx.MockTransport(handler)


def _run_mock(monkeypatch, capsys, *extra):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", _security_high_transport)
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)
    code = cli.main(["scan", "https://example.com/", "--format", "json", *extra])
    return code, capsys.readouterr().out


def test_fail_on_security_high_gates_on_a_real_high_confidence_credential(monkeypatch, capsys):
    code, out = _run_mock(monkeypatch, capsys, "--fail-on-security", "high")
    assert code == 6
    import json

    d = json.loads(out)
    f = next(x for x in d["findings"] if x["id"] == "CORE-SECURITY-007")
    assert f["status"] == "FAIL" and f["severity"] == "high"


def test_fail_on_security_medium_and_never_on_security_bad(monkeypatch, capsys):
    # security-bad has FAIL findings at severity medium (CSP, cookies,
    # security.txt) but none at high/critical — its one high-severity
    # finding (CORE-SECURITY-013) is a WARN, which never gates.
    code, _ = _run(monkeypatch, capsys, "security-bad", "--fail-on-security", "medium")
    assert code == 6
    code, _ = _run(monkeypatch, capsys, "security-bad", "--fail-on-security", "high")
    assert code == 0
    code, _ = _run(monkeypatch, capsys, "security-bad", "--fail-on-security", "critical")
    assert code == 0
    code, _ = _run(monkeypatch, capsys, "security-good", "--fail-on-security", "medium")
    assert code == 0


def test_security_gate_is_independent_of_readiness_gate(monkeypatch, capsys):
    code, _ = _run(monkeypatch, capsys, "security-bad", "--fail-on", "never")
    assert code == 0
    # `--fail-on` is readiness-only: security-bad has NO readiness FAIL
    # (only SECURITY-category ones), so `--fail-on fail` alone must not
    # gate on them.
    code, _ = _run(monkeypatch, capsys, "security-bad", "--fail-on", "fail")
    assert code == 0
    # ...but stacking `--fail-on-security` on top still gates independently.
    code, _ = _run(monkeypatch, capsys, "security-bad", "--fail-on", "fail", "--fail-on-security", "medium")
    assert code == 6


def test_action_outputs_and_gate(tmp_path, monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, "security-bad")
    p = tmp_path / "core.json"
    p.write_text(out)
    gh = tmp_path / "out.txt"
    assert action.main(["outputs", str(p), "--report-path", "r.html"], env={"GITHUB_OUTPUT": str(gh)}) == 0
    lines = gh.read_text().splitlines()
    assert any(line.startswith("security_critical=") for line in lines) and "security_high=1" in lines
    assert action.main(["gate", str(p), "--fail-on", "never", "--fail-on-security", "high"], env={}) == 0
    assert action.main(["gate", str(p), "--fail-on", "never", "--fail-on-security", "medium"], env={}) == 6
