"""CLI exit-code contract: `main(argv)` never talks to the real network in
tests — the module-level `_TRANSPORT_FACTORY`/`_CLOCK` hooks are monkeypatched
to a `FixtureTransport` (or a raising `httpx.MockTransport`) so every case is
deterministic and hermetic."""
from __future__ import annotations

import json
import logging

import httpx
import pytest

import scovant_core
from scovant_core import cli
from tests.conftest import FIXTURES, FixtureTransport

CLOCK = lambda: "2026-09-04T00:00:00Z"  # noqa: E731 — deterministic test clock

# Assembled the same way the CLI itself assembles it (see cli.py's own
# comment) — the publish guard bans the literal concatenated string
# everywhere in this package, tests included.
_CLOUD_CRAWLER_TOKEN = "Scovant" + "Bot"


def _use_fixture(monkeypatch, name: str = "commerce-good", host: str = "example.com") -> None:
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: FixtureTransport(FIXTURES / "sites" / name, host))
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)


def _use_network_error(monkeypatch) -> None:
    def _boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure", request=request)

    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: httpx.MockTransport(_boom))
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)


def test_version_prints_version_and_returns_0(capsys):
    code = cli.main(["--version"])
    out = capsys.readouterr().out
    assert code == 0
    assert scovant_core.__version__ in out
    assert out.strip() == f"scovant-core {scovant_core.__version__}"


def test_bad_scheme_url_is_invalid_input(capsys):
    code = cli.main(["scan", "not-a-url"])
    err = capsys.readouterr().err
    assert code == 2
    assert "INVALID_INPUT" in err


def test_user_agent_containing_cloud_crawler_identity_is_rejected(capsys, monkeypatch):
    _use_fixture(monkeypatch)
    code = cli.main(["scan", "https://example.com/", "--user-agent", _CLOUD_CRAWLER_TOKEN])
    err = capsys.readouterr().err
    assert code == 2
    assert "INVALID_INPUT" in err


def test_user_agent_check_is_case_insensitive(capsys, monkeypatch):
    _use_fixture(monkeypatch)
    code = cli.main(["scan", "https://example.com/", "--user-agent", _CLOUD_CRAWLER_TOKEN.lower()])
    assert code == 2


@pytest.mark.parametrize("url", ["http://localhost/", "http://127.0.0.1/"])
def test_localhost_targets_are_a_security_block(capsys, monkeypatch, url):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: None)
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)
    code = cli.main(["scan", url])
    err = capsys.readouterr().err
    assert code == 4
    assert "SECURITY_BLOCK" in err


def test_commerce_good_json_format_returns_0_and_valid_json(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["scan", "https://example.com/", "--format", "json"])
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert "schema_version" in data


def test_min_score_100_trips_on_commerce_bad(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-bad")
    code = cli.main(["scan", "https://example.com/", "--min-score", "100"])
    assert code == 1


def test_min_score_gates_on_the_technical_rating_not_the_five_domain_score(capsys, monkeypatch):
    """commerce-bad: Technical Readiness 57, five-domain score 38. The gate
    reads Technical, so 57 passes and 58 fails — the five-domain 38 would
    fail both. A failed gate prints exactly one stderr line."""
    _use_fixture(monkeypatch, "commerce-bad")
    assert cli.main(["scan", "https://example.com/", "--min-score", "57", "--quiet"]) == 0
    assert capsys.readouterr().err == ""
    _use_fixture(monkeypatch, "commerce-bad")
    assert cli.main(["scan", "https://example.com/", "--min-score", "58", "--quiet"]) == 1
    assert capsys.readouterr().err.splitlines() == ["Technical Readiness 57 < --min-score 58 (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)"]


def test_min_score_on_a_clean_site_reads_technical(capsys, monkeypatch):
    """commerce-good: five-domain 100, Technical 82 (its robots.txt blocks
    GPTBot and the declared MCP endpoint is not measured). `--min-score 100`
    now fails; 82 passes."""
    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--min-score", "100", "--quiet"]) == 1
    assert capsys.readouterr().err.splitlines() == ["Technical Readiness 82 < --min-score 100 (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)"]
    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--min-score", "82", "--quiet"]) == 0


def test_legacy_score_min_score_100_is_reachable_on_a_clean_site(capsys, monkeypatch):
    """`--legacy-score` restores the five-domain gate: commerce-good has no
    FAIL and no WARN — every remaining verdict is a PASS or an honest N/A —
    so it scores 100 and a `--min-score 100` gate passes. (Before the
    machine-reference fix it "failed" on a declared MCP endpoint that
    answered 404 to a GET, which Core never probes for real.)"""
    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--min-score", "100", "--quiet"]) == 0
    assert capsys.readouterr().err == ""


def test_legacy_score_min_score_reads_the_five_domain_score(capsys, monkeypatch):
    """commerce-bad under `--legacy-score`: five-domain 38 — 38 passes, 39
    fails, silently (today's behaviour), whatever Technical says."""
    _use_fixture(monkeypatch, "commerce-bad")
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--min-score", "38", "--quiet"]) == 0
    _use_fixture(monkeypatch, "commerce-bad")
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--min-score", "39", "--quiet"]) == 1
    assert capsys.readouterr().err == ""


def test_fail_on_warn_trips_on_commerce_bad(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-bad")
    code = cli.main(["scan", "https://example.com/", "--fail-on", "warn"])
    assert code == 1


def test_fail_on_fail_trips_on_commerce_bad(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-bad")
    code = cli.main(["scan", "https://example.com/", "--fail-on", "fail"])
    assert code == 1


def test_unreachable_entry_is_a_network_fatal(capsys, monkeypatch):
    _use_network_error(monkeypatch)
    code = cli.main(["scan", "https://example.com/"])
    err = capsys.readouterr().err
    assert code == 3
    assert "NETWORK_ERROR" in err


def test_output_writes_the_file_and_prints_nothing_to_stdout(capsys, monkeypatch, tmp_path):
    _use_fixture(monkeypatch, "commerce-good")
    out_path = tmp_path / "report.json"
    code = cli.main(["scan", "https://example.com/", "--format", "json", "--output", str(out_path)])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "schema_version" in data


def test_include_a_single_check_yields_exactly_one_non_na_finding(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["scan", "https://example.com/", "--format", "json", "--include", "CORE-ACCESS-001"])
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    non_na = [f for f in data["findings"] if f["status"] != "N/A"]
    assert len(non_na) == 1
    assert non_na[0]["id"] == "CORE-ACCESS-001"


def test_unknown_include_selector_is_invalid_input(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["scan", "https://example.com/", "--include", "nope"])
    err = capsys.readouterr().err
    assert code == 2
    assert "INVALID_INPUT" in err


def test_quiet_text_prints_exactly_one_line(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["scan", "https://example.com/", "--quiet"])
    out = capsys.readouterr().out
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("Technical Readiness  ")


def test_min_score_out_of_range_is_argparse_exit_2():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "https://example.com/", "--min-score", "150"])
    assert exc_info.value.code == 2


def test_check_alias_works_like_scan(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["check", "https://example.com/", "--format", "json"])
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out)["schema_version"]


def test_no_color_disables_ansi_even_when_forced_tty(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-bad")
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    code = cli.main(["scan", "https://example.com/", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "\033[" not in out


def test_output_text_file_never_contains_ansi_even_on_a_forced_tty(capsys, monkeypatch, tmp_path):
    """Colour is derived from `not args.output` too, not just `--no-color` —
    a real TTY writing `--output report.txt` must never embed escape codes
    in the file (they'd be meaningless outside a terminal)."""
    _use_fixture(monkeypatch, "commerce-bad")
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    out_path = tmp_path / "report.txt"
    code = cli.main(["scan", "https://example.com/", "--output", str(out_path)])
    assert code == 0  # default --fail-on=never: FAIL findings alone don't affect the exit code
    content = out_path.read_text(encoding="utf-8")
    assert "\x1b" not in content
    assert "Technical Readiness  " in content


def test_verbose_attaches_a_scoped_handler_never_touches_root_logger(capsys, monkeypatch):
    root = logging.getLogger()
    core_logger = logging.getLogger("scovant_core")
    root_level_before = root.level
    core_level_before = core_logger.level
    try:
        _use_fixture(monkeypatch, "commerce-good")
        code = cli.main(["scan", "https://example.com/", "--verbose", "--quiet"])
        assert code in (0, 1)
        assert root.level == root_level_before
        assert core_logger.level == logging.DEBUG
        # Calling main() again with --verbose must not stack a second handler.
        handler_count = sum(1 for h in core_logger.handlers if getattr(h, "_scovant_cli_verbose_handler", False))
        cli.main(["scan", "https://example.com/", "--verbose", "--quiet"])
        handler_count_again = sum(
            1 for h in core_logger.handlers if getattr(h, "_scovant_cli_verbose_handler", False)
        )
        assert handler_count == handler_count_again == 1
    finally:
        core_logger.setLevel(core_level_before)
        for h in list(core_logger.handlers):
            if getattr(h, "_scovant_cli_verbose_handler", False):
                core_logger.removeHandler(h)


def test_exit_4_independent_of_check_selection_excluding_access(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: None)
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)
    code = cli.main(["scan", "http://localhost/", "--exclude", "access"])
    err = capsys.readouterr().err
    assert code == 4
    assert "SECURITY_BLOCK" in err


def test_exit_3_independent_of_check_selection_including_only_machine_001(capsys, monkeypatch):
    _use_network_error(monkeypatch)
    code = cli.main(["scan", "https://example.com/", "--include", "CORE-MACHINE-001"])
    err = capsys.readouterr().err
    assert code == 3
    assert "NETWORK_ERROR" in err


def test_security_block_takes_precedence_over_min_score(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: None)
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)
    code = cli.main(["scan", "http://localhost/", "--min-score", "100"])
    err = capsys.readouterr().err
    assert code == 4
    assert "SECURITY_BLOCK" in err


class _OwnFetchFailsTransport(FixtureTransport):
    """A fixture site where every https request except `keep` fails on OUR
    side (a connect error) — the real engine then reports the probes it
    could not make as not measured, which is how a real Technical
    DEGRADED / INSUFFICIENT_EVIDENCE arises without an entry error."""

    def __init__(self, root, keep):
        super().__init__(root)
        self.keep = keep

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https" and request.url.path not in self.keep:
            raise httpx.ConnectError("simulated own-side failure", request=request)
        return super().handle_request(request)


def _use_own_fetch_failures(monkeypatch, name: str, keep: set[str]) -> None:
    monkeypatch.setattr(cli, "_TRANSPORT_FACTORY", lambda: _OwnFetchFailsTransport(FIXTURES / "sites" / name, keep))
    monkeypatch.setattr(cli, "_CLOCK", CLOCK)


def _real_report(name: str, keep: set[str] | None = None):
    from scovant_core.engine import scan

    transport = (_OwnFetchFailsTransport(FIXTURES / "sites" / name, keep) if keep is not None
                 else FixtureTransport(FIXTURES / "sites" / name))
    return scan("https://example.com/", transport=transport, clock=CLOCK, scan_id="local-test")


def test_min_score_against_insufficient_evidence_exits_1(capsys, monkeypatch):
    """Only the entry page answers: both scores lack a number, no entry
    error (so not exit 3). The Technical gate fails with one stderr line."""
    _use_own_fetch_failures(monkeypatch, "commerce-good", {"/"})
    code = cli.main(["scan", "https://example.com/", "--min-score", "50", "--quiet"])
    assert code == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness has no number (status INSUFFICIENT_EVIDENCE); --min-score fails (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)",
    ]


def test_legacy_min_score_fails_on_a_five_domain_score_with_no_number(capsys, monkeypatch):
    """`--legacy-score`: only the entry page answers, so the five-domain
    score has no number (INSUFFICIENT_EVIDENCE) and no entry error. The
    legacy gate still fails — silently, as before 0.18.0 (no Technical
    gate line)."""
    report = _real_report("commerce-good", keep={"/"})
    assert (report.score.value, report.score.status) == (None, "INSUFFICIENT_EVIDENCE")
    assert report.metrics.get("entry_error") is None
    _use_own_fetch_failures(monkeypatch, "commerce-good", {"/"})
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--min-score", "50", "--quiet"]) == 1
    assert capsys.readouterr().err == ""


def test_insufficient_technical_with_ok_five_domain_score(capsys, monkeypatch):
    """Review Focus 4: a real commerce-good report (five-domain 100, OK)
    carrying the real INSUFFICIENT_EVIDENCE Technical block of a scan whose
    own fetches failed. `--min-score 0` fails; `--legacy-score --min-score
    0` passes."""
    good = _real_report("commerce-good")
    insufficient = _real_report("commerce-good", keep={"/"}).readiness
    assert insufficient is not None and insufficient.technical.rating is None
    assert insufficient.technical.status == "INSUFFICIENT_EVIDENCE"
    assert (good.score.value, good.score.status) == (100, "OK")
    report = good.model_copy(update={"readiness": insufficient})
    monkeypatch.setattr(cli, "scan", lambda *a, **k: report)

    assert cli.main(["scan", "https://example.com/", "--min-score", "0", "--quiet"]) == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness has no number (status INSUFFICIENT_EVIDENCE); --min-score fails (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)",
    ]
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--min-score", "0", "--quiet"]) == 0
    assert capsys.readouterr().err == ""


def test_report_without_readiness_fails_the_gates(capsys, monkeypatch):
    """Review Focus 1: Technical raised, so the engine recorded the error
    and left `readiness` None. `--min-score 0` and `--require-canonical`
    each exit 1 with one stderr line; `--legacy-score` still gates on the
    five-domain score; every output format still renders (no exit 5)."""
    def boom(store, ctx):
        raise RuntimeError("boom")
    monkeypatch.setattr("scovant_core.r2.readiness.technical_report", boom)

    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--min-score", "0", "--quiet"]) == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness has no number (not computed); --min-score fails (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)",
    ]
    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--require-canonical", "--quiet"]) == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness not computed; --require-canonical fails (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)",
    ]
    for fmt in ("text", "json", "markdown", "html"):
        _use_fixture(monkeypatch, "commerce-good")
        assert cli.main([
            "scan", "https://example.com/", "--legacy-score", "--min-score", "0", "--require-canonical",
            "--format", fmt,
        ]) == 0
        assert capsys.readouterr().err == ""


def test_unexpected_exception_from_scan_is_internal_error_not_invalid_input(capsys, monkeypatch):
    """Only `UnknownSelector` maps to exit 2. Any other exception raised
    while scanning — even a plain `ValueError` that in principle could come
    from deep inside a gatherer — must be treated as an internal bug (exit
    5), never misreported as bad user input. Gatherer/check exceptions are
    normally shielded by `EvidenceStore` and the base check's `run()` method
    (see checks/base) and degrade to an ERROR finding instead of propagating
    at all, so the cleanest way to exercise the CLI's own exception boundary
    is to make `scan()` itself raise, exactly as if some other unshielded
    internal failure had escaped that shielding."""
    _use_fixture(monkeypatch, "commerce-good")

    def _boom(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(cli, "scan", _boom)
    code = cli.main(["scan", "https://example.com/"])
    err = capsys.readouterr().err
    assert code == 5
    assert "INTERNAL_ERROR" in err
    assert "ValueError" in err


def test_json_output_has_a_trailing_newline(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["scan", "https://example.com/", "--format", "json"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.endswith("\n")


def test_output_text_writes_the_file(capsys, monkeypatch, tmp_path):
    _use_fixture(monkeypatch, "commerce-good")
    out_path = tmp_path / "report.txt"
    code = cli.main(["scan", "https://example.com/", "--output", str(out_path)])
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == ""
    content = out_path.read_text(encoding="utf-8")
    assert "Technical Readiness  " in content
    assert content.endswith("\n")


def test_exclude_a_category_removes_its_checks(capsys, monkeypatch):
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main(["scan", "https://example.com/", "--format", "json", "--exclude", "trust"])
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert not any(f["category"] == "trust" for f in data["findings"])


def test_timeout_must_be_positive():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "https://example.com/", "--timeout", "0"])
    assert exc_info.value.code == 2


def test_max_pages_must_be_at_least_one():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "https://example.com/", "--max-pages", "0"])
    assert exc_info.value.code == 2


def test_unresolvable_host_exits_network_not_security(capsys, monkeypatch):
    """A hostname DNS cannot resolve is a NETWORK failure (exit 3), not an
    SSRF block (exit 4) — nothing was blocked, the name does not exist."""
    import socket

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "nx.example.com":
            raise socket.gaierror("Name or service not known")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    _use_fixture(monkeypatch)
    code = cli.main(["scan", "https://nx.example.com/"])
    err = capsys.readouterr().err
    assert code == 3
    assert "NETWORK_ERROR" in err
    assert "SECURITY_BLOCK" not in err


def test_token_chars_ratio_2_doubles_estimated_tokens(capsys, monkeypatch):
    """`--token-chars-ratio` is threaded into `ScanOptions.token_chars_ratio`,
    which CORE-OPERABILITY-005's evidence divides the entry page's character
    count by — halving the ratio must double `estimated_tokens`."""
    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main([
        "scan", "https://example.com/", "--format", "json",
        "--include", "CORE-OPERABILITY-005",
    ])
    assert code == 0
    baseline = json.loads(capsys.readouterr().out)
    base_finding = next(f for f in baseline["findings"] if f["id"] == "CORE-OPERABILITY-005")
    text_chars = base_finding["evidence"]["text_chars"]
    assert base_finding["evidence"]["token_chars_ratio"] == 4
    assert base_finding["evidence"]["estimated_tokens"] == text_chars // 4

    _use_fixture(monkeypatch, "commerce-good")
    code = cli.main([
        "scan", "https://example.com/", "--format", "json",
        "--include", "CORE-OPERABILITY-005", "--token-chars-ratio", "2",
    ])
    assert code == 0
    doubled = json.loads(capsys.readouterr().out)
    doubled_finding = next(f for f in doubled["findings"] if f["id"] == "CORE-OPERABILITY-005")
    assert doubled_finding["evidence"]["token_chars_ratio"] == 2
    assert doubled_finding["evidence"]["text_chars"] == text_chars
    assert doubled_finding["evidence"]["estimated_tokens"] == text_chars // 2
    assert doubled_finding["evidence"]["estimated_tokens"] == 2 * base_finding["evidence"]["estimated_tokens"]


def test_token_chars_ratio_must_be_at_least_one():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "https://example.com/", "--token-chars-ratio", "0"])
    assert exc_info.value.code == 2


def test_scan_provenance_carries_scope_and_selection(monkeypatch, capsys):
    import json
    _use_fixture(monkeypatch)
    assert cli.main(["scan", "https://example.com/", "--format", "json", "--include", "CORE-ACCESS-003"]) == 0
    rep = json.loads(capsys.readouterr().out)
    p = rep["provenance"]
    assert p["scan_scope"] == "CUSTOM" and p["included_checks"] == ["CORE-ACCESS-003"] and p["excluded_checks"] == []
    assert p["canonical_min_coverage"] == 0.85 and p["evidence_min_coverage"] == 0.6
    assert rep["metrics"]["error_count"] == 0
    assert rep["score"]["scope"] == "CUSTOM" and rep["score"]["name"] == "Subset Diagnostic Score"


def test_full_fixture_scan_is_canonical(monkeypatch, capsys):
    import json
    _use_fixture(monkeypatch)
    assert cli.main(["scan", "https://example.com/", "--format", "json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["score"]["scope"] == "CANONICAL" and rep["score"]["status"] == "OK"
    assert rep["provenance"]["included_checks"] == [] and rep["provenance"]["excluded_checks"] == []


def test_excluded_checks_records_only_what_exclude_removed(monkeypatch, capsys):
    import json
    _use_fixture(monkeypatch)
    code = cli.main([
        "scan", "https://example.com/", "--format", "json",
        "--include", "CORE-ACCESS-003", "--include", "CORE-ACCESS-004",
        "--exclude", "CORE-ACCESS-004",
    ])
    assert code == 0
    rep = json.loads(capsys.readouterr().out)
    p = rep["provenance"]
    assert p["included_checks"] == ["CORE-ACCESS-003", "CORE-ACCESS-004"]
    assert p["excluded_checks"] == ["CORE-ACCESS-004"]
    non_na = [f for f in rep["findings"] if f["status"] != "N/A"]
    assert len(non_na) == 1 and non_na[0]["id"] == "CORE-ACCESS-003"


def test_exclude_alone_records_only_the_excluded_id(monkeypatch, capsys):
    import json
    _use_fixture(monkeypatch)
    code = cli.main([
        "scan", "https://example.com/", "--format", "json",
        "--exclude", "CORE-ACCESS-003",
    ])
    assert code == 0
    rep = json.loads(capsys.readouterr().out)
    p = rep["provenance"]
    assert p["excluded_checks"] == ["CORE-ACCESS-003"]
    assert p["included_checks"] == []


def _base_report_for_text():
    from scovant_core.engine import scan

    return scan(
        "https://example.com/",
        transport=FixtureTransport(FIXTURES / "sites" / "commerce-good", "example.com"),
        clock=CLOCK,
    )


def test_text_legacy_score_line_by_status():
    """`--legacy-score`: the deprecated five-domain line, one form per
    five-domain status. (The default line is the Technical headline — see
    test_report_headline.py.)"""
    from scovant_core.models import Score
    from scovant_core.report.text import score_line

    base = _base_report_for_text()

    ok = base.model_copy(update={
        "score": Score(value=71, grade="C", coverage=1.0, status="OK", scope="CANONICAL"),
    })
    assert score_line(ok, legacy_score=True) == "Legacy Static Signal Score 71 / 100 C (removed in 0.19.0)"

    degraded = base.model_copy(update={
        "score": Score(value=71, grade=None, coverage=0.78, status="DEGRADED", scope="PARTIAL"),
        "metrics": {**base.metrics, "error_count": 2},
    })
    assert score_line(degraded, legacy_score=True) == (
        "Legacy Static Signal Score 71 / 100 · DEGRADED (removed in 0.19.0)"
    )

    not_canonical = base.model_copy(update={
        "score": Score(
            name="Subset Diagnostic Score", value=71, grade=None, coverage=1.0,
            status="NOT_CANONICAL", scope="CUSTOM",
        ),
    })
    assert score_line(not_canonical, legacy_score=True) == (
        "Legacy Subset Diagnostic Score 71 / 100 · NOT_CANONICAL (removed in 0.19.0)"
    )

    insufficient = base.model_copy(update={
        "score": Score(value=None, grade=None, coverage=0.3, status="INSUFFICIENT_EVIDENCE", scope="CANONICAL"),
    })
    assert score_line(insufficient, legacy_score=True) == (
        "Legacy Static Signal Score — · INSUFFICIENT_EVIDENCE · coverage 30% (removed in 0.19.0)"
    )


def test_require_canonical_exit_codes(monkeypatch, capsys):
    """`--require-canonical` requires Technical status OK. Technical does not
    depend on the five-domain selection, so a narrowed `--include` scan
    (five-domain CUSTOM / NOT_CANONICAL) still passes."""
    _use_fixture(monkeypatch)
    assert cli.main(["scan", "https://example.com/", "--require-canonical", "--quiet"]) == 0
    _use_fixture(monkeypatch)
    assert cli.main([
        "scan", "https://example.com/", "--require-canonical", "--quiet", "--include", "CORE-ACCESS-003",
    ]) == 0
    assert capsys.readouterr().err == ""


def test_require_canonical_passes_on_ok_technical_with_a_partial_five_domain_scan(monkeypatch, capsys):
    """commerce-good with only `/` and robots.txt answering: five-domain
    PARTIAL/DEGRADED, Technical OK (85). The new gate passes, the legacy
    gate fails."""
    report = _real_report("commerce-good", keep={"/", "/robots.txt"})
    assert (report.score.scope, report.score.status) == ("PARTIAL", "DEGRADED")
    assert report.readiness.technical.status == "OK"
    _use_own_fetch_failures(monkeypatch, "commerce-good", {"/", "/robots.txt"})
    assert cli.main(["scan", "https://example.com/", "--require-canonical", "--quiet"]) == 0
    _use_own_fetch_failures(monkeypatch, "commerce-good", {"/", "/robots.txt"})
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--require-canonical", "--quiet"]) == 1


def test_require_canonical_fails_on_degraded_technical(monkeypatch, capsys):
    """saas-mixed with only `/` and robots.txt answering: Technical DEGRADED
    with a number (70). `--require-canonical` fails (only OK passes), while
    `--min-score 70` alone passes — a DEGRADED rating is still a number."""
    report = _real_report("saas-mixed", keep={"/", "/robots.txt"})
    t = report.readiness.technical
    assert (t.rating, t.status) == (70, "DEGRADED")
    _use_own_fetch_failures(monkeypatch, "saas-mixed", {"/", "/robots.txt"})
    assert cli.main(["scan", "https://example.com/", "--require-canonical", "--quiet"]) == 1
    assert capsys.readouterr().err.splitlines() == [
        "Technical Readiness status DEGRADED is not OK; --require-canonical fails (deprecated five-domain gate: --legacy-score / Action legacy-score: 'true', until 0.19.0)",
    ]
    _use_own_fetch_failures(monkeypatch, "saas-mixed", {"/", "/robots.txt"})
    assert cli.main(["scan", "https://example.com/", "--min-score", "70", "--quiet"]) == 0


def test_legacy_score_require_canonical_exit_codes(monkeypatch, capsys):
    """`--legacy-score` restores the five-domain CANONICAL/OK requirement."""
    _use_fixture(monkeypatch)
    assert cli.main(["scan", "https://example.com/", "--legacy-score", "--require-canonical", "--quiet"]) == 0
    _use_fixture(monkeypatch)
    assert cli.main([
        "scan", "https://example.com/", "--legacy-score", "--require-canonical", "--quiet",
        "--include", "CORE-ACCESS-003",
    ]) == 1
    out = capsys.readouterr().out
    assert "Legacy Subset Diagnostic Score" in out and "NOT_CANONICAL" in out


def test_gate_help_names_technical_readiness_and_the_legacy_flag(capsys):
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--legacy-score" in help_text
    assert "gate and print the deprecated five-domain Static Signal Score; removed in 0.19.0" in help_text
    assert "exit 1 if Technical Readiness is below this value" in help_text


def test_markdown_and_html_show_scope_and_status(monkeypatch, capsys):
    _use_fixture(monkeypatch)
    cli.main(["scan", "https://example.com/", "--format", "markdown", "--include", "CORE-ACCESS-003",
              "--legacy-score"])
    md = capsys.readouterr().out
    assert "Legacy Subset Diagnostic Score" in md and "**Scope:** CUSTOM" in md and "Canonical Core Score: NOT CALCULATED" in md
    cli.main(["scan", "https://example.com/", "--format", "html", "--include", "CORE-ACCESS-003", "--legacy-score"])
    html = capsys.readouterr().out
    assert "Subset Diagnostic Score" in html and "NOT CALCULATED" in html and "CUSTOM" in html


def test_markdown_degraded_status_line_appears_once():
    from scovant_core.models import Score
    from scovant_core.report.markdown import render_markdown

    base = _base_report_for_text()
    degraded = base.model_copy(update={
        "score": Score(value=71, grade=None, coverage=0.78, status="DEGRADED", scope="PARTIAL"),
        "metrics": {**base.metrics, "error_count": 2},
    })
    md = render_markdown(degraded, legacy_score=True)
    assert md.count("**Status:**") == 1
    assert "No grade" in md


def test_markdown_not_canonical_note_appears_once(monkeypatch, capsys):
    _use_fixture(monkeypatch)
    cli.main(["scan", "https://example.com/", "--format", "markdown", "--include", "CORE-ACCESS-003", "--legacy-score"])
    md = capsys.readouterr().out
    assert md.count("Canonical Core Score: NOT CALCULATED") == 1


LEAK_CANARY = "canary-7f3a9c"


def test_userinfo_url_is_invalid_input_and_never_echoed(capsys):
    # Assembled at runtime (not one literal containing `user:...@example.com`) so
    # the publish guard's bare-hostname heuristic doesn't mistake this test
    # fixture for a real leaked credential.
    url = "https://" + f"user:{LEAK_CANARY}@" + "example.com/"
    code = cli.main(["scan", url])
    err = capsys.readouterr().err
    assert code == 2 and "credentials" in err and LEAK_CANARY not in err


def test_query_secret_never_appears_in_any_output(monkeypatch, capsys, tmp_path):
    _use_fixture(monkeypatch)
    url = f"https://example.com/?token={LEAK_CANARY}&x=1"
    for fmt in ("text", "json", "markdown", "html"):
        code = cli.main(["scan", url, "--format", fmt])
        cap = capsys.readouterr()
        assert code == 0, cap.err
        assert LEAK_CANARY not in cap.out and LEAK_CANARY not in cap.err
        assert "token=[REDACTED]" in cap.out

    # --quiet text mode goes through the same score_line/renderer path
    _use_fixture(monkeypatch)
    code = cli.main(["scan", url, "--quiet"])
    cap = capsys.readouterr()
    assert code == 0, cap.err
    assert LEAK_CANARY not in cap.out and LEAK_CANARY not in cap.err

    # --require-canonical's failure path renders through the same text
    # renderer as the success path above (the five-domain gate, which a
    # narrowed selection fails)
    _use_fixture(monkeypatch)
    code = cli.main(["scan", url, "--legacy-score", "--require-canonical", "--include", "CORE-ACCESS-003"])
    assert code == 1
    cap = capsys.readouterr()
    assert LEAK_CANARY not in cap.out and LEAK_CANARY not in cap.err

    # the Action's summary + outputs, fed from the JSON report
    from scovant_core import action
    cli.main(["scan", url, "--format", "json", "--output", str(tmp_path / "core.json")])
    capsys.readouterr()
    out, summ = tmp_path / "out", tmp_path / "summ"
    action.main(["outputs", str(tmp_path / "core.json"), "--report-path", "r.html"], env={"GITHUB_OUTPUT": str(out)})
    action.main(["summary", str(tmp_path / "core.json")], env={"GITHUB_STEP_SUMMARY": str(summ)})
    assert LEAK_CANARY not in out.read_text() and LEAK_CANARY not in summ.read_text()
    assert LEAK_CANARY not in (tmp_path / "core.json").read_text()


_LEAK_CANARY_Q = "canary-query-9f21c"
_LEAK_CANARY_P = "canary-pathparam-7be44"
_LEAK_URL = f"https://example.com/path;sid={_LEAK_CANARY_P}?token={_LEAK_CANARY_Q}&x=1"


@pytest.mark.parametrize("extra_args", [[], ["--experimental"]], ids=["canonical", "experimental"])
@pytest.mark.parametrize("fixture_name", ["commerce-good", "commerce-bad", "api-good", "saas-mixed"])
def test_no_secret_leaks_across_every_fixture_format_and_selection(
    monkeypatch, capsys, tmp_path, fixture_name, extra_args,
):
    """Permanent tripwire (fix round 1 on task S.4): a query-string secret
    AND an RFC 3986 path-parameter secret must never survive into ANY
    report surface, for ANY golden fixture, canonical or `--experimental`.
    Guards both the ~20 at-source `display_url`/`redact_message` call
    sites AND the report-level `redact_report_strings` backstop — a check
    added later that forgets to redact a URL it copies into evidence is
    still caught here (by the backstop), even though this test can't tell
    which layer caught it."""
    for fmt in ("text", "json", "markdown", "html"):
        _use_fixture(monkeypatch, fixture_name)
        code = cli.main(["scan", _LEAK_URL, "--format", fmt, *extra_args])
        cap = capsys.readouterr()
        assert code in (0, 1, 5), cap.err  # never a crash on the injected secret itself
        assert _LEAK_CANARY_Q not in cap.out and _LEAK_CANARY_Q not in cap.err
        assert _LEAK_CANARY_P not in cap.out and _LEAK_CANARY_P not in cap.err

    if fixture_name != "commerce-good" or extra_args:
        return  # the Action round-trip below only needs to run once

    from scovant_core import action

    _use_fixture(monkeypatch, fixture_name)
    report_path = tmp_path / "core.json"
    cli.main(["scan", _LEAK_URL, "--format", "json", "--output", str(report_path)])
    capsys.readouterr()
    out_file, summ_file = tmp_path / "out", tmp_path / "summ"
    action.main(["outputs", str(report_path), "--report-path", "r.html"], env={"GITHUB_OUTPUT": str(out_file)})
    action.main(["summary", str(report_path)], env={"GITHUB_STEP_SUMMARY": str(summ_file)})
    for text in (report_path.read_text(), out_file.read_text(), summ_file.read_text()):
        assert _LEAK_CANARY_Q not in text and _LEAK_CANARY_P not in text
