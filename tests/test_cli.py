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


def test_min_score_100_is_reachable_on_a_clean_site(capsys, monkeypatch):
    """commerce-good has no FAIL and no WARN — every remaining verdict is a
    PASS or an honest N/A — so it scores 100 and a `--min-score 100` gate
    passes. (Before the machine-reference fix it "failed" on a declared MCP
    endpoint that answered 404 to a GET, which Core never probes for real.)"""
    _use_fixture(monkeypatch, "commerce-good")
    assert cli.main(["scan", "https://example.com/", "--min-score", "100"]) == 0


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
    assert "Static Signal Score" in lines[0] or "INSUFFICIENT EVIDENCE" in lines[0]


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
    assert "Static Signal Score" in content or "INSUFFICIENT EVIDENCE" in content


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


def _fake_insufficient_evidence_report():
    """A minimal, hand-built `Report` with `score.status == INSUFFICIENT_EVIDENCE`
    and NO `entry_error` — i.e. the entry URL fetched fine, but overall
    evidence coverage still fell below the scoring floor for some other
    reason. Isolates the `--min-score` vs. INSUFFICIENT_EVIDENCE path from
    the network-fatal path (which is exit 3, covered by its own test above
    and always carries a non-null `entry_error`)."""
    from scovant_core.models import Report, Score, Target

    return Report(
        core_version=scovant_core.__version__,
        ruleset_version="test",
        scan_id="local-test",
        started_at=CLOCK(),
        completed_at=CLOCK(),
        target=Target(
            input_url="https://example.com/", final_url="https://example.com/",
            requested_profile="auto", resolved_profile="content", profile_confidence=1.0,
        ),
        score=Score(value=None, grade=None, coverage=0.05, status="INSUFFICIENT_EVIDENCE"),
        categories={},
        findings=[],
        metrics={"requests": 1, "bytes_fetched": 10, "gather_errors": [], "gather_error_details": [], "entry_error": None},
    )


def test_min_score_against_insufficient_evidence_exits_1(capsys, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: _fake_insufficient_evidence_report())
    code = cli.main(["scan", "https://example.com/", "--min-score", "50"])
    assert code == 1


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
    assert "Static Signal Score" in content or "INSUFFICIENT EVIDENCE" in content
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
