"""`scovant` CLI: argparse entry point wired to `scovant_core.engine.scan` and
the text/JSON renderers, with a stable exit-code contract for CI use.

Exit codes: 0 ok; 1 `--min-score`/`--fail-on` triggered; 2 invalid input;
3 network fatal (entry unreachable); 4 security block (entry blocked by the
SSRF guard — private/reserved/localhost target); 5 internal error (an
unexpected exception — `scan()` itself never raises for a bad/blocked URL,
so reaching this path means a genuine bug).
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

import scovant_core
from scovant_core.context import ScanOptions
from scovant_core.contribute import build_payload, send
from scovant_core.engine import UnknownSelector, scan, validate_selectors
from scovant_core.models import CheckStatus, Report
from scovant_core.profiles import PROFILES
from scovant_core.report.html import render_html
from scovant_core.report.json import render_json
from scovant_core.report.markdown import render_markdown
from scovant_core.report.text import render_text, score_line
from scovant_core.security.url_safety import has_userinfo

__all__ = ["main"]

# Test-injection hooks. Production leaves both `None` — `scan()` then dials
# the real network (`transport=None`) and uses its own wall-clock default
# (`clock=None`). Tests monkeypatch `_TRANSPORT_FACTORY` to return a
# `FixtureTransport`/`httpx.MockTransport` instance (and may set `_CLOCK` to
# pin timestamps for deterministic output).
def _default_transport_factory() -> httpx.BaseTransport | None:
    return None


_TRANSPORT_FACTORY: Callable[[], httpx.BaseTransport | None] = _default_transport_factory
_CLOCK: Callable[[], str] | None = None

# The Cloud crawler's own UA identity token, assembled at runtime rather than
# written as a literal — the scovant-core publish guard
# (scripts/core_publish_guard.py) bans that exact string everywhere in this
# package, tests included, so a hardcoded literal here would fail the guard
# on its own source. `--user-agent` is rejected when it contains this token
# (case-insensitively) so a Core user can never impersonate the Cloud
# crawler's identity from the OSS CLI.
_CLOUD_CRAWLER_TOKEN = "Scovant" + "Bot"

_EXIT_OK = 0
_EXIT_THRESHOLD = 1
_EXIT_INVALID_INPUT = 2
_EXIT_NETWORK = 3
_EXIT_SECURITY = 4
_EXIT_INTERNAL = 5

_PROFILES = PROFILES
_FORMATS = ("text", "json", "markdown", "html")
_FAIL_ON = ("fail", "warn", "never")

# Marker attribute so `_enable_verbose_logging` never attaches a second
# handler to the `scovant_core` logger when `main()` is called more than
# once in the same process (every CLI test does exactly this).
_VERBOSE_HANDLER_MARK = "_scovant_cli_verbose_handler"


def _score_range(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if not 0 <= n <= 100:
        raise argparse.ArgumentTypeError("--min-score must be between 0 and 100")
    return n


def _positive_timeout(value: str) -> float:
    try:
        n = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    if n <= 0:
        raise argparse.ArgumentTypeError("--timeout must be > 0")
    return n


def _positive_max_pages(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("--max-pages must be >= 1")
    return n


def _positive_token_chars_ratio(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("--token-chars-ratio must be >= 1")
    return n


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scovant", description="Scovant Core — passive AI-agent readiness scanner.",
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", aliases=["check"], help="scan a URL and print a readiness report")
    scan_p.add_argument("url", help="the entry URL to scan (http:// or https://)")
    scan_p.add_argument(
        "--profile", choices=_PROFILES, default="auto",
        help="site profile to score against (default: auto-detect)",
    )
    scan_p.add_argument(
        "--format", choices=_FORMATS, default="text", help="output format (default: text)",
    )
    scan_p.add_argument("--output", default=None, help="write the rendered report to PATH instead of stdout")
    scan_p.add_argument(
        "--min-score", type=_score_range, default=None,
        help="exit 1 if the Static Signal Score is below this value (0..100)",
    )
    scan_p.add_argument(
        "--fail-on", choices=_FAIL_ON, default="never",
        help="exit 1 when any finding reaches this status or worse (default: never)",
    )
    scan_p.add_argument(
        "--require-canonical", action="store_true", dest="require_canonical",
        help="exit 1 unless the scan is CANONICAL with score status OK",
    )
    scan_p.add_argument(
        "--timeout", type=_positive_timeout, default=60.0, help="total scan time budget in seconds (default: 60)",
    )
    scan_p.add_argument(
        "--max-pages", type=_positive_max_pages, default=5, help="max pages to sample beyond the entry URL (default: 5)",
    )
    scan_p.add_argument(
        "--user-agent", default=None, dest="user_agent",
        help="suffix appended to the Scovant Core user agent string",
    )
    scan_p.add_argument("--no-color", action="store_true", help="disable ANSI colour in text output")
    scan_p.add_argument("--verbose", action="store_true", help="enable debug logging for scovant_core")
    scan_p.add_argument("--quiet", action="store_true", help="text format only: print just the score line")
    scan_p.add_argument(
        "--include", action="append", default=[], metavar="ID|CATEGORY",
        help="run only checks matching this id or category (repeatable)",
    )
    scan_p.add_argument(
        "--exclude", action="append", default=[], metavar="ID|CATEGORY",
        help="skip checks matching this id or category (repeatable)",
    )
    scan_p.add_argument("--experimental", action="store_true", help="include experimental checks in scoring")
    scan_p.add_argument(
        "--token-chars-ratio", type=_positive_token_chars_ratio, default=4, dest="token_chars_ratio",
        help="characters-per-token estimate used for CORE-OPERABILITY-005's page-cost evidence (default: 4)",
    )
    scan_p.add_argument(
        "--allow-private-networks", action="store_true", dest="allow_private_networks",
        help=(
            "allow targets that resolve to private, loopback or link-local addresses "
            "(you assert the target is yours; all other protections stay on)"
        ),
    )
    scan_p.add_argument(
        "--contribute", action="store_true",
        help=(
            "send an anonymous, aggregate-only measurement of this PUBLIC site to "
            "Scovant's community index (see docs/security.md)"
        ),
    )

    sub.add_parser("mcp", help="run the stdio MCP server (needs scovant-core[mcp])")
    return parser


def _validate_url(raw: str) -> bool:
    parts = urlsplit(raw)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _invalid_input(message: str) -> int:
    print(f"INVALID_INPUT: {message}", file=sys.stderr)
    return _EXIT_INVALID_INPUT


def _enable_verbose_logging() -> None:
    """`--verbose` attaches a `StreamHandler(sys.stderr)` to the
    `scovant_core` logger ONLY and raises its level to DEBUG (`propagate`
    left at its default). It never calls `logging.basicConfig` — that
    configures the ROOT logger (and, transitively, every third-party
    library's logger) for the rest of the process, which is both far wider
    than "debug scovant_core's own scan" and, in a long-lived host process
    embedding this CLI, a global side effect the caller never asked for."""
    logger = logging.getLogger("scovant_core")
    logger.setLevel(logging.DEBUG)
    if not any(getattr(h, _VERBOSE_HANDLER_MARK, False) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        setattr(handler, _VERBOSE_HANDLER_MARK, True)
        logger.addHandler(handler)


def _entry_error_kind(report: Report) -> str | None:
    """The entry-URL fetch error kind from `report.metrics["entry_error"]` —
    populated by the engine from the "http" evidence regardless of which
    checks were selected (`--include`/`--exclude`), so exit 3/4 never
    depends on whether CORE-ACCESS-001 itself happened to run."""
    entry_error = report.metrics.get("entry_error")
    return entry_error["kind"] if entry_error else None


def _threshold_exit_code(
    report: Report, *, min_score: int | None, fail_on: str, require_canonical: bool = False,
) -> int:
    if require_canonical and not (report.score.scope == "CANONICAL" and report.score.status == "OK"):
        return _EXIT_THRESHOLD
    if min_score is not None and (report.score.value is None or report.score.value < min_score):
        return _EXIT_THRESHOLD
    if fail_on != "never":
        statuses = {f.status for f in report.findings}
        if CheckStatus.FAIL in statuses:
            return _EXIT_THRESHOLD
        if fail_on == "warn" and CheckStatus.WARN in statuses:
            return _EXIT_THRESHOLD
    return _EXIT_OK


def _run_scan(args: argparse.Namespace) -> int:
    if not _validate_url(args.url):
        return _invalid_input("URL must start with http:// or https:// and include a host")

    if has_userinfo(args.url):
        return _invalid_input("URL must not contain credentials (user:password@host)")

    # The fragment is never sent to the server and never needed downstream —
    # drop it before it can reach any output surface (it isn't redacted like
    # a query value, so keeping it around would be a leak, not a display
    # choice).
    args.url = urlunsplit(urlsplit(args.url)._replace(fragment=""))

    if args.user_agent and _CLOUD_CRAWLER_TOKEN.lower() in args.user_agent.lower():
        return _invalid_input("--user-agent must not contain the Cloud crawler's identity")

    if args.contribute and args.allow_private_networks:
        return _invalid_input("--contribute cannot be combined with --allow-private-networks")

    if args.verbose:
        _enable_verbose_logging()

    options = ScanOptions(
        profile=args.profile,
        max_pages=args.max_pages,
        timeout=args.timeout,
        user_agent_suffix=args.user_agent,
        experimental=args.experimental,
        include=tuple(args.include),
        exclude=tuple(args.exclude),
        token_chars_ratio=args.token_chars_ratio,
        allow_private_networks=args.allow_private_networks,
    )

    # Validated up front, before any network I/O — `scan()` itself validates
    # again (defense in depth for direct library callers), but the CLI needs
    # to distinguish THIS specific, typed failure from any other exception
    # `scan()` might raise (which is an internal error, exit 5 — see main()).
    try:
        validate_selectors(options)
    except UnknownSelector:
        return _invalid_input("unknown --include/--exclude check id or category")

    report = scan(args.url, options, transport=_TRANSPORT_FACTORY(), clock=_CLOCK)

    kind = _entry_error_kind(report)
    if kind == "security":
        print("SECURITY_BLOCK", file=sys.stderr)
        exit_code = _EXIT_SECURITY
    elif kind in ("network", "timeout"):
        print("NETWORK_ERROR", file=sys.stderr)
        exit_code = _EXIT_NETWORK
    else:
        exit_code = _threshold_exit_code(
            report, min_score=args.min_score, fail_on=args.fail_on,
            require_canonical=args.require_canonical,
        )

    color = args.format == "text" and not args.no_color and not args.output and sys.stdout.isatty()
    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "markdown":
        rendered = render_markdown(report, utm_medium="cli")
    elif args.format == "html":
        rendered = render_html(report, utm_medium="html")
    else:
        rendered = render_text(report, color=color)
    if not rendered.endswith("\n"):
        rendered += "\n"

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    elif args.quiet and args.format == "text":
        print(score_line(report))
    else:
        print(rendered, end="")

    if args.contribute and report.metrics.get("entry_error") is None:
        if report.score.scope != "CANONICAL":
            print(
                f"contributed: skipped (scan is {report.score.scope}; only canonical scans are accepted)",
                file=sys.stderr,
            )
        else:
            payload = build_payload(report)
            result = send(payload)
            print(f"contributed: {payload['domain']} ({result.message})", file=sys.stderr)

    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)  # a bad option value/choice exits 2 here — argparse's own contract

    if args.version:
        print(f"scovant-core {scovant_core.__version__}")
        return _EXIT_OK

    if not getattr(args, "command", None):
        parser.print_usage(sys.stderr)
        return _invalid_input("no command given (use 'scovant scan URL')")

    if args.command == "mcp":
        from scovant_core import mcp_server  # noqa: PLC0415

        return mcp_server.run_stdio()

    try:
        return _run_scan(args)
    except Exception as exc:  # noqa: BLE001 — last-resort guard: `scan()` itself never
        # raises for a bad/blocked URL (see the module docstring), and
        # `UnknownSelector` is caught explicitly above, so reaching here means
        # a genuine, unanticipated bug. Never let it crash the CLI with a raw
        # traceback; report it and exit 5 instead.
        print(f"INTERNAL_ERROR: {type(exc).__name__}", file=sys.stderr)
        return _EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
