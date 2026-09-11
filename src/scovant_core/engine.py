"""The scan entry point: wires evidence gathering, profile resolution, check
execution and scoring into one deterministic `Report`. `clock` and `scan_id`
are injectable so tests can pin timestamps/ids without patching globals."""
from __future__ import annotations

import platform
import secrets
import sys
from datetime import UTC, datetime
from urllib.parse import urlsplit

import scovant_core
from scovant_core import checks  # noqa: F401 — importing this populates registry.CHECKS
from scovant_core.checks.registry import CHECKS, RULESET_VERSION, ruleset_digest
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers import _register  # noqa: F401 — registers evidence.GATHERERS
from scovant_core.models import Report, Target
from scovant_core.profiles import apply_profile
from scovant_core.scoring import score_results
from scovant_core.security.client import SecureClient
from scovant_core.security.policy import CORE_USER_AGENT, SecurityPolicy

__all__ = ["NOT_TESTED", "UnknownSelector", "scan", "user_agent_for", "validate_selectors"]


class UnknownSelector(ValueError):
    """Raised by `validate_selectors` when an `include`/`exclude` token
    matches no check id or category. Public (not a bare `ValueError`) so a
    caller — the CLI — can map exactly this failure to its own "bad input"
    exit code without also catching an unrelated `ValueError` raised deeper
    inside a gatherer/check and misreporting a real bug as bad input."""

# What Scovant Core deliberately does NOT measure — static/declared evidence
# only, never real agent traffic. Copied verbatim into every Report so the
# text/JSON renderers never have to hand-maintain a second copy.
NOT_TESTED = [
    "Observed WAF access",
    "Real agent tasks",
    "MCP tool execution",
    "WebMCP state parity",
    "Multi-model reliability",
    "Regression stability",
]
# Alias kept for existing importers/tests — the constant itself now lives in
# `security.policy` (as `CORE_USER_AGENT`) so gatherers can import it without
# reaching into `engine`, which would be a circular import.
BASE_USER_AGENT = CORE_USER_AGENT


def user_agent_for(options: ScanOptions) -> str:
    if options.user_agent_suffix:
        return f"{BASE_USER_AGENT} {options.user_agent_suffix}".strip()
    return BASE_USER_AGENT


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_selectors(options: ScanOptions) -> None:
    """`include`/`exclude` accept a check id (case-insensitive) or a
    category value (case-insensitive) — nothing else. A typo'd or renamed
    token must never silently select zero/all checks; it's a hard error
    (`UnknownSelector`) the CLI maps to exit code 2. Public so a caller can
    validate selectors up front, before dialing any network I/O."""
    valid_ids = {c.id for c in CHECKS}
    valid_categories = {c.category.value for c in CHECKS}
    for token in (*options.include, *options.exclude):
        if token.upper() not in valid_ids and token.lower() not in valid_categories:
            raise UnknownSelector(f"unknown check or category: {token}")


def _selected(options: ScanOptions):
    def match(check, sel: tuple[str, ...]) -> bool:
        return any(s.upper() == check.id or s.lower() == check.category.value for s in sel)

    out = [c for c in CHECKS if not options.include or match(c, options.include)]
    return [c for c in out if not (options.exclude and match(c, options.exclude))]


def scan(
    url: str,
    options: ScanOptions | None = None,
    *,
    transport=None,
    clock=None,
    scan_id: str | None = None,
) -> Report:
    """Run every selected check against `url` and return a `Report`.

    `transport` is an `httpx.BaseTransport` (tests pass `FixtureTransport` or
    `httpx.MockTransport`; production leaves it `None` so `httpx.Client`
    dials the real network through the SSRF-guarded `SecureClient`).
    """
    options = options or ScanOptions()
    validate_selectors(options)
    clock = clock or _now
    started = clock()
    ctx = ScanContext(url, options)
    # The address block is lifted ONLY for the entry URL's own host — never
    # for a redirect hop or any link the scan discovers on another host (see
    # `SecurityPolicy.private_hosts` and docs/security.md § Private-network
    # targets (opt-in)).
    entry_host = (urlsplit(url).hostname or "").lower()
    policy = SecurityPolicy(
        total_budget_seconds=options.timeout,
        allow_private_networks=options.allow_private_networks,
        private_hosts=frozenset({entry_host}) if options.allow_private_networks else frozenset(),
    )
    client = SecureClient(policy, user_agent_for(options), transport=transport)
    try:
        store = EvidenceStore(client, ctx)
        store.try_get("http")
        apply_profile(ctx, store)
        results = sorted((c.run(store, ctx) for c in _selected(options)), key=lambda r: r.id)
    finally:
        client.close()
    score, cats = score_results(results, include_experimental=options.experimental)
    gather_error_names = sorted(store.errors)
    gather_error_details = [
        {"name": name, "kind": store.errors[name].kind, "message": store.errors[name].message}
        for name in gather_error_names
    ]
    # The entry-URL fetch outcome, independent of which checks were selected
    # (the "http" evidence is always gathered — see `store.try_get("http")`
    # above — regardless of `include`/`exclude`). A caller (the CLI) needs
    # this to classify a security/network-fatal scan without depending on
    # whether CORE-ACCESS-001 itself happened to run.
    http_evidence = store.get("http")
    entry_error = (
        {"kind": http_evidence["error"]["kind"], "message": http_evidence["error"]["message"]}
        if http_evidence.get("error")
        else None
    )
    return Report(
        core_version=scovant_core.__version__,
        ruleset_version=RULESET_VERSION,
        scan_id=scan_id or f"local-{secrets.token_hex(8)}",
        started_at=started,
        completed_at=clock(),
        target=Target(
            input_url=url,
            # An entry fetch that failed resolved NO final URL. `ctx.final_url`
            # is seeded with the input URL in that case so the gatherers have a
            # base to build origins from, but reporting it as the "final URL"
            # would claim we reached a page we never reached.
            final_url=None if entry_error else ctx.final_url,
            requested_profile=options.profile,
            resolved_profile=ctx.resolved_profile,
            profile_confidence=ctx.profile_confidence,
        ),
        score=score,
        categories=cats,
        findings=results,
        metrics={
            "requests": len(client.requests),
            "bytes_fetched": sum(r["bytes"] for r in client.requests),
            "gather_errors": gather_error_names,
            "gather_error_details": gather_error_details,
            "entry_error": entry_error,
        },
        not_tested=list(NOT_TESTED),
        provenance={
            "core_version": scovant_core.__version__,
            "ruleset_version": RULESET_VERSION,
            "ruleset_digest": ruleset_digest(),
            "python": sys.version.split()[0],
            "platform": platform.system(),
            "user_agent": user_agent_for(options),
            "timeout": options.timeout,
            "max_pages": options.max_pages,
            "network_mode": "live" if transport is None else "fixture",
            "experimental": options.experimental,
            "allow_private_networks": options.allow_private_networks,
        },
    )
