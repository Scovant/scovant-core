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
from scovant_core.analysis.ai_policy import classify_policy
from scovant_core.analysis.protocol_adoption import protocol_adoption
from scovant_core.checks.registry import CHECKS, RULESET_VERSION, ruleset_digest
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers import _register  # noqa: F401 — registers evidence.GATHERERS
from scovant_core.models import CheckStatus, Report, Target
from scovant_core.profiles import PROFILE_DETECTOR_VERSION, apply_profile
from scovant_core.provenance import environment_fingerprint
from scovant_core.scoring import CANONICAL_MIN_COVERAGE, EVIDENCE_MIN_COVERAGE, score_results
from scovant_core.security.client import SecureClient
from scovant_core.security.policy import CORE_USER_AGENT, SecurityPolicy
from scovant_core.security.url_safety import display_url, redact_message, redact_report_strings

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


def _match(check, sel: tuple[str, ...]) -> bool:
    return any(s.upper() == check.id or s.lower() == check.category.value for s in sel)


def _include_filtered(options: ScanOptions):
    """Checks surviving the `--include` filter only (before `--exclude` is
    applied) — the ONE pass both `_selected` and the provenance's
    `included_checks`/`excluded_checks` derive from, so they can never
    diverge."""
    return [c for c in CHECKS if not options.include or _match(c, options.include)]


def _selected(options: ScanOptions):
    return [c for c in _include_filtered(options) if not (options.exclude and _match(c, options.exclude))]


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
    error_count = sum(1 for r in results if r.status == CheckStatus.ERROR)
    selection_is_custom = bool(options.include or options.exclude or options.experimental)
    score, cats = score_results(results, include_experimental=options.experimental,
                                selection_is_custom=selection_is_custom, error_count=error_count)
    # `included_checks` is the resolved post-`--include` selection (before
    # `--exclude` is applied); `excluded_checks` is exactly what `--exclude`
    # removed FROM THAT selection — never `all checks minus selected`, which
    # would falsely list every check `--include` never chose in the first
    # place as "excluded" (e.g. `--include A,B --exclude B` must report only
    # `[B]`, not the other 44 checks `--include` was never asked to run).
    include_filtered = _include_filtered(options)
    included_ids = sorted(c.id for c in include_filtered)
    selected_ids = sorted(c.id for c in _selected(options))
    excluded_ids = sorted(set(included_ids) - set(selected_ids))
    gather_error_names = sorted(store.errors)
    gather_error_details = [
        {
            "name": name,
            "kind": store.errors[name].kind,
            "message": redact_message(store.errors[name].message, url),
        }
        for name in gather_error_names
    ]
    # The entry-URL fetch outcome, independent of which checks were selected
    # (the "http" evidence is always gathered — see `store.try_get("http")`
    # above — regardless of `include`/`exclude`). A caller (the CLI) needs
    # this to classify a security/network-fatal scan without depending on
    # whether CORE-ACCESS-001 itself happened to run.
    http_evidence = store.get("http")
    # `gathered`, never `get`/`try_get`: this metric must never trigger a
    # NEW robots.txt fetch on its own. A narrowed `--include`/`--exclude`
    # selection that never needed robots.txt evidence means the measurement
    # this metric describes was genuinely never made — reporting every
    # dimension as "undeclared" in that case would claim a fetch that never
    # happened (see docs/methodology.md's "None never 0" discipline).
    robots_evidence = store.gathered("robots_txt")
    ai_crawler_policy = (
        classify_policy(robots_evidence["text"] if robots_evidence.get("text") else None, f"{ctx.origin}/")
        if robots_evidence is not None
        else None
    )
    entry_error = (
        {
            "kind": http_evidence["error"]["kind"],
            "message": redact_message(http_evidence["error"]["message"], url),
        }
        if http_evidence.get("error")
        else None
    )
    dependencies, environment_digest = environment_fingerprint()
    report = Report(
        core_version=scovant_core.__version__,
        ruleset_version=RULESET_VERSION,
        scan_id=scan_id or f"local-{secrets.token_hex(8)}",
        started_at=started,
        completed_at=clock(),
        target=Target(
            input_url=display_url(url),
            # An entry fetch that failed resolved NO final URL. `ctx.final_url`
            # is seeded with the input URL in that case so the gatherers have a
            # base to build origins from, but reporting it as the "final URL"
            # would claim we reached a page we never reached.
            final_url=None if entry_error else display_url(ctx.final_url),
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
            "error_count": error_count,
            "ai_crawler_policy": ai_crawler_policy,
            "protocol_adoption": protocol_adoption(results),
        },
        not_tested=list(NOT_TESTED),
        provenance={
            "core_version": scovant_core.__version__,
            "profile_detector_version": PROFILE_DETECTOR_VERSION,
            "ruleset_version": RULESET_VERSION,
            "ruleset_digest": ruleset_digest(),
            "python": sys.version.split()[0],
            "platform": platform.system(),
            "user_agent": user_agent_for(options),
            "timeout": options.timeout,
            "max_pages": options.max_pages,
            "network_mode": "pinned" if transport is None else "fixture",
            "experimental": options.experimental,
            "allow_private_networks": options.allow_private_networks,
            "scan_scope": score.scope,
            "included_checks": included_ids if options.include else [],
            "excluded_checks": excluded_ids if options.exclude else [],
            "error_count": error_count,
            "evidence_min_coverage": EVIDENCE_MIN_COVERAGE,
            "canonical_min_coverage": CANONICAL_MIN_COVERAGE,
            "dependencies": dependencies,
            "environment_digest": environment_digest,
        },
    )
    # Structural backstop, not a substitute for the at-source redactions
    # above/in the individual checks: a check that copies a URL into its
    # evidence without routing it through `display_url` would otherwise
    # leak the raw secret query/path-param/fragment. This walks the
    # FINISHED report once and scrubs any raw fragment of `url` that
    # slipped through anyway.
    return Report.model_validate(redact_report_strings(report.model_dump(), url))
