"""A curated, public crosswalk between the Core checks and the readiness rules.

Core runs two different things over the same gathered evidence:

- **checks** (`checks.registry.CHECKS`) — diagnostics, each with its own
  verdict, evidence and limitations, carrying no weight in the
  Technical Readiness rating (the deprecated five-domain score still reads them);
- **readiness rules** — the rules the Technical Readiness rating is computed
  from (`scovant_core.rules.RULES`), plus the agent-only rules that need
  Scovant Cloud's agent execution and that Core therefore never evaluates.

This module says, for every check, which readiness rules read the same signal
and how closely. It is curated by hand — a reviewer reads the check's evidence
against the rule's evidence — and pinned complete by `tests/test_crosswalk.py`:
a check or rule added without a row fails that test by name.

Relationships:

- `same_signal` — the rule reads the same evidence and judges it the same way
  (the scope may differ: the check reads the entry page, the rule every page);
- `partial` — the evidence overlaps but the verdicts differ (absence handled
  differently, a narrower or wider set of fields, other thresholds);
- `diagnostic_only` — the matching rule (listed) is diagnostic in the
  Technical manifest: it reports, it does not count towards the rating;
- `no_rule` — no readiness rule reads this signal (every security check).

`python -m scovant_core.docs --crosswalk` writes `docs/crosswalk.md` from
`render_markdown()`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from scovant_core import checks as _checks  # noqa: F401 — importing populates registry.CHECKS
from scovant_core.checks.registry import CHECKS
from scovant_core.models import Category
from scovant_core.r2.technical import MARKER_CODES
from scovant_core.rules import RULES

__all__ = [
    "AGENT_ONLY_RULES",
    "CHECK_ROWS",
    "DIAGNOSTIC_RULES",
    "RULE_ROWS",
    "CheckRow",
    "RuleRow",
    "counts",
    "render_markdown",
]

Relationship = Literal["same_signal", "partial", "diagnostic_only", "no_rule"]
EvaluatedBy = Literal["core", "cloud_execution_only"]

# The readiness rules that need an agent fetch or identity probe only Scovant
# Cloud performs. Names only: Core never evaluates them and never imports the
# host that does. Copied from the host's agent-only set; the host's sync test
# pins the two equal.
AGENT_ONLY_RULES: tuple[str, ...] = (
    "AGENT-EDGE-001",
    "AGENT-EDGE-003",
    "AGENT-ID-001",
    "AGENT-ID-002",
    "AGENT-ID-003",
    "AGENT-ID-005",
    "AI-BOT-POLICY-003",
    "AI-BOT-POLICY-005",
    "BOT_PROTECTION_BLOCKING_AGENTS",
)

# Core rules that are diagnostic markers in the Technical manifest: they
# report a finding but carry no weight in the rating. Derived, never typed.
DIAGNOSTIC_RULES: tuple[str, ...] = tuple(sorted(MARKER_CODES))


@dataclass(frozen=True)
class CheckRow:
    check_id: str
    rules: tuple[str, ...]
    relationship: Relationship
    note: str


@dataclass(frozen=True)
class RuleRow:
    rule: str
    evaluated_by: EvaluatedBy
    # The rule's own maturity; None for the agent-only rules Core never runs.
    maturity: str | None = None


def _row(check_id: str, relationship: Relationship, rules: tuple[str, ...], note: str) -> CheckRow:
    return CheckRow(check_id=check_id, rules=rules, relationship=relationship, note=note)


_SECURITY_NOTE = "Security diagnostic; never scored, outside the readiness rating."

CHECK_ROWS: tuple[CheckRow, ...] = (
    # --- Access --------------------------------------------------------
    _row("CORE-ACCESS-001", "no_rule", (),
         "HTTPS reachability of the entry URL; no readiness rule judges it (a failed fetch leaves rules not measured)."),
    _row("CORE-ACCESS-002", "no_rule", (),
         "robots.txt reachability and syntax only; rules read the parsed per-agent policy, which other checks cover."),
    _row("CORE-ACCESS-003", "partial", ("AI_CRAWLER_BLOCKED",),
         "The check asks if search crawlers are allowed; the rule fires on a root Disallow for GPTBot, ClaudeBot, Google-Extended or PerplexityBot."),
    _row("CORE-ACCESS-004", "diagnostic_only", ("AI-BOT-POLICY-001",),
         "AI-BOT-POLICY-001 (diagnostic) summarises policy by intent; AI_CRAWLER_BLOCKED reads training tokens the other way, as a block."),
    _row("CORE-ACCESS-005", "same_signal", ("SITEMAP_MISSING_OR_INVALID",),
         "Same sitemap probe: missing or unparsable sitemap is a finding in both."),
    _row("CORE-ACCESS-006", "no_rule", (),
         "Sitemap lastmod freshness; the sitemap rule judges presence and validity only."),
    _row("CORE-ACCESS-007", "no_rule", (),
         "Canonical URL integrity; no readiness rule reads the canonical link."),
    _row("CORE-ACCESS-008", "partial", ("BLOCKED_CRAWLABILITY",),
         "Both flag noindex; the rule reads every sampled page, the check the entry page including X-Robots-Tag."),
    _row("CORE-ACCESS-009", "partial", ("LLMS_TXT_MISSING_OR_INVALID",),
         "Same llms.txt document; the check does not penalise absence and checks link status, the rule fires on a missing file."),
    _row("CORE-ACCESS-010", "partial", ("CONTENT-SIGNAL-001", "CONTENT_SIGNALS_ABSENT"),
         "Same Content-Signal parse; the check reports absence as N/A, the rules fire on absence and on malformed lines."),
    _row("CORE-ACCESS-011", "partial", ("LLMS_TXT_MISSING_OR_INVALID",),
         "Same llms.txt document; the check judges usefulness (links, template text), the rule only presence and validity."),
    # --- Interfaces ----------------------------------------------------
    _row("CORE-INTERFACE-001", "partial", ("MCP_ENDPOINT_ABSENT",),
         "Same MCP discovery file and server card; the check reports absence as N/A, the rule fires on it for some site types."),
    _row("CORE-INTERFACE-002", "partial", ("MCP_DISCOVERY_INVALID", "SERVER-CARD-005"),
         "Same declared servers; the check judges name, URL, transport, description; the rules read only the URL and name against a live handshake."),
    _row("CORE-INTERFACE-003", "diagnostic_only", ("WEBMCP-001",),
         "A static WebMCP marker; WEBMCP-001 reports an in-page WebMCP surface and is diagnostic, not rated."),
    _row("CORE-INTERFACE-004", "partial", ("WEBMCP-003",),
         "Both flag WebMCP tools without a schema or description; the check reads static HTML, the rule an in-browser enumeration."),
    _row("CORE-INTERFACE-005", "partial", ("AGENT_INTERFACE_DISCOVERY_ABSENT",),
         "An OpenAPI document is one of the surfaces that satisfies the rule; the rule fires only when none is found."),
    _row("CORE-INTERFACE-006", "partial", ("AGENT_INTERFACE_DISCOVERY_ABSENT",),
         "Authorization-server metadata is one of the surfaces that satisfies the rule; the check also judges its fields."),
    _row("CORE-INTERFACE-007", "partial", ("AGENT_INTERFACE_DISCOVERY_ABSENT", "MCP-AUTH-001"),
         "Protected-resource metadata satisfies the discovery rule; MCP-AUTH-001 needs it where an MCP endpoint answers 401."),
    _row("CORE-INTERFACE-008", "partial", ("UCP_PROFILE_ABSENT", "UCP_PROFILE_INVALID"),
         "Same /.well-known/ucp profile; the rules split absent from invalid and apply only to some site types."),
    _row("CORE-INTERFACE-009", "partial", ("AGENT_INTERFACE_DISCOVERY_ABSENT",),
         "Overlapping surface sets; the rule also counts OpenAPI and OAuth metadata and applies only to some site types."),
    # --- Machine-readable data -----------------------------------------
    _row("CORE-MACHINE-001", "no_rule", (),
         "JSON-LD syntax; rules read the parsed blocks but none judges an unparsable one."),
    _row("CORE-MACHINE-002", "no_rule", (),
         "Organization entity; no readiness rule reads it."),
    _row("CORE-MACHINE-003", "no_rule", (),
         "WebSite/WebPage entity; no readiness rule reads it."),
    _row("CORE-MACHINE-004", "partial", ("MISSING_PRODUCT_SCHEMA",),
         "Both look for a Product entity; the rule fires only on pages that look like product pages, the check also wants identifiers."),
    _row("CORE-MACHINE-005", "partial", ("MISSING_AVAILABILITY", "MISSING_OFFER_DATA", "PRICE_MISSING_INVALID"),
         "Same Offer fields; the check reads the first product page as one verdict, the rules split the fields per page."),
    _row("CORE-MACHINE-006", "no_rule", (),
         "Product identifier count; no readiness rule counts sku/gtin/mpn/brand."),
    _row("CORE-MACHINE-007", "no_rule", (),
         "BreadcrumbList; no readiness rule reads it."),
    _row("CORE-MACHINE-008", "partial", ("MISSING_OG_META_FOR_CITATION",),
         "Overlapping metadata; the rule wants og:title and og:description, the check also title and description tags."),
    _row("CORE-MACHINE-009", "same_signal", ("HEADING_HIERARCHY_POOR",),
         "Same outline test (no H1, several H1, skipped level); the check reads the entry page, the rule every page."),
    _row("CORE-MACHINE-010", "no_rule", (),
         "lang attribute; no readiness rule reads it."),
    _row("CORE-MACHINE-011", "no_rule", (),
         "Image alt coverage; no readiness rule reads it."),
    _row("CORE-MACHINE-012", "partial", ("PRICE_MISMATCH",),
         "Both compare visible and structured price; their visible-price extraction and matching differ."),
    # --- Operability ---------------------------------------------------
    _row("CORE-OPERABILITY-001", "partial", ("JS_ONLY_CRITICAL_CONTENT",),
         "Both read static visible text; the rule also fires on a low share of labelled controls (see OPERABILITY-006) and missing product signals."),
    _row("CORE-OPERABILITY-002", "no_rule", (),
         "Redirect chain length; no readiness rule reads it."),
    _row("CORE-OPERABILITY-003", "no_rule", (),
         "ETag/Last-Modified; no readiness rule reads them."),
    _row("CORE-OPERABILITY-004", "no_rule", (),
         "HTTP status of declared machine references; no readiness rule judges it."),
    _row("CORE-OPERABILITY-005", "partial", ("PAGE_TOKEN_BLOAT",),
         "Both measure page token cost; the check estimates from characters on the entry page, the rule counts tokens per page."),
    _row("CORE-OPERABILITY-006", "partial", ("JS_ONLY_CRITICAL_CONTENT",),
         "The check wants a label on every form control; the rule fires when under 30% of interactive elements are labelled."),
    _row("CORE-OPERABILITY-007", "partial", ("LLMS-SUPPLY-002", "LLMS-SUPPLY-006", "LLMS-SUPPLY-008"),
         "Same reference probe; the rules split dead domains, remote-exec (curl piped to sh) and claimable names in install commands."),
    _row("CORE-OPERABILITY-008", "no_rule", (),
         "Soft-404 behaviour; no readiness rule reads it."),
    _row("CORE-OPERABILITY-009", "no_rule", (),
         "Retry-After on 429; no readiness rule reads it."),
    _row("CORE-OPERABILITY-010", "partial", ("BOT_PROTECTION_BLOCKING_AGENTS",),
         "Both detect challenge pages; the agent-only rule judges Cloud's own agent fetch, the check a challenge served as 200."),
    _row("CORE-OPERABILITY-011", "no_rule", (),
         "Whether machine surfaces are linked from the entry page; no readiness rule reads that linkage."),
    # --- Trust ---------------------------------------------------------
    _row("CORE-TRUST-001", "no_rule", (),
         "Contact or support link; no readiness rule reads it."),
    _row("CORE-TRUST-002", "partial", ("SHIPPING_INFO_UNAVAILABLE",),
         "Both look for a shipping-policy link; the rule also accepts structured shipping data, the check fetches the page."),
    _row("CORE-TRUST-003", "partial", ("MISSING_RETURNS_POLICY",),
         "Both look for a returns-policy link; the check follows it from the entry page and checks it is readable."),
    _row("CORE-TRUST-004", "no_rule", (),
         "Privacy policy link; no readiness rule reads it."),
    _row("CORE-TRUST-005", "no_rule", (),
         "Terms link; no readiness rule reads it."),
    _row("CORE-TRUST-006", "no_rule", (),
         "security.txt presence; no readiness rule reads it."),
    _row("CORE-TRUST-007", "partial", ("PRICE_MISSING_INVALID",),
         "The check's structured-price fallback overlaps the rule; the rule judges Offer prices only, not a pricing page."),
    # --- Security (never scored) ---------------------------------------
    *(_row(f"CORE-SECURITY-{n:03d}", "no_rule", (), _SECURITY_NOTE) for n in range(1, 14)),
    _row("CORE-SECURITY-014", "no_rule", (),
         "Security diagnostic, never scored; shares find_injection_markers with WEBMCP-004 and AGENT-META-001."),
    _row("CORE-SECURITY-015", "no_rule", (), _SECURITY_NOTE),
    _row("CORE-SECURITY-016", "no_rule", (),
         "Security diagnostic, never scored; shares find_injection_markers/find_obfuscation with WEBMCP-004, AGENT-META-001/-008."),
    *(_row(f"CORE-SECURITY-{n:03d}", "no_rule", (), _SECURITY_NOTE) for n in range(17, 19)),
)


RULE_ROWS: tuple[RuleRow, ...] = tuple(
    sorted(
        [RuleRow(rule=r.code, evaluated_by="core", maturity=r.maturity) for r in RULES]
        + [RuleRow(rule=code, evaluated_by="cloud_execution_only") for code in AGENT_ONLY_RULES],
        key=lambda row: row.rule,
    )
)


def counts() -> dict[str, int]:
    """Counts derived from the registries, never typed."""
    security = sum(1 for c in CHECKS if c.category is Category.SECURITY)
    return {
        "checks": len(CHECKS),
        "readiness_checks": len(CHECKS) - security,
        "security_checks": security,
        "rules": len(RULES) + len(AGENT_ONLY_RULES),
        "core_rules": len(RULES),
        "cloud_only_rules": len(AGENT_ONLY_RULES),
    }


_HEADER = "<!-- generated by python -m scovant_core.docs --crosswalk — do not edit -->"


def render_markdown() -> str:
    c = counts()
    rel = {r: sum(1 for row in CHECK_ROWS if row.relationship == r)
           for r in ("same_signal", "partial", "diagnostic_only", "no_rule")}
    lines = [
        _HEADER,
        "",
        "# Checks ↔ readiness rules",
        "",
        (f"{c['checks']} checks ({c['readiness_checks']} readiness, {c['security_checks']} security) · "
         f"{c['rules']} readiness rules ({c['core_rules']} evaluated by Core, "
         f"{c['cloud_only_rules']} need Scovant Cloud's agent execution)."),
        "",
        ("Checks are diagnostics: each reports its own verdict and evidence and carries no weight "
         "in the Technical Readiness rating (the deprecated five-domain score, due to be removed in 0.19.0, "
         "is still computed from checks). "
         "The Technical Readiness rating is computed from the Core-evaluated rules, over the same "
         "gathered evidence. The agent-only rules need an agent fetch that only "
         "Scovant Cloud performs, so Core lists them but never evaluates them. This table says, "
         "for every check, which rules read the same signal and how closely; it is curated and "
         "regenerated by `python -m scovant_core.docs --crosswalk` — do not hand-edit."),
        "",
        "## Relationship legend",
        "",
        "| Relationship | Meaning |",
        "|---|---|",
        "| same_signal | The rule reads the same evidence and judges it the same way (its scope may differ). |",
        "| partial | The evidence overlaps; the verdicts differ (absence, fields or thresholds). |",
        "| diagnostic_only | The matching rule is diagnostic: it reports, it does not count towards the rating. |",
        "| no_rule | No readiness rule reads this signal. |",
        "",
        "Experimental rules are reported but do not count toward the rating.",
        "",
        (f"Tally: {rel['same_signal']} same_signal, {rel['partial']} partial, "
         f"{rel['diagnostic_only']} diagnostic_only, {rel['no_rule']} no_rule."),
        "",
        "## Checks",
        "",
        "| Check | Rules | Relationship | Note |",
        "|---|---|---|---|",
    ]
    for row in sorted(CHECK_ROWS, key=lambda r: r.check_id):
        rules = ", ".join(row.rules) if row.rules else "—"
        lines.append(f"| {row.check_id} | {rules} | {row.relationship} | {row.note} |")
    lines += [
        "",
        "## Readiness rules",
        "",
        "| Rule | Evaluated by | Maturity |",
        "|---|---|---|",
    ]
    for rrow in RULE_ROWS:
        lines.append(f"| {rrow.rule} | {rrow.evaluated_by} | {rrow.maturity or '—'} |")
    return "\n".join(lines) + "\n"
