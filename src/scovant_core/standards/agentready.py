"""AgentReady v1.0 (August 2026, MIT) — https://agentready.org/ ; spec:
https://github.com/agentready-org/standard/blob/main/spec/spec.md

Requirements verbatim (id, title, tier). MAPPING has exactly one entry per
requirement: which Core checks measure it and how faithfully. `EXACT` —
the check's evidence IS the requirement's evidence; `PARTIAL` — narrower,
the gap is in `notes`; `SCOVANT_SUPERSET` — Core checks strictly more;
`AGENTREADY_ONLY` — Core does not measure it; `NOT_APPLICABLE` — not a
website signal a passive scanner can read.
"""
from __future__ import annotations

from collections.abc import Mapping as _StrMapping
from dataclasses import dataclass

from scovant_core.models import CheckResult

AGENTREADY_VERSION = "1.0"
AGENTREADY_URL = "https://agentready.org/"
TIERS: tuple[str, ...] = ("MUST", "SHOULD", "MAY")
RELATIONSHIPS: tuple[str, ...] = ("EXACT", "PARTIAL", "SCOVANT_SUPERSET", "AGENTREADY_ONLY", "NOT_APPLICABLE")


@dataclass(frozen=True)
class Requirement:
    id: str
    title: str
    tier: str


@dataclass(frozen=True)
class Mapping:
    requirement_id: str
    core_checks: tuple[str, ...]
    relationship: str
    notes: str


REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement("AR-FIND-01", "Block no agent/crawler access", "MUST"),
    Requirement("AR-FIND-02", "Publish answers on canonical docs", "SHOULD"),
    Requirement("AR-FIND-03", "List pages in sitemap.xml", "SHOULD"),
    Requirement("AR-READ-01", "Answer in initial HTML", "MUST"),
    Requirement("AR-READ-02", "Accurate HTTP status codes", "MUST"),
    Requirement("AR-READ-03", "Homepage as raw HTML + links", "SHOULD"),
    Requirement("AR-READ-04", "Docs answer user tasks", "SHOULD"),
    Requirement("AR-READ-05", "Fenced, language-tagged code", "SHOULD"),
    Requirement("AR-READ-06", "Link discovery files from content", "SHOULD"),
    Requirement("AR-READ-07", "Ship llms.txt", "SHOULD"),
    Requirement("AR-READ-08", "JSON-LD on key pages", "SHOULD"),
    Requirement("AR-READ-09", "Markdown mirror via Link header", "MAY"),
    Requirement("AR-ACT-01", "Agent-completable auth", "SHOULD"),
    Requirement("AR-ACT-02", "API described in OpenAPI", "SHOULD"),
    Requirement("AR-ACT-03", "MCP server at /mcp", "SHOULD"),
    Requirement("AR-ACT-04", "MCP server card", "MAY"),
    Requirement("AR-ACT-05", "MCP Apps UI view", "MAY"),
    Requirement("AR-ACT-06", "SDKs and CLI", "SHOULD"),
)

MAPPING: tuple[Mapping, ...] = (
    Mapping("AR-FIND-01", ("CORE-ACCESS-002", "CORE-ACCESS-003", "CORE-ACCESS-008"), "PARTIAL",
            "robots.txt syntax, AI search crawler policy and indexability; network-layer blocking is observed only by Scovant Cloud."),
    Mapping("AR-FIND-02", (), "AGENTREADY_ONLY", "Whether canonical docs answer questions is a content judgement Core does not make."),
    Mapping("AR-FIND-03", ("CORE-ACCESS-005", "CORE-ACCESS-006"), "SCOVANT_SUPERSET", "Sitemap presence and robots.txt reference, plus freshness."),
    Mapping("AR-READ-01", ("CORE-OPERABILITY-001",), "EXACT", "Server-rendered core content in the initial HTML."),
    Mapping("AR-READ-02", ("CORE-OPERABILITY-004", "CORE-OPERABILITY-008", "CORE-OPERABILITY-009"), "EXACT",
            "Real 404 for missing paths (CORE-OPERABILITY-008), 429 + Retry-After when throttling (-009), and no broken machine endpoints (-004) — the requirement's three clauses are each measured."),
    Mapping("AR-READ-03", ("CORE-OPERABILITY-001", "CORE-TRUST-001", "CORE-TRUST-007"), "PARTIAL", "Raw HTML plus discoverable contact and pricing links; docs/product link coverage is not measured."),
    Mapping("AR-READ-04", (), "AGENTREADY_ONLY", "Docs task coverage is a content judgement Core does not make."),
    Mapping("AR-READ-05", (), "AGENTREADY_ONLY", "Core does not parse code blocks."),
    Mapping("AR-READ-06", ("CORE-OPERABILITY-007", "CORE-INTERFACE-009"), "PARTIAL", "Machine reference integrity and agent discovery surfaces (both experimental); footer/metadata link placement is not measured."),
    Mapping("AR-READ-07", ("CORE-ACCESS-009",), "SCOVANT_SUPERSET", "Presence, well-formedness and link integrity of llms.txt."),
    Mapping("AR-READ-08", ("CORE-MACHINE-001", "CORE-MACHINE-002", "CORE-MACHINE-003"), "SCOVANT_SUPERSET", "JSON-LD parseability plus Organization and WebSite/WebPage entities on sampled pages."),
    Mapping("AR-READ-09", (), "AGENTREADY_ONLY", "Markdown mirrors via Link header are measured by Scovant Cloud's content-negotiation probe, not by Core."),
    Mapping("AR-ACT-01", ("CORE-INTERFACE-006", "CORE-INTERFACE-007"), "PARTIAL", "OAuth authorization-server and protected-resource metadata presence; the auth flow itself is verified only by Scovant Cloud."),
    Mapping("AR-ACT-02", ("CORE-INTERFACE-005",), "EXACT", "OpenAPI discovery at conventional paths or linked from the entry page."),
    Mapping("AR-ACT-03", ("CORE-INTERFACE-001", "CORE-INTERFACE-002"), "PARTIAL", "MCP discovery file and declaration quality; the /mcp handshake is performed only by Scovant Cloud."),
    Mapping("AR-ACT-04", ("CORE-INTERFACE-009",), "PARTIAL", "MCP server cards are one of the agent discovery surfaces (experimental)."),
    Mapping("AR-ACT-05", (), "NOT_APPLICABLE", "An MCP Apps UI view is not a website signal a passive scanner can read."),
    Mapping("AR-ACT-06", (), "AGENTREADY_ONLY", "SDK and CLI availability is not a website signal Core measures."),
)

_BY_ID = {m.requirement_id: m for m in MAPPING}
_TIER = {r.id: r.tier for r in REQUIREMENTS}


def checks_for(ar_id: str) -> tuple[str, ...]:
    return _BY_ID[ar_id].core_checks


def standards_for(check_id: str) -> tuple[str, ...]:
    return tuple(m.requirement_id for m in MAPPING if check_id in m.core_checks)


def mapping_summary() -> dict:
    rel = {k: sum(1 for m in MAPPING if m.relationship == k) for k in RELATIONSHIPS}
    return {
        "version": AGENTREADY_VERSION, "url": AGENTREADY_URL, "requirements": len(REQUIREMENTS),
        "with_checks": sum(1 for m in MAPPING if m.core_checks),
        "exact": rel["EXACT"], "partial": rel["PARTIAL"], "superset": rel["SCOVANT_SUPERSET"],
        "agentready_only": rel["AGENTREADY_ONLY"], "not_applicable": rel["NOT_APPLICABLE"],
    }


_EVALUATED_STR = ("PASS", "WARN", "FAIL")
_WORST_STR = {"FAIL": 3, "WARN": 2, "PASS": 1}


def agentready_coverage_from_statuses(statuses: _StrMapping[str, str]) -> dict:
    """Same reduction as `agentready_coverage`, but over raw status strings
    (`PASS|WARN|FAIL|N/A|ERROR`) keyed by check id — the shape
    `app.core_rescan.runner.RescanResult.server["check_statuses"]` carries,
    for callers (the internal corpus-sample script) that never build
    `CheckResult` objects."""
    requirements: dict[str, str] = {}
    for m in MAPPING:
        evaluated = [statuses[c] for c in m.core_checks if c in statuses and statuses[c] in _EVALUATED_STR]
        if not evaluated:
            requirements[m.requirement_id] = "not_measured"
        else:
            requirements[m.requirement_id] = max(evaluated, key=lambda s: _WORST_STR[s]).lower()
    by_tier: dict[str, dict[str, int]] = {}
    for r in REQUIREMENTS:
        t = by_tier.setdefault(r.tier, {"requirements": 0, "measured": 0, "pass": 0, "warn": 0, "fail": 0})
        t["requirements"] += 1
        st = requirements[r.id]
        if st != "not_measured":
            t["measured"] += 1
            t[st] += 1
    return {"version": AGENTREADY_VERSION, "by_tier": by_tier, "requirements": requirements}


def agentready_coverage(findings: list[CheckResult]) -> dict:
    """Descriptive coverage (never scored): per requirement pass|warn|fail|
    not_measured (worst evaluated status of its mapped checks; all N/A or
    ERROR, or no mapped checks → not_measured), plus per-tier counts."""
    return agentready_coverage_from_statuses({f.id: f.status.value for f in findings})
