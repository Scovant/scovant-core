"""Report data model (product-facing contract; see docs/methodology.md)."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "1.1"
SCORE_NAME = "Scovant Core Static Signal Score"
SCORE_SHORT_NAME = "Core Score"
SCORE_SUBSET_NAME = "Subset Diagnostic Score"
SCAN_SCOPES = ("CANONICAL", "CUSTOM", "PARTIAL")
SCORE_STATUSES = ("OK", "DEGRADED", "NOT_CANONICAL", "INSUFFICIENT_EVIDENCE")
# How a check's evidence was obtained — DECLARED (a document/header the site
# published) and PASSIVE_OBSERVED (an unauthenticated observation Core made
# itself) are the only two Core ever emits; ACTIVE_SAFE and
# SYNTHETIC_AUTHORIZED are reserved for a future, explicitly-consented probe
# tier and must never appear on a Core-emitted CheckResult (see
# `test_verification_mode_vocabulary`).
VERIFICATION_MODES = ("DECLARED", "PASSIVE_OBSERVED", "ACTIVE_SAFE", "SYNTHETIC_AUTHORIZED")


class CheckStatus(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NA = "N/A"
    ERROR = "ERROR"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    ACCESS = "access"
    MACHINE = "machine"
    INTERFACES = "interfaces"
    TRUST = "trust"
    OPERABILITY = "operability"
    # Never scored (see scoring.SCORED_CATEGORIES) — passive security/trust
    # signals only, surfaced through `Report.security`, not `Report.score`.
    SECURITY = "security"


CATEGORY_TITLES = {
    Category.ACCESS: "Access & Discovery",
    Category.MACHINE: "Machine Understanding",
    Category.INTERFACES: "Agent Interfaces",
    Category.TRUST: "Trust & Commerce",
    Category.OPERABILITY: "Operability & Efficiency",
    Category.SECURITY: "Agentic Security & Trust",
}


class CheckResult(BaseModel):
    id: str
    title: str
    category: Category
    status: CheckStatus
    severity: Severity
    confidence: Confidence
    weight: int
    summary: str
    evidence: dict = Field(default_factory=dict)
    why_it_matters: str = ""
    limitations: str = ""
    cloud_extension: str = ""
    remediation: str = ""
    experimental: bool = False
    check_version: str = "1.0"
    # SECURITY-category fields only; "" / "PASSIVE_OBSERVED" / [] defaults
    # keep every pre-1.1 check's `result()` call unchanged.
    family_id: str = ""
    verification_mode: str = "PASSIVE_OBSERVED"
    security_domain: str = ""
    fix_owner: str = ""
    security_tags: list[str] = Field(default_factory=list)


class CategoryScore(BaseModel):
    title: str
    score: float | None
    weight: int
    applicable_weight: float
    evaluated_weight: float


class Target(BaseModel):
    input_url: str
    final_url: str | None
    requested_profile: str
    resolved_profile: str
    profile_confidence: float


class Score(BaseModel):
    name: str = SCORE_NAME
    value: int | None
    grade: str | None
    coverage: float
    # OK | DEGRADED | NOT_CANONICAL | INSUFFICIENT_EVIDENCE — see docs/methodology.md
    status: str
    # CANONICAL (full selection, coverage >= 0.85, no ERROR) | CUSTOM
    # (--include/--exclude/--experimental) | PARTIAL (full selection but
    # under-covered or errored). A property of the SELECTION and evidence;
    # `status` is a property of the score.
    scope: str = "CANONICAL"


class SecuritySummary(BaseModel):
    """The report's `security` block — counts over SECURITY-category
    findings only. Never a score; see `scoring.SCORED_CATEGORIES` and
    docs/security.md."""
    scored: bool = False
    label: str = "PASSIVE SIGNALS ONLY"
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    by_domain: dict[str, dict[str, int]] = Field(default_factory=dict)
    not_tested: list[str] = Field(default_factory=list)
    redaction_applied: bool = False


class Report(BaseModel):
    schema_version: str = REPORT_SCHEMA_VERSION
    core_version: str
    ruleset_version: str
    scan_id: str
    started_at: str
    completed_at: str
    target: Target
    score: Score
    categories: dict[str, CategoryScore]
    findings: list[CheckResult]
    metrics: dict = Field(default_factory=dict)
    not_tested: list[str] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    security: SecuritySummary = Field(default_factory=SecuritySummary)
