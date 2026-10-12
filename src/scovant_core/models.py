"""Report data model (product-facing contract; see docs/methodology.md)."""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "2.0"
# `provenance.scan_scope`: CANONICAL (the full default selection) or CUSTOM
# (--include/--exclude/--experimental). A property of the SELECTION only.
SCAN_SCOPES = ("CANONICAL", "CUSTOM")
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
    # Passive security/trust signals only, surfaced through `Report.security`;
    # never part of Technical Readiness.
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
    # OWASP Agentic Top 10 mapping (`scovant_core.owasp`) — read from the
    # check's own `standards` declaration; a mapping, never a compliance claim.
    owasp_agentic: list[dict] = Field(default_factory=list)


class Target(BaseModel):
    input_url: str
    final_url: str | None
    requested_profile: str
    resolved_profile: str
    profile_confidence: float


class SecuritySummary(BaseModel):
    """The report's `security` block — counts over SECURITY-category
    findings only. Never a score; see docs/security.md."""
    scored: bool = False
    label: str = "PASSIVE SIGNALS ONLY"
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    by_domain: dict[str, dict[str, int]] = Field(default_factory=dict)
    not_tested: list[str] = Field(default_factory=list)
    redaction_applied: bool = False


class TechnicalCategory(BaseModel):
    rating: float | None
    applicable: bool


class NotMeasured(BaseModel):
    rule: str
    reason: str


class TechnicalReadiness(BaseModel):
    """Technical Readiness: the open R2 rating over the evidence Core gathered.
    Passive evidence only, so it is ESTIMATED (or NOT_MEASURED without a
    number) — never verified."""
    label: str = "Technical Readiness"
    rating: int | None
    grade: str | None
    badge: str | None
    status: str
    coverage: float
    model_id: str
    evidence_state: str
    scope: str = "CORE_PASSIVE"
    site_type: str
    site_type_origin: str
    categories: dict[str, TechnicalCategory]
    not_measured: list[NotMeasured]


class Readiness(BaseModel):
    technical: TechnicalReadiness


class TechnicalOutcome(BaseModel):
    rule: str
    state: Literal["PASS", "WARN", "FAIL", "N/A", "NOT_MEASURED", "ERROR", "BLOCKED_BY_POLICY", "UNKNOWN"]
    reason: str = ""
    scope: Literal["domain", "page"]


class Report(BaseModel):
    schema_version: str = REPORT_SCHEMA_VERSION
    core_version: str
    ruleset_version: str
    scan_id: str
    started_at: str
    completed_at: str
    target: Target
    findings: list[CheckResult]
    metrics: dict = Field(default_factory=dict)
    not_tested: list[str] = Field(default_factory=list)
    provenance: dict = Field(default_factory=dict)
    security: SecuritySummary = Field(default_factory=SecuritySummary)
    readiness: Readiness | None = None
    technical_outcomes: list[TechnicalOutcome] = Field(default_factory=list)
