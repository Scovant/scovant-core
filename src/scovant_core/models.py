"""Report data model (product-facing contract; see docs/methodology.md)."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "1.0"
SCORE_NAME = "Scovant Core Static Signal Score"
SCORE_SHORT_NAME = "Core Score"


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


CATEGORY_TITLES = {
    Category.ACCESS: "Access & Discovery",
    Category.MACHINE: "Machine Understanding",
    Category.INTERFACES: "Agent Interfaces",
    Category.TRUST: "Trust & Commerce",
    Category.OPERABILITY: "Operability & Efficiency",
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
    status: str  # "OK" | "INSUFFICIENT_EVIDENCE"


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
