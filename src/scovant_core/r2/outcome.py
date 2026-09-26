"""R2 outcome contract: one outcome per rule per scan.

The report's `CheckStatus` is a published contract (report schema 1.1) and is
deliberately NOT extended here. R2 needs states the report never emits:
NOT_MEASURED (the input the rule needs is absent), BLOCKED_BY_POLICY (our own
identity was refused), UNKNOWN (the rule produced no outcome at all). Only
PASS / WARN / FAIL are measurements; every other state leaves the score and
lowers coverage — it is never a failure of the site.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator


class OutcomeState(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NA = "N/A"
    NOT_MEASURED = "NOT_MEASURED"
    ERROR = "ERROR"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    UNKNOWN = "UNKNOWN"


MEASURED_STATES: frozenset[OutcomeState] = frozenset(
    {OutcomeState.PASS, OutcomeState.WARN, OutcomeState.FAIL}
)
STATE_VALUE: dict[OutcomeState, float] = {
    OutcomeState.PASS: 1.0, OutcomeState.WARN: 0.5, OutcomeState.FAIL: 0.0,
}


class R2Category(StrEnum):
    DISCOVERABILITY = "discoverability"
    STRUCTURED = "structured"
    CONSISTENCY = "consistency"
    ACTIONABILITY = "actionability"
    TRUST = "trust"
    UCP = "ucp"
    CITABILITY = "citability"


class Outcome(BaseModel):
    """What one rule concluded on one scan. Category, severity and scope are
    NOT carried here — they come from the rule's `RuleSpec`, the single
    source, so an outcome can never disagree with its rule's definition."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    state: OutcomeState
    # Page-scope rules only: how many sampled pages the rule looked at and on
    # how many it did not pass. Both None for a domain-scope rule.
    pages_measured: int | None = None
    pages_failed: int | None = None
    # Identity of the evidence behind a failure (e.g. "robots:/"). Two failing
    # outcomes are treated as one root cause only when they share BOTH the
    # rule's root_cause_group AND a non-empty evidence_key.
    evidence_key: str = ""
    reason: str = ""

    @model_validator(mode="after")
    def _pages_consistent(self) -> Outcome:
        pm, pf = self.pages_measured, self.pages_failed
        if (pm is None) != (pf is None):
            raise ValueError("pages_measured and pages_failed must both be set or both be None")
        if pm is not None and pf is not None:
            if pm < 0 or pf < 0:
                raise ValueError("page counts must be non-negative")
            if pf > pm:
                raise ValueError("pages_failed cannot exceed pages_measured")
        return self
