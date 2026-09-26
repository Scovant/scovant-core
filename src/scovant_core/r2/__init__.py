"""Readiness R2 — the open, bounded readiness model shared by Scovant Core
(Technical Readiness) and any host that supplies its own policy.

Not yet part of the scan report: `scovant scan` output, the report schema and
`ruleset_version` are unchanged by this package. See docs/r2.md.
"""
from __future__ import annotations

from scovant_core.r2.manifest import Manifest, RuleScope, RuleSpec, ScoreEffect
from scovant_core.r2.outcome import (
    MEASURED_STATES,
    STATE_VALUE,
    Outcome,
    OutcomeState,
    R2Category,
)
from scovant_core.r2.policy import PUBLIC_POLICY, Gate, ScoringPolicy
from scovant_core.r2.score import (
    FORMULA_VERSION,
    CategoryResult,
    GateHit,
    R2Result,
    model_id,
    score_r2,
)

__all__ = [
    "FORMULA_VERSION", "MEASURED_STATES", "PUBLIC_POLICY", "STATE_VALUE", "CategoryResult", "Gate",
    "GateHit", "Manifest", "Outcome", "OutcomeState", "R2Category", "R2Result", "RuleScope",
    "RuleSpec", "ScoreEffect", "ScoringPolicy", "model_id", "score_r2",
]
