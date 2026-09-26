"""R2 aggregation policy. `PUBLIC_POLICY` is the Technical Readiness policy:
every number in it is public and reproducible from this file. A host may pass
its own `ScoringPolicy` (e.g. a private gate cap); that result is then the
host's, not a Technical Readiness result."""
from __future__ import annotations

import hashlib
import json
import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from scovant_core.r2.outcome import R2Category


class Gate(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_cause_group: str
    effect: Literal["badge_block", "cap"]
    cap: int | None = None

    @model_validator(mode="after")
    def _cap_matches_effect(self) -> Gate:
        if self.effect == "cap" and (self.cap is None or not 0 <= self.cap <= 100):
            raise ValueError("a cap gate needs cap in 0..100")
        if self.effect == "badge_block" and self.cap is not None:
            raise ValueError("a badge_block gate takes no cap")
        return self


class ScoringPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    category_weights: dict[R2Category, float]
    severity_weights: dict[str, int]
    # Categories restricted to some profiles; a category absent here applies to all.
    category_profiles: dict[R2Category, tuple[str, ...]]
    evidence_min_coverage: float
    canonical_min_coverage: float
    grades: tuple[tuple[int, str], ...]   # descending floors
    badges: tuple[tuple[int, str], ...]   # descending floors
    gates: tuple[Gate, ...]
    # R2.1: a pseudo-pass weight added to every MEASURED category (numerator and
    # denominator), so one failure in a sparse category cannot collapse it to 0.
    # Not evidence: coverage ignores it. 0 = the plain ratio.
    category_prior_weight: float = 0.0

    @field_validator("category_profiles")
    @classmethod
    def _profiles_normalised(
        cls, v: dict[R2Category, tuple[str, ...]],
    ) -> dict[R2Category, tuple[str, ...]]:
        return {c: tuple(sorted({p.strip().lower() for p in ps if p.strip()})) for c, ps in v.items()}

    @model_validator(mode="after")
    def _complete(self) -> ScoringPolicy:
        if set(self.category_weights) != set(R2Category):
            raise ValueError("category_weights must cover every R2Category exactly")
        if set(self.severity_weights) != {"critical", "high", "medium", "low", "info"}:
            raise ValueError("severity_weights must cover every severity exactly")
        if not (math.isfinite(self.category_prior_weight) and self.category_prior_weight >= 0):
            raise ValueError("category_prior_weight must be a non-negative number")
        groups = [g.root_cause_group for g in self.gates]
        if len(groups) != len(set(groups)):
            raise ValueError("one gate per root_cause_group")
        return self

    def category_applies(self, category: R2Category, profile: str) -> bool:
        allowed = self.category_profiles.get(category)
        return allowed is None or profile in allowed

    def gate_for(self, group: str) -> Gate | None:
        return next((g for g in self.gates if g.root_cause_group == group), None)

    def digest(self) -> str:
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:12]


PUBLIC_POLICY = ScoringPolicy(
    name="technical-public",
    category_weights={
        R2Category.DISCOVERABILITY: 0.17, R2Category.STRUCTURED: 0.18,
        R2Category.CONSISTENCY: 0.15, R2Category.ACTIONABILITY: 0.12,
        R2Category.TRUST: 0.08, R2Category.UCP: 0.12, R2Category.CITABILITY: 0.18,
    },
    severity_weights={"critical": 40, "high": 25, "medium": 14, "low": 6, "info": 2},
    category_profiles={
        R2Category.UCP: ("booking", "commerce", "restaurant", "saas"),
        R2Category.CITABILITY: ("blog", "docs", "documentation", "media", "news", "other", "portfolio"),
    },
    evidence_min_coverage=0.60,
    canonical_min_coverage=0.85,
    grades=((90, "A"), (80, "B"), (60, "C"), (0, "D")),
    badges=((80, "agent_ready"), (60, "agent_compatible")),
    gates=(Gate(root_cause_group="agent_access_blocked", effect="badge_block"),),
    category_prior_weight=14.0,   # one medium-severity rule's weight
)
