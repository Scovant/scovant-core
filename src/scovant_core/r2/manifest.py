"""R2 rule definitions and the manifest a readiness rating is built from.

The manifest is the single list of rules a rating counts. Exactly one rule
owns each measured `signal`, so the same fact (say, robots.txt allowing agents)
can never be scored twice by two rules that happen to measure it.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from scovant_core.models import Severity
from scovant_core.r2.outcome import R2Category

_RULE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]*$")


class RuleScope(StrEnum):
    PAGE = "page"
    DOMAIN = "domain"


class ScoreEffect(StrEnum):
    WEIGHTED = "weighted"      # counts in its category's ratio
    GATE = "gate"              # never in the ratio; a FAIL fires the policy's gate
    DIAGNOSTIC = "diagnostic"  # explained to the reader, never affects any number


class RuleSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    signal: str
    category: R2Category
    severity: Severity
    scope: RuleScope
    score_effect: ScoreEffect = ScoreEffect.WEIGHTED
    root_cause_group: str = ""
    # Site profiles the rule applies to; empty = every profile. Stored
    # lower-cased, stripped, sorted and de-duplicated, so matching is
    # case-insensitive and the digest never depends on input order.
    profiles: tuple[str, ...] = ()
    maturity: Literal["required", "experimental"] = "required"
    rule_version: str = "1.0"

    @field_validator("rule_id")
    @classmethod
    def _rule_id_shape(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError(f"rule_id {v!r} must match {_RULE_ID_RE.pattern}")
        return v

    @field_validator("signal")
    @classmethod
    def _signal_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("signal must be non-empty")
        return v

    @field_validator("profiles")
    @classmethod
    def _profiles_sorted(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({p.strip().lower() for p in v if p.strip()}))

    @model_validator(mode="after")
    def _gate_needs_group(self) -> RuleSpec:
        if self.score_effect == ScoreEffect.GATE and not self.root_cause_group:
            raise ValueError(f"gate rule {self.rule_id} needs a root_cause_group")
        return self


class Manifest:
    """An immutable, validated set of `RuleSpec`s."""

    def __init__(self, specs: Iterable[RuleSpec]) -> None:
        ordered = tuple(sorted(specs, key=lambda s: s.rule_id))
        seen_ids: set[str] = set()
        seen_signals: dict[str, str] = {}
        for s in ordered:
            if s.rule_id in seen_ids:
                raise ValueError(f"duplicate rule_id {s.rule_id}")
            seen_ids.add(s.rule_id)
            if s.signal in seen_signals:
                raise ValueError(
                    f"signal {s.signal!r} is owned by both {seen_signals[s.signal]} and {s.rule_id}"
                )
            seen_signals[s.signal] = s.rule_id
        group_category: dict[str, R2Category] = {}
        for s in ordered:
            if s.score_effect != ScoreEffect.WEIGHTED or not s.root_cause_group:
                continue
            first = group_category.setdefault(s.root_cause_group, s.category)
            if first != s.category:
                # Weighted outcomes of one root cause are merged into one
                # element; merging across categories would make the rating
                # depend on which member currently fails (not monotone).
                raise ValueError(f"root_cause_group {s.root_cause_group!r} spans categories "
                                 f"{first.value} and {s.category.value}")
        self.specs: tuple[RuleSpec, ...] = ordered
        self._by_id = {s.rule_id: s for s in ordered}

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._by_id

    def get(self, rule_id: str) -> RuleSpec:
        return self._by_id[rule_id]

    def digest(self) -> str:
        payload = [s.model_dump(mode="json") for s in self.specs]
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:12]
