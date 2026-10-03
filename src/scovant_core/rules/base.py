"""The contract a Scovant Cloud rule implements once it lives in Core.

A rule reads the public evidence documented in `scovant_core.rules.evidence`
and answers two questions:

- `evaluate(page, domain)` — the findings on this page (or the domain), as
  plain `Finding`s. An empty list means "nothing to report", which is a pass
  only when `measure` says the rule actually measured something.
- `measure(page, domain, ctx)` — `None` when the rule measured its input,
  `OutcomeState.NA` when it does not apply here, `OutcomeState.NOT_MEASURED`
  when the input was absent or the probe behind it failed.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from scovant_core.r2 import OutcomeState


@dataclass(frozen=True)
class Finding:
    title: str
    description: str
    remediation_hint: str
    example: str | None = None
    metadata: dict = field(default_factory=dict)
    url: str | None = None


@dataclass(frozen=True)
class MeasureCtx:
    site_category: str | None
    # probes that fell back to an inert default because the fetch failed;
    # None = the evidence predates this marker (read as measured)
    defaulted: frozenset[str] | None


class CoreRule(ABC):
    code: str
    category: str
    severity: str
    title: str
    maturity: str = "required"
    rule_version: str = "1.0"
    scope: str = "domain"  # "page" | "domain"

    @abstractmethod
    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]: ...

    @abstractmethod
    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None: ...


def probe_measured(domain: dict | None, ctx: MeasureCtx, *keys: str) -> OutcomeState | None:
    """NOT_MEASURED when the domain evidence is absent, a block is missing,
    the probe that filled it fell back to its default, or the block itself
    reports that a request never answered (`fetch_status: "error"`);
    otherwise None."""
    if not domain:
        return OutcomeState.NOT_MEASURED
    for key in keys:
        block = domain.get(key)
        if not isinstance(block, dict):
            return OutcomeState.NOT_MEASURED
        if ctx.defaulted is not None and key in ctx.defaulted:
            return OutcomeState.NOT_MEASURED
        if block.get("fetch_status") == "error":
            return OutcomeState.NOT_MEASURED
    return None


RULES: list[CoreRule] = []


def register_rule(cls: type[CoreRule]) -> type[CoreRule]:
    """Class decorator: instantiate once and add to `RULES`."""
    if any(r.code == cls.code for r in RULES):
        raise ValueError(f"duplicate rule code {cls.code}")
    RULES.append(cls())
    return cls
