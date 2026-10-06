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

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from scovant_core.r2 import OutcomeState

SEVERITIES: frozenset[str] = frozenset({"info", "low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Finding:
    title: str
    description: str
    remediation_hint: str
    example: str | None = None
    metadata: dict = field(default_factory=dict)
    url: str | None = None
    # A graded rule picks the severity of each finding (one of SEVERITIES);
    # None = the rule's own `severity`.
    severity: str | None = None
    # The share of the rule's penalty this finding carries: a page rule that
    # normalises by the number of sampled pages reports 1/N per page. 1.0 =
    # the whole penalty.
    weight_multiplier: float = 1.0
    # The issue code the finding is reported under when it is not the rule's
    # own `code`: one of the rule's declared `aliases` (a rule that names its
    # worst band separately, for instance). None = the rule's code.
    code: str | None = None

    def __post_init__(self) -> None:
        if self.severity is not None and self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if not 0.0 < self.weight_multiplier <= 1.0:
            raise ValueError(f"weight_multiplier must be in (0, 1], got {self.weight_multiplier!r}")
        if self.code is not None and (not isinstance(self.code, str) or not self.code.strip()):
            raise ValueError(f"code must be a non-empty string, got {self.code!r}")


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
    # Other issue codes this rule's findings may carry (`Finding.code`); a
    # host maps each back to `code`. No code is claimed by two rules.
    aliases: tuple[str, ...] = ()
    # The Core release that first shipped this rule ("X.Y.Z"): a host's
    # catalog states "computed by Scovant Core ≥ since", and anyone can pin
    # that version and get the same verdicts. Required at registration.
    since: str = ""

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


_RELEASE = re.compile(r"\d+\.\d+\.\d+")
RULES: list[CoreRule] = []


def _conforming(cls: type[CoreRule]) -> None:
    """Make the rule read its evidence as `evidence.py` documents it (see
    `scovant_core.rules.conform`): `evaluate` and `measure` receive the
    conformed page and domain, whoever calls them."""
    from scovant_core.rules.conform import conform_domain, conform_page  # noqa: PLC0415 (cycle)

    evaluate, measure = cls.evaluate, cls.measure

    def evaluate_conformed(self, page, domain):
        return evaluate(self, conform_page(page), conform_domain(domain))

    def measure_conformed(self, page, domain, ctx):
        return measure(self, conform_page(page), conform_domain(domain), ctx)

    evaluate_conformed.__wrapped__ = evaluate  # type: ignore[attr-defined]
    measure_conformed.__wrapped__ = measure  # type: ignore[attr-defined]
    cls.evaluate = evaluate_conformed  # type: ignore[method-assign]
    cls.measure = measure_conformed  # type: ignore[method-assign]


def register_rule(cls: type[CoreRule]) -> type[CoreRule]:
    """Class decorator: instantiate once and add to `RULES`, reading
    conformed evidence (`_conforming`).

    `aliases` must be a tuple of non-empty codes, each different from the
    rule's own code and from one another; no code or alias may already be
    claimed by a registered rule. `since` must name a release ("X.Y.Z")."""
    if not isinstance(cls.since, str) or not _RELEASE.fullmatch(cls.since):
        raise ValueError(f"{cls.code}: since must be a release version like '0.9.0', got {cls.since!r}")
    aliases = cls.aliases
    if not isinstance(aliases, tuple) or any(
            not isinstance(a, str) or not a.strip() for a in aliases):
        raise ValueError(f"{cls.code}: aliases must be a tuple of non-empty codes")
    if cls.code in aliases or len(set(aliases)) != len(aliases):
        raise ValueError(f"{cls.code}: an alias repeats the rule's code or another alias")
    claimed = {c for r in RULES for c in (r.code, *r.aliases)}
    taken = sorted(claimed & {cls.code, *cls.aliases})
    if taken:
        raise ValueError(f"duplicate rule code {', '.join(taken)}")
    _conforming(cls)
    RULES.append(cls())
    return cls
