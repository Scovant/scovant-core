"""Technical Readiness for one scan: evaluate every public rule on the
sampled pages and the domain evidence, turn the verdicts into outcomes, and
score them under `PUBLIC_POLICY`.

A rule EVALUATES a page as its producer stored it and MEASURES it with the
fetch status (`_http_status`) attached — the same split a Cloud scan uses, so
the same evidence gives the same outcomes in both.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from scovant_core.r2.outcome import Outcome, OutcomeState
from scovant_core.r2.policy import PUBLIC_POLICY
from scovant_core.r2.score import R2Result, score_r2
from scovant_core.r2.technical import (
    domain_outcome,
    outcome_from_row,
    page_outcome,
    technical_manifest,
    technical_outcomes,
)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class TechnicalRun:
    result: R2Result
    outcomes: tuple[Outcome, ...]


def _without_status(page: dict) -> dict:
    return {k: v for k, v in page.items() if k != "_http_status"}


def rule_rows(pages: Sequence[dict], domain: dict | None, *, site_category: str | None,
              defaulted: frozenset[str] | None) -> list[dict]:
    from scovant_core.rules import RULES, CoreRule, MeasureCtx  # noqa: PLC0415 (rules import r2)

    ctx = MeasureCtx(site_category=site_category, defaulted=defaulted)
    domain = domain if isinstance(domain, dict) else None
    pages = [p if isinstance(p, dict) else {} for p in pages]
    rows: list[dict] = []
    for rule in sorted((r for r in RULES if r.maturity != "deprecated"), key=lambda r: r.code):
        fired_per_page: list[bool] = []
        seen: str | None = None
        for page in pages:
            findings = rule.evaluate(_without_status(page), domain)
            fired_per_page.append(bool(findings))
            for f in findings:
                sev = f.severity or rule.severity
                if seen is None or _SEVERITY_RANK[sev] > _SEVERITY_RANK[seen]:
                    seen = sev
        if rule.scope == "domain":
            def measure_domain(dd: dict | None, r: CoreRule = rule) -> OutcomeState | None:
                return r.measure({}, dd, ctx)

            outcome = domain_outcome(rule.code, measure_domain, domain,
                                     fired=any(fired_per_page), have_pages=bool(pages))
        else:
            def measure_page(ex: dict, dd: dict | None, r: CoreRule = rule) -> OutcomeState | None:
                return r.measure(ex, dd, ctx)

            outcome = page_outcome(rule.code, measure_page, pages, domain,
                                   fired_per_page, site_category=site_category)
        rows.append({**outcome.model_dump(mode="json"), "severity_seen": seen})
    return rows


def technical_readiness(pages: Sequence[dict], domain: dict | None, *, site_type: str,
                        defaulted: frozenset[str] | None) -> TechnicalRun:
    rows = rule_rows(pages, domain, site_category=site_type, defaulted=defaulted)
    by_id = {row["rule_id"]: outcome_from_row(row) for row in rows}
    manifest = technical_manifest()
    outcomes = technical_outcomes(by_id, manifest)
    profile = (site_type or "other").strip().lower()
    result = score_r2(outcomes, profile=profile, manifest=manifest, policy=PUBLIC_POLICY)
    return TechnicalRun(result=result, outcomes=tuple(sorted(outcomes, key=lambda o: o.rule_id)))
