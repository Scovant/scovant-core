"""The machine-readable catalog of Core's rules and checks (Wave 4 PR-12).

Derived from the registries; nothing here is typed by hand. `scovant rules
--json` / `scovant checks --json` print it. The id lists are plain lists, not
closed enums: a rule added in a later release must not break a client."""
from __future__ import annotations

from scovant_core import __version__
from scovant_core.checks.registry import CHECKS, RULESET_VERSION
from scovant_core.crosswalk import AGENT_ONLY_RULES, CHECK_ROWS, counts
from scovant_core.r2.manifest import ScoreEffect
from scovant_core.r2.readiness import core_evidence
from scovant_core.r2.technical import technical_manifest
from scovant_core.rules import RULES

SCHEMA_VERSION = "1"


def _rule(rule, manifest) -> dict:
    spec = manifest.get(rule.code) if rule.code in manifest else None
    return {
        "code": rule.code, "title": rule.title, "category": str(rule.category),
        "severity": str(rule.severity), "maturity": rule.maturity, "scope": rule.scope,
        "rule_version": rule.rule_version, "since": rule.since,
        "evidence_core": core_evidence(rule.code),
        "technical_scored": bool(spec and spec.score_effect == ScoreEffect.WEIGHTED
                                 and spec.maturity == "required"),
        "requires_execution": False,
    }


def _agent_only(code: str) -> dict:
    # Core lists these rules but knows nothing about them beyond the code:
    # they need Scovant Cloud's agent fetch.
    return {"code": code, "title": None, "category": None, "severity": None, "maturity": None,
            "scope": None, "rule_version": None, "since": None,
            "evidence_core": "cloud_execution_only", "technical_scored": False,
            "requires_execution": True}


def build_catalog() -> dict:
    manifest = technical_manifest()
    rules = sorted([_rule(r, manifest) for r in RULES] + [_agent_only(c) for c in AGENT_ONLY_RULES],
                   key=lambda e: e["code"])
    rows = {row.check_id: row for row in CHECK_ROWS}
    checks = [{"id": c.id, "category": str(c.category.value if hasattr(c.category, "value") else c.category),
               "experimental": c.experimental,
               "profiles": sorted(c.profiles) if c.profiles is not None else None,
               "relationship": rows[c.id].relationship, "rules": list(rows[c.id].rules)}
              for c in sorted(CHECKS, key=lambda c: c.id)]
    return {"schema_version": SCHEMA_VERSION, "core_version": __version__,
            "ruleset_version": RULESET_VERSION, "counts": counts(),
            "rule_ids": [r["code"] for r in rules], "check_ids": [c["id"] for c in checks],
            "rules": rules, "checks": checks}


def render_text(kind: str) -> str:
    """One line per entry plus a counts line — the `scovant rules|checks` text mode."""
    cat = build_catalog()
    c = cat["counts"]
    if kind == "rules":
        lines = [f"{r['code']:<36} {r['maturity'] or '-':<12} {r['evidence_core']:<20} "
                 f"{'scored' if r['technical_scored'] else 'unscored'}" for r in cat["rules"]]
        lines.append(f"{c['rules']} rules: Core implements {c['core_rules']}; its CLI gathers "
                     f"evidence for {c['core_rules_gathered']} today ({c['core_rules_handshake']} of them only "
                     f"when the site publishes no MCP file); {c['cloud_only_rules']} need "
                     "Scovant Cloud's agent execution.")
    else:
        lines = [f"{k['id']:<24} {k['category']:<14} {'experimental' if k['experimental'] else 'stable':<12} "
                 f"{k['relationship']}" for k in cat["checks"]]
        lines.append(f"{c['checks']} checks: {c['readiness_checks']} readiness, {c['security_checks']} "
                     f"security, {c['experimental_checks']} experimental. Every check is a diagnostic.")
    return "\n".join(lines) + "\n"
