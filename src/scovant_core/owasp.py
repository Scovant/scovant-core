"""OWASP Top 10 for Agentic Applications (2026) — a mapping layer, not a ruleset.

A mapping says which ASI category a check or rule produces evidence about,
and how strongly. It is never a compliance claim: matching these checks says
nothing about the categories they do not test, and a category no check maps
to is simply not tested by a passive scanner.

The security checks declare their mapping in their own ``standards`` tuple
(``"OWASP Agentic Top 10 2026: ASI01 (partial)"``) — that declaration is the
one source, and :func:`parse_standards` reads it. Rules have no ``standards``
field, so their mapping lives in :data:`RULE_MAPPINGS` below.
"""
from __future__ import annotations

import re

#: The ten categories, verbatim from the 2026 list.
ASI_TITLES: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

#: How much of a category a check covers. ``EXACT`` and ``SCOVANT_SUPERSET``
#: are part of the vocabulary but no passive check claims either.
RELATIONS = ("EXACT", "PARTIAL", "SCOVANT_SUPERSET", "FRAMEWORK_ONLY", "NOT_APPLICABLE")

FRAMEWORK = "OWASP Top 10 for Agentic Applications 2026"

_STANDARD = re.compile(r"^OWASP Agentic Top 10 2026: (ASI(?:0[1-9]|10)) \(([a-z_]+)\)$")

#: Core rules that produce evidence about an ASI category. Every entry is
#: PARTIAL: a rule sees one surface of a category, never the whole of it.
RULE_MAPPINGS: dict[str, tuple[tuple[str, str], ...]] = {
    # Instructions planted in tool metadata steer the agent's goal.
    "AGENT-META-001": (("ASI01", "PARTIAL"),),
    "AGENT-META-008": (("ASI01", "PARTIAL"),),
    "WEBMCP-004": (("ASI01", "PARTIAL"),),
    # Tool surfaces an agent can misuse or misroute.
    "AGENT-META-004": (("ASI02", "PARTIAL"),),
    "TOOL-RISK-001": (("ASI02", "PARTIAL"),),
    "WEBMCP-005": (("ASI02", "PARTIAL"),),
    # Authorization an agent cannot discover is authorization it cannot scope.
    "MCP-AUTH-001": (("ASI03", "PARTIAL"),),
    # Instructions that point an agent at packages or domains it will install.
    "LLMS-SUPPLY-001": (("ASI04", "PARTIAL"),),
    "LLMS-SUPPLY-002": (("ASI04", "PARTIAL"),),
    "LLMS-SUPPLY-006": (("ASI04", "PARTIAL"), ("ASI05", "PARTIAL")),
    "LLMS-SUPPLY-008": (("ASI04", "PARTIAL"),),
}


def entry(asi: str, relation: str) -> dict:
    """One mapping as served: ``{framework, id, title, relation}``."""
    if asi not in ASI_TITLES:
        raise ValueError(f"unknown OWASP Agentic category {asi!r}")
    if relation not in RELATIONS:
        raise ValueError(f"unknown mapping relation {relation!r}")
    return {"framework": FRAMEWORK, "id": asi, "title": ASI_TITLES[asi], "relation": relation}


def parse_standards(standards) -> list[dict]:
    """The OWASP entries a check's ``standards`` tuple declares, in order.
    Non-OWASP references (RFCs, format specs) are not mappings and are
    skipped; an OWASP string this parser cannot read raises, so a typo in a
    declaration fails the test suite rather than silently mapping nothing."""
    out = []
    for std in standards or ():
        if not std.startswith("OWASP"):
            continue
        m = _STANDARD.match(std)
        if not m:
            raise ValueError(f"unreadable OWASP standard declaration {std!r}")
        out.append(entry(m.group(1), m.group(2).upper()))
    return out


def for_rule(code: str) -> list[dict]:
    """The OWASP entries for a Core rule code; ``[]`` when it maps to none."""
    return [entry(a, r) for a, r in RULE_MAPPINGS.get(code, ())]


def describe(entries) -> str:
    """One line for a report: ``ASI01 Agent Goal Hijack (partial)``, joined.
    Empty when nothing is mapped — a report never prints "none" as if it
    had looked and found the check irrelevant."""
    return "; ".join(f"{e['id']} {e['title']} ({e['relation'].lower()})" for e in entries or ())
