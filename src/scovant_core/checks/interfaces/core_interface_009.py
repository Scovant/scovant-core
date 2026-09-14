"""CORE-INTERFACE-009 (EXPERIMENTAL): agent discovery surface presence,
reading the shared `check_agent_discovery` probe results
(`gatherers/agent_discovery_surface.py`). Text-only surfaces (e.g.
`agents_txt`) are recorded in evidence but not part of the scored set —
a plain-text manifest has no structured shape to evaluate.

CARRY-FORWARD, not fully resolved here: a scored surface's own probe
reports `exists: bool | None`, where `None` means "the candidate's body
was cut off before we could tell whether it parsed"
(`gatherers/agent_discovery.py`), never a claimed `False`. The `found`
list below still reads `exists` truthily, so a truncated-and-undetermined
surface is indistinguishable from a confirmed-absent one — the same class
of bug CORE-INTERFACE-001 had for its server-card probe. Unlike that
check's single binary condition, fixing this HONESTLY across six
independently tri-state surfaces means deciding what the overall verdict
should be when some surfaces are confirmed absent and others are merely
unread (ERROR? WARN? which one wins?) — and this check's own
`limitations` above already documents a DELIBERATE, pre-existing design
choice to never report WARN or ERROR at all, collapsing every failure
mode into "absent". Changing that vocabulary is a bigger decision than
threading a flag through a single `if`, so it is left unresolved and
noted here rather than guessed at. Only the truncation NOTE/CONFIDENCE
treatment is applied below; the status vocabulary is untouched.
"""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_SCORED_SURFACES = (
    "a2a_card",
    "a2a_card_legacy",
    "ai_plugin",
    "agents_json",
    "agent_skills",
    "agent_skills_legacy",
)


class AgentDiscoverySurfacePresence(CoreCheck):
    id = "CORE-INTERFACE-009"
    title = "Agent discovery surface presence"
    category = Category.INTERFACES
    profiles = frozenset({"api", "saas"})
    weight = 2
    experimental = True
    severity_on_fail = Severity.LOW
    references = (
        "https://a2a-protocol.org/",
        "https://github.com/openai/plugins",
    )
    why_it_matters = (
        "A published agent discovery surface — an A2A agent card, an AI-plugin manifest, "
        "an agents.json, or an Agent Skills index — lets an agent find this service's own "
        "capabilities without a human pointing it there."
    )
    limitations = (
        "Only a fixed set of conventional well-known paths is probed; a custom discovery "
        "location is not found. A surface whose document could not be fetched or did not "
        "parse is indistinguishable here from one that is absent; this check therefore "
        "never reports WARN or ERROR."
    )
    cloud_extension = "Scovant Cloud validates each discovered surface's own schema, not just that a document is present."
    standards = ("AR-READ-06", "AR-ACT-04")

    def evaluate(self, store, ctx):
        surface = store.get("agent_discovery_surface")
        surfaces = surface.get("surfaces") or {}
        found = [key for key in _SCORED_SURFACES if surfaces.get(key, {}).get("exists")]
        ev = {
            "surfaces_checked": list(_SCORED_SURFACES),
            "found": found,
            "agents_txt_present": bool(surfaces.get("agents_txt", {}).get("exists")),
        }
        # Every scored surface is read from its own probed document; a body
        # cut off at the fetch cap may be hiding a surface that would
        # otherwise have been found (see the CARRY-FORWARD note above), so
        # neither verdict below can claim full confidence when any
        # candidate was only read in part. `agent_discovery_surface` folds
        # many distinctly-named documents into one flag (mirroring
        # `agent_discovery`, a FOLDED record — see
        # test_truncation_document_labels.py), so no single document name
        # is attached.
        note, truncated = record_truncation(surface, ev)
        conf = truncated_confidence(truncated)

        if found:
            return self.result(
                CheckStatus.PASS,
                f"An agent discovery surface is published ({', '.join(found)})." + note,
                evidence=ev, confidence=conf,
            )

        return self.result(
            CheckStatus.NA,
            "No agent discovery surface (A2A card, AI-plugin manifest, agents.json, or "
            "Agent Skills index) was found." + note,
            evidence=ev, confidence=conf, severity=Severity.INFO,
        )
