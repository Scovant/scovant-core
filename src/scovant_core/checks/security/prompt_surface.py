"""CORE-SECURITY-011..016 — prompt / instruction manipulation surface
(PROMPT-SURFACE-*). All experimental, WARN-only heuristic pattern matches
over already-gathered machine-facing text (never a fresh probe, never an
authenticated request, never a `tools/call`)."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from scovant_core.analysis.instruction_markers import (
    find_disclosure_requests,
    find_external_transmission,
    find_imperatives,
    find_override_phrases,
)
from scovant_core.analysis.mcp_meta import find_injection_markers, find_obfuscation
from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.checks.base import CoreCheck
from scovant_core.checks.security._secrets import redact_phrase
from scovant_core.models import Category, CheckStatus, Confidence, Severity
from scovant_core.parsers.html import extract_visible_text

_LIMITS = ("Heuristic passive indicator only: pattern matches over public machine-facing text. It never executes "
           "an instruction, never tests a real agent, and a WARN is not a vulnerability claim.")
_MACHINE_KINDS = ("hidden_dom", "meta_description", "json_ld", "llms_txt", "markdown_mirror", "mcp_discovery",
                  "mcp_server_description", "webmcp_tool", "agent_discovery", "openapi", "ucp")
# Structured, machine-generated surfaces where a matched "external
# transmission" phrase is far more likely to be a legitimate declared
# integration (an OpenAPI callback URL, a JSON-LD `sameAs`/contact link, a
# UCP payment/webhook endpoint) than a prose instruction — a hit confined to
# these kinds is reported at LOW rather than MEDIUM confidence.
_LOW_SIGNAL_TRANSMIT_KINDS = frozenset({"openapi", "json_ld", "ucp"})
_VISIBLE_TEXT_CAP = 5000  # extract_visible_text's own documented cap


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()



def _phrase_fields(phrase: str) -> dict:
    """`{"phrase": ...}` with every credential-shaped span replaced, plus a
    `"redacted": True` marker when a replacement actually happened.

    The marker is not decoration: `security_summary._has_redaction` looks
    for a literal `redacted` key anywhere in a finding's evidence to set
    the report's `security.redaction_applied` flag, so a redaction that
    left no key behind would make that flag read `false` on a report where
    a secret WAS removed."""
    redacted = redact_phrase(phrase)
    out: dict = {"phrase": redacted}
    if redacted != phrase:
        out["redacted"] = True
    return out


def _marker_fields(markers: list[str]) -> dict:
    """The `markers` counterpart of `_phrase_fields` — same redaction, same
    honest flag, over a list of matched marker strings."""
    redacted = [redact_phrase(m) for m in markers]
    out: dict = {"markers": redacted}
    if redacted != markers:
        out["redacted"] = True
    return out


class _Prompt(CoreCheck):
    category = Category.SECURITY
    security_domain = "prompt_surface"
    verification_mode = "DECLARED"
    fix_owner = "content"
    experimental = True
    severity_on_fail = Severity.MEDIUM
    security_tags = ("agentic-security", "prompt-surface")
    limitations = _LIMITS
    cloud_extension = "Scovant Cloud runs authorized prompt-resilience scenarios with synthetic canaries."
    references = ("https://owasp.org/www-project-top-10-for-large-language-model-applications/",)
    standards = ("OWASP Agentic Top 10 2026: ASI01 (partial)",)

    def _machine_text(self, store) -> dict | None:
        """`None` when the entry URL itself could not be fetched (`error`() is
        the right verdict — a site we could not read at all, not "nothing to
        evaluate"). Otherwise the raw `machine_text` gatherer record, never a
        fresh fetch of its own."""
        if store.get("http").get("error"):
            return None
        return store.get("machine_text")

    @staticmethod
    def _kind_surfaces(mt: dict, kinds: tuple[str, ...]) -> list[dict]:
        return [s for s in mt["surfaces"] if s["kind"] in kinds]

    @staticmethod
    def _any_truncated(mt: dict, surfaces: list[dict]) -> bool:
        return bool(mt.get("capped")) or any(s.get("truncated") for s in surfaces)


class HiddenImperative(_Prompt):
    id = "CORE-SECURITY-011"
    family_id = "PROMPT-SURFACE-001"
    title = "Hidden machine-facing imperative instructions"
    why_it_matters = "Text a human never sees but an agent reads verbatim is the classic indirect-injection carrier."
    promotion_criteria = ("Precision ≥ 0.7 on a hand-labelled sample of ≥ 100 WARNs from the calibration corpus "
                          "and a WARN rate ≤ 3 % on the marketing corpus.")

    def evaluate(self, store, ctx):
        mt = self._machine_text(store)
        if mt is None:
            return self.error("entry URL could not be fetched")
        surfaces = self._kind_surfaces(mt, _MACHINE_KINDS)
        if not surfaces:
            # `machine_text` genuinely gathered no surface at all across
            # EVERY kind it can ever produce — an empty list here means no
            # gatherer produced content, not that a truncated read cut it
            # away (the first surface always fits the total budget; see
            # AUDITED_SILENT_BRANCHES in test_truncation_check_completeness.py).
            return self.na("No machine-facing surface was gathered.")
        hits = [{"surface_kind": s["kind"], "source": s["source"], **_phrase_fields(p)}
                for s in surfaces for p in find_imperatives(s["text"])]
        any_truncated = self._any_truncated(mt, surfaces)
        if hits:
            ev = {"hits": hits[:20], "hit_count": len(hits)}
            base = Confidence.MEDIUM if len(hits) >= 2 else Confidence.LOW
            note, truncated = record_truncation({"truncated": any_truncated}, ev)
            conf = truncated_confidence(truncated, default=base)
            return self.result(CheckStatus.WARN,
                                f"Imperative instruction(s) addressed to agents in machine-facing text.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Remove instructions aimed at agents from hidden/metadata surfaces; describe, don't command.")
        ev = {"surfaces_scanned": len(surfaces)}
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        # A heuristic PASS ("nothing matched") is not HIGH-confidence
        # evidence of absence — the pattern set is a curated sample, not an
        # exhaustive grammar — so every PASS here publishes at MEDIUM even
        # on a fully-read document.
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        return self.result(CheckStatus.PASS, f"No indicators found.{note}", evidence=ev, confidence=conf)


class SensitiveRequest(_Prompt):
    id = "CORE-SECURITY-012"
    family_id = "PROMPT-SURFACE-002"
    title = "Sensitive-information request instruction"
    severity_on_fail = Severity.HIGH
    why_it_matters = "A machine-facing request to disclose credentials or private data is the exfiltration half of an injection."
    promotion_criteria = "Precision ≥ 0.8 on ≥ 30 labelled WARNs; zero hits on the public fixture corpus except the suspicious fixture."

    def evaluate(self, store, ctx):
        mt = self._machine_text(store)
        if mt is None:
            return self.error("entry URL could not be fetched")
        surfaces = self._kind_surfaces(mt, _MACHINE_KINDS)
        if not surfaces:
            return self.na("No machine-facing surface was gathered.")
        hits = [{"surface_kind": s["kind"], "source": s["source"], **_phrase_fields(p)}
                for s in surfaces for p in find_disclosure_requests(s["text"])]
        any_truncated = self._any_truncated(mt, surfaces)
        if hits:
            ev = {"hits": hits[:20], "hit_count": len(hits)}
            note, truncated = record_truncation({"truncated": any_truncated}, ev)
            conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
            return self.result(CheckStatus.WARN,
                                f"Machine-facing text asks an agent to disclose credentials or private data.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Remove the request; no legitimate site content asks an agent for secrets.")
        ev = {"surfaces_scanned": len(surfaces)}
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        return self.result(CheckStatus.PASS, f"No indicators found.{note}", evidence=ev, confidence=conf)


class ExternalTransmissionInstruction(_Prompt):
    id = "CORE-SECURITY-013"
    family_id = "PROMPT-SURFACE-003"
    title = "External transmission instruction"
    severity_on_fail = Severity.HIGH
    why_it_matters = "An instruction to send data to a third-party host is a data-exfiltration attempt if an agent obeys it."
    promotion_criteria = "Precision ≥ 0.8 on ≥ 30 labelled WARNs (a legitimate webhook/documentation URL must not count)."

    def evaluate(self, store, ctx):
        mt = self._machine_text(store)
        if mt is None:
            return self.error("entry URL could not be fetched")
        surfaces = self._kind_surfaces(mt, _MACHINE_KINDS)
        if not surfaces:
            return self.na("No machine-facing surface was gathered.")
        own = (urlsplit(ctx.origin or ctx.input_url).hostname or "").lower()
        hits = [{"surface_kind": s["kind"], "source": s["source"], **h, **_phrase_fields(h["phrase"])}
                for s in surfaces for h in find_external_transmission(s["text"], own)]
        any_truncated = self._any_truncated(mt, surfaces)
        if hits:
            ev = {"hits": hits[:20], "hit_count": len(hits)}
            note, truncated = record_truncation({"truncated": any_truncated}, ev)
            # A hit found ONLY inside structured, machine-generated surfaces
            # (a declared OpenAPI callback URL, a JSON-LD contact/sameAs
            # link, a UCP payment/webhook endpoint) is much more likely to
            # be a legitimate declared integration than a prose
            # instruction — downgrade to LOW rather than MEDIUM in that case.
            base = (Confidence.LOW if all(h["surface_kind"] in _LOW_SIGNAL_TRANSMIT_KINDS for h in hits)
                    else Confidence.MEDIUM)
            conf = truncated_confidence(truncated, default=base)
            return self.result(CheckStatus.WARN,
                                f"Machine-facing text instructs sending data to an external host.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Remove instructions that direct agents to third-party endpoints.")
        ev = {"surfaces_scanned": len(surfaces)}
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        return self.result(CheckStatus.PASS, f"No indicators found.{note}", evidence=ev, confidence=conf)


class OverrideLanguage(_Prompt):
    id = "CORE-SECURITY-014"
    family_id = "PROMPT-SURFACE-004"
    title = "Policy/role override language"
    why_it_matters = "\"Ignore previous instructions\" and friends have no legitimate place in site content."
    promotion_criteria = "WARN rate ≤ 2 % on the marketing corpus with precision ≥ 0.8 on labelled hits."

    def evaluate(self, store, ctx):
        mt = self._machine_text(store)
        if mt is None:
            return self.error("entry URL could not be fetched")
        surfaces = self._kind_surfaces(mt, _MACHINE_KINDS)
        if not surfaces:
            return self.na("No machine-facing surface was gathered.")
        hits = [{"surface_kind": s["kind"], "source": s["source"], **_phrase_fields(p)}
                for s in surfaces for p in (find_override_phrases(s["text"]) + find_injection_markers(s["text"]))]
        any_truncated = self._any_truncated(mt, surfaces)
        if hits:
            ev = {"hits": hits[:20], "hit_count": len(hits)}
            note, truncated = record_truncation({"truncated": any_truncated}, ev)
            conf = truncated_confidence(truncated, default=Confidence.LOW)
            return self.result(CheckStatus.WARN, f"Role/policy override language in machine-facing text.{note}",
                                evidence=ev, confidence=conf, remediation="Remove the phrase(s).")
        ev = {"surfaces_scanned": len(surfaces)}
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        return self.result(CheckStatus.PASS, f"No indicators found.{note}", evidence=ev, confidence=conf)


class HumanMachineDivergence(_Prompt):
    id = "CORE-SECURITY-015"
    family_id = "PROMPT-SURFACE-005"
    title = "Human ↔ machine instruction divergence"
    why_it_matters = "Instructions present in the machine mirror but absent from the visible page are addressed to agents only."
    promotion_criteria = "Precision ≥ 0.7 on ≥ 50 labelled WARNs; N/A rate documented per profile."
    limitations = ("Heuristic passive indicator only: compares an instruction phrase found in machine-facing text "
                  "against the visible text of the rendered page (itself capped at 5000 characters) by normalized "
                  "substring containment. It never executes an instruction, never tests a real agent, and a WARN "
                  "is not a vulnerability claim.")

    def evaluate(self, store, ctx):
        http = store.get("http")
        if http.get("error"):
            return self.error("entry URL could not be fetched")
        mt = store.get("machine_text")
        machine = self._kind_surfaces(mt, ("llms_txt", "markdown_mirror"))
        if not machine:
            # A truncated read never DROPS a gathered surface from the list
            # (`machine_text.py`'s `_surface()` builder still appends a
            # shortened surface when its own text was cut at the per-surface
            # cap) — but it CAN drop a later candidate entirely once the
            # running TOTAL budget is exhausted (`break`, no append at all).
            # llms.txt/markdown are gathered after every html-derived
            # surface (json_ld/meta_description/hidden_dom/webmcp_tool), so
            # a handful of large JSON-LD blocks can push the running total
            # over budget before llms.txt is ever reached — an empty subset
            # here is NOT independent of truncation in that case, and must
            # disclose it rather than reading as "no machine mirror exists".
            if mt.get("capped"):
                return self.na("No machine mirror (llms.txt / markdown) to compare.", {"truncated": True},
                                confidence=Confidence.MEDIUM)
            return self.na("No machine mirror (llms.txt / markdown) to compare.")
        visible_raw = extract_visible_text(http.get("html") or "")
        visible_capped = len(visible_raw) >= _VISIBLE_TEXT_CAP
        visible_norm = _normalize(visible_raw)
        hits = []
        for s in machine:
            for p in find_imperatives(s["text"]) + find_override_phrases(s["text"]):
                p_norm = _normalize(p)
                if p_norm and p_norm not in visible_norm:
                    hits.append({"surface_kind": s["kind"], "source": s["source"], **_phrase_fields(p)})
        any_truncated = self._any_truncated(mt, machine) or bool(http.get("truncated")) or visible_capped
        ev: dict = {"hits": hits[:20], "hit_count": len(hits)} if hits else {"surfaces_scanned": len(machine)}
        if visible_capped:
            ev["visible_text_capped"] = True
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        # The visible-text comparison is only ever a partial read when the
        # 5000-char cap was hit — an instruction could be sitting in the
        # truncated tail and read as "absent" when it is merely unread.
        # That specific degradation always publishes at MEDIUM, whichever
        # verdict it feeds (WARN or PASS); otherwise WARN stays at the
        # check's normal LOW and PASS at the shared heuristic-absence
        # MEDIUM (see the MEDIUM-not-HIGH note on the other five checks).
        base = Confidence.MEDIUM if (visible_capped or not hits) else Confidence.LOW
        conf = truncated_confidence(truncated, default=base)
        if hits:
            return self.result(CheckStatus.WARN,
                                f"Instruction(s) in the machine mirror are absent from the visible page.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Keep the machine mirror a faithful copy of visible content.")
        return self.result(CheckStatus.PASS, f"No indicators found.{note}", evidence=ev, confidence=conf)


class ToolDescriptionTrust(_Prompt):
    id = "CORE-SECURITY-016"
    family_id = "PROMPT-SURFACE-006"
    title = "Tool/server description trust risk"
    fix_owner = "mcp"
    why_it_matters = ("A tool description is injected into the agent's context on every call; unrelated "
                      "instructions or hidden Unicode there are a supply-chain injection vector.")
    promotion_criteria = "Precision ≥ 0.8 on ≥ 30 labelled WARNs from the community Core index."
    limitations = ("Heuristic passive indicator only: pattern matches over declared MCP server and WebMCP tool "
                  "descriptions. It never executes an instruction, never invokes a tool, and a WARN is not a "
                  "vulnerability claim.")

    def evaluate(self, store, ctx):
        mt = self._machine_text(store)
        if mt is None:
            return self.error("entry URL could not be fetched")
        descs = self._kind_surfaces(mt, ("mcp_server_description", "webmcp_tool"))
        if not descs:
            # Same reasoning as CORE-SECURITY-015 above: llms.txt/openapi
            # surfaces (gathered before the per-server description
            # surfaces, see machine_text.py) can exhaust the running total
            # budget and drop every mcp_server_description/webmcp_tool
            # surface with `break` before this check ever sees one, even
            # though a real MCP server with a real description was declared.
            if mt.get("capped"):
                return self.na("No MCP server or WebMCP tool descriptions gathered.", {"truncated": True},
                                confidence=Confidence.MEDIUM)
            return self.na("No MCP server or WebMCP tool descriptions gathered.")
        hits = []
        for s in descs:
            markers = (find_override_phrases(s["text"]) + find_injection_markers(s["text"])
                       + find_imperatives(s["text"]) + find_obfuscation(s["text"]))
            if markers:
                hits.append({"surface_kind": s["kind"], "source": s["source"], **_marker_fields(markers[:10])})
        any_truncated = self._any_truncated(mt, descs)
        if hits:
            ev = {"hits": hits[:20], "hit_count": len(hits)}
            note, truncated = record_truncation({"truncated": any_truncated}, ev)
            conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
            return self.result(CheckStatus.WARN,
                                f"Tool/server description carries instructions unrelated to its purpose or obfuscated text.{note}",
                                evidence=ev, confidence=conf,
                                remediation="Descriptions must describe the tool only; strip imperatives and hidden Unicode.")
        ev = {"surfaces_scanned": len(descs)}
        note, truncated = record_truncation({"truncated": any_truncated}, ev)
        conf = truncated_confidence(truncated, default=Confidence.MEDIUM)
        return self.result(CheckStatus.PASS, f"No indicators found.{note}", evidence=ev, confidence=conf)


PROMPT_SURFACE_CHECKS: list[CoreCheck] = [
    HiddenImperative(), SensitiveRequest(), ExternalTransmissionInstruction(),
    OverrideLanguage(), HumanMachineDivergence(), ToolDescriptionTrust(),
]
