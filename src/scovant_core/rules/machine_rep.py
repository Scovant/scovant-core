"""Consolidated-representation rules published from Scovant Cloud
(experimental): a homepage requested with `Prefer: return=consolidated`.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. Both fire
only when the site claims to honour the preference.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule


def _preference_measured(domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
    verdict = probe_measured(domain, ctx, "machine_rep")
    if verdict:
        return verdict
    assert domain is not None
    mr = (domain.get("machine_rep") or {})
    if not mr.get("attempted") or mr.get("status") is None:
        return OutcomeState.NOT_MEASURED
    if mr.get("status") != 200 or not mr.get("preference_applied"):
        return OutcomeState.NA
    return None


@register_rule
class MachineRepIndistinguishableFromHtml(CoreRule):
    code = "MACHINE-REP-004"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Consolidated representation preference applied but response is unchanged"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        # Content-Type level by design: the probe sends one Prefer-carrying
        # request and has no baseline response to diff a body against, so
        # "indistinguishable" means the Content-Type did not change. Any
        # Content-Type other than HTML (json, markdown, plain, xml, ...) is a
        # distinguishable representation.
        if not domain or "machine_rep" not in domain:
            return []
        mr = (domain.get("machine_rep") or {})
        if not mr.get("attempted") or mr.get("status") != 200:
            return []
        if not mr.get("preference_applied"):
            return []
        content_type = (mr.get("content_type") or "").lower()
        if content_type and "html" not in content_type:
            return []  # distinguishable representation — preference actually did something
        return [
            Finding(
                title="Consolidated representation preference applied but response is unchanged",
                description=(
                    "The homepage reported 'Preference-Applied: return=consolidated' for "
                    "a request with 'Prefer: return=consolidated', but the response's "
                    f"Content-Type ({content_type or '(none)'}) is indistinguishable from "
                    "the plain HTML page — the preference is claimed but not honored."
                ),
                remediation_hint=(
                    "Only send 'Preference-Applied: return=consolidated' when the "
                    "response actually differs from the default page (e.g. a "
                    "consolidated Markdown or JSON view) — claiming a preference was "
                    "applied without changing the response misleads agents that rely on "
                    "the header."
                ),
                example=(
                    "# Only claim Preference-Applied when the response actually changes\n"
                    "GET / HTTP/1.1\n"
                    "Prefer: return=consolidated\n\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: text/markdown\n"
                    "Preference-Applied: return=consolidated\n\n"
                    "# Example Co — consolidated view\n..."
                ),
                metadata={"content_type": content_type, "preference_applied": True},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _preference_measured(domain, ctx)


@register_rule
class MachineRepVaryMissingPrefer(CoreRule):
    code = "MACHINE-REP-005"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "low"
    title = "Consolidated representation preference applied but Vary omits Prefer"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain or "machine_rep" not in domain:
            return []
        mr = (domain.get("machine_rep") or {})
        if not mr.get("attempted") or mr.get("status") != 200:
            return []
        if not mr.get("preference_applied"):
            return []
        vary = (mr.get("vary") or "").lower()
        if "prefer" in vary:
            return []
        return [
            Finding(
                title="Consolidated representation preference applied but Vary omits Prefer",
                description=(
                    "The homepage honors 'Prefer: return=consolidated' "
                    "(Preference-Applied was set), but its Vary header "
                    f"({mr.get('vary') or '(none)'}) does not include 'Prefer' — caches "
                    "may serve the consolidated response to a client that never asked "
                    "for it, or vice versa."
                ),
                remediation_hint=(
                    "Add 'Vary: Prefer' (alongside any other Vary values already "
                    "present) to the response whenever the Prefer header changes what's "
                    "returned."
                ),
                example=(
                    "# Declare that the response varies by Prefer\n"
                    "HTTP/1.1 200 OK\n"
                    "Content-Type: text/markdown\n"
                    "Preference-Applied: return=consolidated\n"
                    "Vary: Prefer"
                ),
                metadata={"vary": mr.get("vary")},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _preference_measured(domain, ctx)
