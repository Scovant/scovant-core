"""Instruction-supply rules published from Scovant Cloud: whether what a
site's machine-readable instructions (llms.txt, MCP tool descriptions) point
at is real, and whether they tell an agent to run a remote script unseen.

An agent does not merely read these instructions, it acts on them.
Instructions naming a package that does not exist hand an attacker a
registrable name; instructions that pipe a remote script into a shell hand
whoever controls that URL arbitrary execution on the agent's host. An unsafe
instruction surface is therefore worse than none.

Every rule reads `domain["instruction_integrity"]`
(`analysis.integrity_probe.check_instruction_integrity`) and fires ONLY on
checked-and-negative evidence: an unchecked reference, an exhausted lookup
budget or a registry timeout produces nothing. The findings' text and
metadata are the ones Scovant Cloud has always reported for these codes;
`measure` says when silence is a pass.
"""
from __future__ import annotations

from typing import Any

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule

NA = OutcomeState.NA
NM = OutcomeState.NOT_MEASURED

_EXAMPLE_CAP = 5


def _block(domain: dict | None) -> dict[str, Any] | None:
    """The probe block, or None when this scan has nothing to say."""
    if not domain:
        return None
    block = domain.get("instruction_integrity")
    if not isinstance(block, dict) or not block.get("attempted"):
        return None
    return block


def _refs(block: dict[str, Any]) -> list[dict[str, Any]]:
    refs = block.get("references")
    return [r for r in refs if isinstance(r, dict)] if isinstance(refs, list) else []


def _instructions_measured(domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
    verdict = probe_measured(domain, ctx, "instruction_integrity")
    if verdict:
        return verdict
    if ctx.defaulted is not None and "llms_txt" in ctx.defaulted:
        return NM  # the probe read the MCP text only; llms.txt references were never checked
    assert domain is not None
    # not attempted and not defaulted: there was no instruction text to check
    return None if domain["instruction_integrity"].get("attempted") else NA


class _InstructionRule(CoreRule):
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "trust"

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _instructions_measured(domain, ctx)


@register_rule
class LlmsSupplyPackageResolves(_InstructionRule):
    """LLMS-SUPPLY-001 — a package named in the instructions does not exist.

    Scoped to packages merely NAMED in the documentation. The exploitable
    subset — a missing package inside an actual install command — is
    reported once, and only, by LLMS-SUPPLY-008 at high severity, so one
    fact never produces two findings at two severities.
    """

    code = "LLMS-SUPPLY-001"
    severity = "medium"
    title = "Referenced package does not exist"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        block = _block(domain)
        if block is None:
            return []
        bad = [r for r in _refs(block)
               if r.get("status") == "UNCLAIMED" and not r.get("in_install_command")]
        if not bad:
            return []
        names = [str(r.get("name")) for r in bad]
        return [
            Finding(
                title="Referenced package does not exist",
                description=(
                    f"{len(bad)} package name(s) referenced in this site's "
                    "machine-readable instructions could not be found in their "
                    "registry. An agent following the documentation would fail "
                    "— and the unregistered name can be claimed by anyone."
                ),
                example="pip install acme-agent   # 404 from the package registry",
                remediation_hint=(
                    "Correct or remove the package names in your agent-facing "
                    "documentation, and pin the ones that are real. A name that "
                    "does not exist today can be registered by someone else "
                    "tomorrow, at which point your own docs point agents at it."
                ),
                metadata={"count": len(bad), "examples": names[:_EXAMPLE_CAP]},
            )
        ]


@register_rule
class LlmsSupplyDomainResolves(_InstructionRule):
    """LLMS-SUPPLY-002 — a domain named in the instructions does not resolve."""

    code = "LLMS-SUPPLY-002"
    severity = "medium"
    title = "Referenced domain does not resolve"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        block = _block(domain)
        if block is None:
            return []
        bad = [r for r in _refs(block)
               if r.get("status") == "BROKEN" and r.get("kind") == "domain"
               and not r.get("in_install_command")]
        if not bad:
            return []
        names = [str(r.get("name")) for r in bad]
        return [
            Finding(
                title="Referenced domain does not resolve",
                description=(
                    f"{len(bad)} domain(s) referenced in this site's "
                    "machine-readable instructions do not resolve in DNS. An "
                    "agent following those links reaches nothing, and an "
                    "unregistered domain in published instructions is a slot "
                    "someone else can take over."
                ),
                example="https://docs.acme-corp.io/agents   # NXDOMAIN",
                remediation_hint=(
                    "Update or remove the dead references. If a domain you "
                    "used to own appears here, re-register it or purge every "
                    "mention: agent-facing docs are followed automatically, "
                    "without a human to notice the link is dead."
                ),
                metadata={"count": len(bad), "examples": names[:_EXAMPLE_CAP]},
            )
        ]


@register_rule
class LlmsSupplyRemoteExec(_InstructionRule):
    """LLMS-SUPPLY-006 — the instructions pipe a remote script into a shell.

    Purely lexical: no resolution is needed, because `curl … | sh` in
    agent-facing documentation is a finding on its own terms.
    """

    code = "LLMS-SUPPLY-006"
    severity = "high"
    title = "Instructions pipe a remote script into a shell"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        block = _block(domain)
        if block is None:
            return []
        hits = [h for h in (block.get("remote_exec") or []) if isinstance(h, str)]
        if not hits:
            return []
        return [
            Finding(
                title="Instructions pipe a remote script into a shell",
                description=(
                    "The machine-readable instructions tell the reader to fetch "
                    "a remote script and execute it unauthenticated. A human "
                    "may skim the script first; an agent following the "
                    "documentation will not, so whoever controls that URL "
                    "controls what runs on the agent's host."
                ),
                example="curl -sSL https://get.acme.io/install.sh | sh",
                remediation_hint=(
                    "Publish a verifiable install path instead: a registry "
                    "package, a signed artifact, or a download plus a "
                    "documented checksum/signature check, so the instruction "
                    "does not require blind trust in whatever the URL returns."
                ),
                metadata={"count": len(hits), "examples": hits[:_EXAMPLE_CAP]},
            )
        ]


@register_rule
class LlmsSupplyClaimableReference(_InstructionRule):
    """LLMS-SUPPLY-008 — an install command names something claimable.

    The exploitable subset of -001/-002: the missing reference is not merely
    mentioned, it sits inside an install or execution command, so an agent
    following the documentation would actually fetch it. Whoever registers
    that name gets code onto every host that follows these instructions.
    """

    code = "LLMS-SUPPLY-008"
    severity = "high"
    title = "Install instructions name a claimable package or domain"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        block = _block(domain)
        if block is None:
            return []
        bad = [r for r in _refs(block)
               if r.get("in_install_command")
               and r.get("status") in ("UNCLAIMED", "BROKEN")]
        if not bad:
            return []
        names = [f"{r.get('kind')}:{r.get('name')}" for r in bad]
        return [
            Finding(
                title="Install instructions name a claimable package or domain",
                description=(
                    f"{len(bad)} reference(s) inside install or execution "
                    "commands in this site's machine-readable instructions do "
                    "not exist. Because they are instructions an agent "
                    "executes rather than prose it reads, anyone who registers "
                    "the name gets their code onto every host that follows "
                    "this documentation."
                ),
                example="npm install @acme/agent-sdk   # unregistered: anyone can claim it",
                remediation_hint=(
                    "Treat this as a live supply-chain exposure: correct the "
                    "name, publish the package under it yourself, or remove "
                    "the command. Then pin versions (and digests where the "
                    "ecosystem supports them) so a future takeover of a "
                    "transitive name cannot reach agents through your docs."
                ),
                metadata={"count": len(bad), "examples": names[:_EXAMPLE_CAP]},
            )
        ]
