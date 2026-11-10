"""Crawler-policy rules published from Scovant Cloud: what a site's
robots.txt declares for known AI user-agents.

`AI_CRAWLER_BLOCKED` reads the per-agent robots.txt groups;
`AI-BOT-POLICY-001` reads the declared AI-crawler policy (the robots.txt
verdict at "/" per known AI user-agent token, with its intent). The
findings' text and metadata are the ones Scovant Cloud has always reported
for these codes; `measure` says when silence is a pass.
"""
from __future__ import annotations

from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule

# Public default (versioned with the rule): the crawler tokens whose root
# Disallow makes AI_CRAWLER_BLOCKED fire.
AI_CRAWLERS: tuple[str, ...] = ("GPTBot", "ClaudeBot", "Google-Extended", "PerplexityBot")
# Public default: how many blocked tokens one AI-BOT-POLICY-001 finding names.
EXAMPLE_CAP = 5


@register_rule
class AiCrawlerBlocked(CoreRule):
    code = "AI_CRAWLER_BLOCKED"
    since = "0.8.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "critical"
    title = "AI crawlers blocked in robots.txt"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        robots = (domain.get("robots") or {})
        blocked_agents = [
            agent
            for agent in AI_CRAWLERS
            if "/" in (robots.get(agent) or {}).get("disallow", [])
        ]
        if blocked_agents:
            return [
                Finding(
                    title="AI crawlers blocked in robots.txt",
                    description=(
                        f"robots.txt disallows root path for: {', '.join(blocked_agents)}."
                    ),
                    remediation_hint=(
                        "Edit your robots.txt to explicitly allow AI crawler user-agents. For each "
                        "blocked agent, add a rule like:\n\n"
                        "User-agent: GPTBot\nAllow: /\n\n"
                        "User-agent: ClaudeBot\nAllow: /\n\n"
                        "If you want to allow all AI crawlers at once, remove any 'Disallow: /' "
                        "rules that target them. Blocking AI crawlers means your site content will "
                        "not be included in AI training data or used by AI agents when answering "
                        "user queries — this significantly reduces your visibility in AI-powered "
                        "search and shopping experiences."
                    ),
                    example=(
                        "# robots.txt — allow AI crawlers explicitly\n"
                        "User-agent: GPTBot\n"
                        "Allow: /\n\n"
                        "User-agent: ClaudeBot\n"
                        "Allow: /\n\n"
                        "User-agent: Google-Extended\n"
                        "Allow: /"
                    ),
                    metadata={"blocked_agents": blocked_agents},
                )
            ]
        return []

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return probe_measured(domain, ctx, "robots")


def _declared_policy(domain: dict | None) -> dict | None:
    """domain["ai_bot_policy"] iff it carries declared data."""
    if not domain:
        return None
    block = domain.get("ai_bot_policy")
    if not block or not isinstance(block.get("declared"), dict) or not block["declared"]:
        return None
    return block


@register_rule
class AiBotPolicyDeclared(CoreRule):
    """AI-BOT-POLICY-001 — an informational capture of the declared policy,
    not a defect judgement (a diagnostic marker in Scovant Cloud's scores)."""

    code = "AI-BOT-POLICY-001"

    since = "0.8.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "info"
    title = "Declared AI-crawler policy"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        block = _declared_policy(domain)
        if block is None or not block.get("declared_any"):
            return []
        declared = block["declared"]
        blocked = sorted(t for t, d in declared.items() if not d.get("allowed"))
        by_intent: dict[str, list[str]] = {}
        for t in blocked:
            by_intent.setdefault(declared[t].get("intent", "unknown"), []).append(t)
        if blocked:
            desc = (
                "This site's robots.txt restricts "
                f"{len(blocked)} known AI user-agent(s) "
                f"({', '.join(blocked[:EXAMPLE_CAP])}"
                f"{', …' if len(blocked) > EXAMPLE_CAP else ''}). Disallowing "
                "search-intent crawlers (e.g. OAI-SearchBot, PerplexityBot) "
                "removes the site from the indexes those answer engines cite; "
                "agent-intent fetchers being blocked stops live user-triggered "
                "retrieval. This is an informational capture of declared "
                "preference, not a defect judgement."
            )
        else:
            desc = (
                "This site declares an AI-crawler policy in robots.txt and "
                "allows all known AI user-agents at the site root. Captured "
                "for agent-discoverability visibility (informational)."
            )
        return [
            Finding(
                title="Declared AI-crawler policy",
                description=desc,
                remediation_hint=(
                    "Confirm the robots.txt directives match your intent for "
                    "search-index crawlers, live agent fetchers, and training "
                    "crawlers separately — blocking a search-intent bot removes "
                    "you from that engine's citable index."
                ),
                example="\n".join(
                    f"{intent}: {', '.join(sorted(toks))}"
                    for intent, toks in sorted(by_intent.items())
                ) or "all known AI user-agents allowed at /",
                metadata={
                    "blocked_tokens": blocked[:EXAMPLE_CAP],
                    "blocked_by_intent": {k: v[:EXAMPLE_CAP] for k, v in by_intent.items()},
                    "blocked_count": len(blocked),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        # The declared half is parsed from robots.txt: a failed robots fetch
        # leaves every token "allowed", which is not the site's policy.
        verdict = probe_measured(domain, ctx, "ai_bot_policy", "robots")
        if verdict:
            return verdict
        assert domain is not None
        declared = (domain.get("ai_bot_policy") or {}).get("declared")
        if not isinstance(declared, dict) or not declared:
            return OutcomeState.NOT_MEASURED
        return None if (domain.get("ai_bot_policy") or {}).get("declared_any") else OutcomeState.NA


def _declared_verdict(domain: dict, token: str) -> bool | None:
    """The robots verdict at "/" for `token`, only when robots.txt names it
    with a group of its own (a token that merely inherits `*` is not a
    declaration)."""
    group = (domain.get("robots") or {}).get(token)
    if not isinstance(group, dict) or not (group.get("allow") or group.get("disallow")):
        return None
    declared = ((domain.get("ai_bot_policy") or {}).get("declared") or {}).get(token)
    if not isinstance(declared, dict) or not isinstance(declared.get("allowed"), bool):
        return None
    return declared["allowed"]


def _usage(domain: dict | None) -> dict | None:
    if not domain:
        return None
    usage = (domain.get("ai_bot_policy") or {}).get("ai_training_usage")
    return usage if isinstance(usage, dict) and usage.get("declared") else None


@register_rule
class AiTrainingUsageConflict(CoreRule):
    """AI-BOT-POLICY-006 — the draft `__usage_ai-training` group contradicts the
    site's other training declarations. Unscored: it names the two sources and
    judges neither (the usage vocabulary is an unfinished draft)."""

    code = "AI-BOT-POLICY-006"
    since = "0.25.0"
    maturity = "experimental"
    rule_version = "1.0"
    scope = "domain"
    category = "discoverability"
    severity = "info"
    title = "AI-training usage group conflicts with another declaration"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        usage = _usage(domain)
        if domain is None or usage is None or not isinstance(usage.get("allowed"), bool):
            return []
        allowed = usage["allowed"]
        conflicts: list[dict] = []
        ge = _declared_verdict(domain, "Google-Extended")
        if ge is not None and ge != allowed:
            conflicts.append({"source": "Google-Extended robots group", "allowed": ge})
        sig = ((domain.get("content_signals") or {}).get("dimensions") or {}).get("ai-train")
        if sig in ("yes", "no") and (sig == "yes") != allowed:
            conflicts.append({"source": "Content-Signal ai-train", "allowed": sig == "yes"})
        if not conflicts:
            return []
        word = {True: "allows", False: "disallows"}
        return [
            Finding(
                title="AI-training usage group conflicts with another declaration",
                description=(
                    f"robots.txt's draft __usage_ai-training group {word[allowed]} AI training, "
                    "but "
                    + "; ".join(f"{c['source']} {word[c['allowed']]} it" for c in conflicts)
                    + ". Two declarations of the same preference disagree, so a crawler "
                    "may follow either. Informational: the usage vocabulary is a draft."
                ),
                remediation_hint=(
                    "Make the declarations agree: state the AI-training preference the same "
                    "way in the __usage_ai-training group, the Google-Extended group and the "
                    "Content-Signal ai-train value, or drop the one you do not mean."
                ),
                example=(
                    "User-agent: __usage_ai-training\nDisallow: /\n\n"
                    "User-agent: Google-Extended\nDisallow: /"
                ),
                metadata={
                    "usage_allowed": allowed,
                    "conflicting_sources": [c["source"] for c in conflicts],
                    "conflicts": conflicts,
                    "draft": True,
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = probe_measured(domain, ctx, "robots")
        if verdict is not None:
            return verdict
        if not domain or not isinstance(domain.get("ai_bot_policy"), dict):
            return OutcomeState.NOT_MEASURED
        return None if _usage(domain) is not None else OutcomeState.NA
