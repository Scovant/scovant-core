"""CORE-ACCESS-011 (experimental): llms.txt utility — presence is not utility."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from scovant_core.checks.base import CoreCheck
from scovant_core.models import Category, CheckStatus, Severity

_POLICY_RE = re.compile(r"^\s*(user-agent|disallow|allow|crawl-delay)\s*:", re.I | re.M)
_POLICY_PHRASE_RE = re.compile(r"\b(do not (train|crawl|index)|no[- ]?train(ing)?|noindex)\b", re.I)
_TEMPLATE_PHRASES = ("Description of the project", "example.com", "Title of the project")
_OPTIONAL_HEADING_RE = re.compile(r"^##\s*Optional\s*$", re.M)
_HEADING_RE = re.compile(r"^##\s", re.M)
_SUMMARY_LINE_RE = re.compile(r"^>\s*(.*)$", re.M)


def _optional_section_has_no_links(raw: str) -> bool:
    """True iff an ``## Optional`` heading is present AND the text between it
    and the next ``##`` heading (or end of file) contains no Markdown link
    (``](``) — an ``## Optional`` section is conventionally a list of
    supplementary links; one with none is a template leftover, not a real
    section."""
    m = _OPTIONAL_HEADING_RE.search(raw)
    if not m:
        return False
    rest = raw[m.end():]
    nxt = _HEADING_RE.search(rest)
    section = rest[: nxt.start()] if nxt else rest
    return "](" not in section


def llms_signals(raw: str, urls: list[str], origin: str, robots_ai_declared: bool, content_signal_declared: bool) -> dict:
    host = (urlsplit(origin).hostname or "").lower()
    same = [u for u in urls if (urlsplit(u).hostname or "").lower() == host]
    policy_text = bool(_POLICY_RE.search(raw) or _POLICY_PHRASE_RE.search(raw))
    optional_empty = _optional_section_has_no_links(raw)
    m = _SUMMARY_LINE_RE.search(raw)
    short_summary = bool(m) and len(m.group(1).strip()) < 20
    placeholders = any(p in raw for p in _TEMPLATE_PHRASES)
    return {
        "links": len(urls), "same_origin_links": len(same),
        "no_useful_references": len(same) == 0,
        "policy_misuse": policy_text and not (robots_ai_declared or content_signal_declared),
        "generic_template": sum((optional_empty, short_summary, placeholders)) >= 2,
    }


class LlmsTxtUtility(CoreCheck):
    id = "CORE-ACCESS-011"
    title = "llms.txt utility"
    category = Category.ACCESS
    weight = 1
    severity_on_fail = Severity.INFO
    experimental = True
    references = ("https://llmstxt.org/",)
    why_it_matters = "An llms.txt that links nothing useful, states crawler policy no crawler enforces, or is an untouched template gives agents nothing — adoption is not utility."
    limitations = (
        "Heuristics over the file text; a WARN is a prompt to review the file, not a defect. "
        "A bare `Disallow: /` in the robots.txt general (default) group does not itself count as an AI-crawler "
        "declaration for policy_misuse — only an allow/disallow entry declared under one of the registered AI "
        "agent tokens counts; a `Content-Signal:` directive can independently satisfy the same check. "
        "Experimental: never scored."
    )
    cloud_extension = "Scovant Cloud compares llms.txt against what agents actually fetch."

    def evaluate(self, store, ctx):
        llms = store.get("llms")
        parsed = llms["parsed"]
        if not parsed.get("exists"):
            return self.na("No llms.txt is published.", {"exists": False})
        robots = store.get("robots_txt")
        # Deliberately excludes "general" (robots.txt's default `User-agent: *`
        # group): a bare `Disallow: /` there is a general crawl policy, not an
        # AI-specific one, so it must not by itself satisfy `ai_declared` and
        # suppress `policy_misuse` below — only a real allow/disallow entry
        # under one of the registered AI agent tokens' own groups counts.
        ai_declared = any((robots["parsed"].get(k) or {}).get("allow") or (robots["parsed"].get(k) or {}).get("disallow")
                          for k in robots["parsed"] if k not in ("general", "sitemaps"))
        cs_declared = bool((robots.get("content_signals") or {}).get("declared"))
        s = llms_signals(parsed.get("raw_content", ""), parsed.get("urls", []), ctx.origin or "", ai_declared, cs_declared)
        flags = [k for k in ("no_useful_references", "policy_misuse", "generic_template") if s[k]]
        if flags:
            return self.result(CheckStatus.WARN, "llms.txt shows " + ", ".join(f.replace("_", " ") for f in flags) + ".", evidence=s,
                               remediation="Link the pages agents should read (same origin), state crawler policy in robots.txt/Content-Signal rather than llms.txt, and replace template text.")
        return self.result(CheckStatus.PASS, "llms.txt links useful same-origin pages and carries no misplaced policy or template text.", evidence=s)
