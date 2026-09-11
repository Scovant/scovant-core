"""Agent instruction reference integrity.

The scoring principle this implements: the mere PRESENCE of a
machine-readable instruction surface (llms.txt, MCP/WebMCP tool
descriptions, agent setup docs) is not a positive readiness signal.
Instructions that name packages which do not exist, domains nobody owns, or
that tell an agent to pipe a remote script into a shell are a supply-chain
surface — measurably worse than having no instructions at all, because an
agent will act on them.

This module is the PURE half — extraction and classification, no network, no
I/O — so the interesting logic is fully testable offline. Resolution lives in
`scovant_core.analysis.integrity_probe`, and every rule keyed on this data
fires only on checked-and-negative evidence: "we did not look" is never
"broken".
"""
from __future__ import annotations

import re
from typing import Any

# Hard cap on references carried per scan. A hostile or sprawling document
# must not inflate the snapshot, the issue metadata, or the lookup budget.
MAX_REFERENCES = 40

# Hosts that are never worth a lookup: ubiquitous infrastructure whose
# existence is not in question, plus the scanned site's own domain. Spending
# the budget here would crowd out the third-party references that actually
# carry supply-chain risk.
_INFRASTRUCTURE_DOMAINS: frozenset[str] = frozenset({
    "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "www.npmjs.com",
    "pypi.org", "registry.npmjs.org", "docs.python.org", "python.org",
    "developer.mozilla.org", "w3.org", "www.w3.org", "schema.org",
    "rfc-editor.org", "www.rfc-editor.org", "ietf.org", "datatracker.ietf.org",
    "creativecommons.org", "json-schema.org", "modelcontextprotocol.io",
    "localhost",
})

# RFC 2606 / RFC 6761 reserved names and their SUBDOMAINS. Documentation is
# full of `get.example.org` and `api.example.com` placeholders that will never
# resolve BY DESIGN; reporting them as dead references would make the whole
# family untrustworthy on exactly the docs it is meant to check. Matched by
# suffix, not by exact host — the live probe caught `get.example.org` slipping
# through an exact-match-only filter.
_RESERVED_SUFFIXES: tuple[str, ...] = (
    "example.com", "example.org", "example.net",
    ".example", ".invalid", ".test", ".localhost", ".local",
)


def _is_reserved(host: str) -> bool:
    return any(
        host == suffix or host.endswith("." + suffix) if not suffix.startswith(".")
        else host.endswith(suffix)
        for suffix in _RESERVED_SUFFIXES
    )

# npm: optional @scope/, then the package; pip: PEP 508-ish distribution name.
_NPM_INSTALL = re.compile(
    r"\bnpm\s+(?:install|i|add)\s+(?:-[\w-]+\s+)*(?P<name>@?[\w.-]+(?:/[\w.-]+)?)", re.I)
_YARN_INSTALL = re.compile(
    r"\b(?:yarn|pnpm)\s+add\s+(?:-[\w-]+\s+)*(?P<name>@?[\w.-]+(?:/[\w.-]+)?)", re.I)
_PIP_INSTALL = re.compile(
    r"\b(?:pip3?|uv\s+pip|python3?\s+-m\s+pip)\s+install\s+(?:-[\w-]+\s+)*(?P<name>[A-Za-z][\w.-]*)", re.I)

# A bare distribution-looking token mentioned in prose (no install verb).
_PROSE_PACKAGE = re.compile(r"\b(?P<name>[a-z][a-z0-9]*(?:-[a-z0-9]+){1,4})\b")

_URL = re.compile(r"https?://(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[/\s)\]]|$)")
_BARE_DOMAIN = re.compile(
    r"(?<![\w@./-])(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"(?:com|org|net|io|dev|ai|app|co|sh|cloud|run|xyz))(?![\w/-])")

# Unauthenticated remote execution: fetch a remote script and hand it
# straight to an interpreter. Lexical only — we never execute anything.
_REMOTE_EXEC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b", re.I),
    re.compile(r"\bwget\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b", re.I),
    re.compile(r"\b(?:irm|invoke-webrequest)\b[^\n|]*\|\s*(?:iex|invoke-expression)\b", re.I),
    re.compile(r"\bcurl\b[^\n|]*\|\s*(?:sudo\s+)?python3?\b", re.I),
)


def find_remote_exec_instructions(text: str) -> list[str]:
    """Return the matched fragments instructing unauthenticated remote execution.

    Purely lexical and network-free. This is the one check in the family that
    needs no resolution at all: `curl … | sh` in agent-facing documentation is
    a finding on its own terms, because an agent that follows the instructions
    executes code chosen by whoever controls that URL.
    """
    if not text:
        return []
    hits: list[str] = []
    for pattern in _REMOTE_EXEC_PATTERNS:
        for m in pattern.finditer(text):
            frag = " ".join(m.group(0).split())[:160]
            if frag not in hits:
                hits.append(frag)
    return hits[:5]


def _norm_host(host: str) -> str:
    return host.strip().strip(".").lower()


def extract_references(text: str, self_domain: str | None = None) -> list[dict[str, Any]]:
    """Extract third-party references an agent might act on.

    Each reference is ``{kind, name, in_install_command}`` where kind is
    ``package_npm`` | ``package_pypi`` | ``domain``.

    ``in_install_command`` is the load-bearing distinction: a package merely
    NAMED in prose that does not exist is stale documentation, while the same
    name inside `npm install …` is a slot an attacker can register and have
    agents install — so the two are reported at different severities.

    Deduplicated, capped at :data:`MAX_REFERENCES`, and never raises.
    """
    if not text or not text.strip():
        return []

    self_host = _norm_host(self_domain or "")
    if self_host.startswith("www."):
        self_host = self_host[4:]

    seen: set[tuple[str, str]] = set()
    refs: list[dict[str, Any]] = []

    def add(kind: str, name: str, install: bool) -> None:
        name = name.strip().strip(".,;:)")
        if not name:
            return
        key = (kind, name.lower())
        if key in seen:
            # An install-context sighting upgrades an earlier prose sighting:
            # the exploitable framing wins.
            if install:
                for r in refs:
                    if (r["kind"], r["name"].lower()) == key:
                        r["in_install_command"] = True
            return
        seen.add(key)
        refs.append({"kind": kind, "name": name, "in_install_command": install})

    for pattern, kind in ((_NPM_INSTALL, "package_npm"), (_YARN_INSTALL, "package_npm"),
                          (_PIP_INSTALL, "package_pypi")):
        for m in pattern.finditer(text):
            add(kind, m.group("name"), True)

    installed_names = {r["name"].lower() for r in refs}

    def _wanted(host: str) -> bool:
        if not host or host in _INFRASTRUCTURE_DOMAINS or _is_reserved(host):
            return False
        return not (self_host and (host == self_host or host.endswith("." + self_host)))

    for pattern in (_URL, _BARE_DOMAIN):
        for m in pattern.finditer(text):
            host = _norm_host(m.group("host"))
            if _wanted(host):
                add("domain", host, False)

    # Prose package mentions are only recorded for names already seen in an
    # install command elsewhere in the document — otherwise every hyphenated
    # English phrase would become a "package reference" and the budget would
    # be spent on noise.
    for m in _PROSE_PACKAGE.finditer(text):
        name = m.group("name").lower()
        if name in installed_names:
            continue
        # not recorded: see docstring — deliberately conservative

    return refs[:MAX_REFERENCES]


def classify_reference(
    ref: dict[str, Any], resolution: dict[str, Any] | None
) -> str:
    """Classify one reference against its resolution result.

    ``VALID`` (exists), ``UNCLAIMED`` (a package registry gave a definitive
    "no such package" — the name is registrable by anyone, i.e. a dependency
    -confusion slot), ``BROKEN`` (a domain that does not resolve), or
    ``UNCHECKED``.

    ``UNCHECKED`` covers both "we never looked" and "the lookup failed": a
    registry timeout must never be published as a broken dependency. Only a
    definitive negative produces a finding.
    """
    if not resolution or not resolution.get("checked"):
        return "UNCHECKED"
    if resolution.get("exists"):
        return "VALID"
    return "UNCLAIMED" if str(ref.get("kind", "")).startswith("package_") else "BROKEN"
