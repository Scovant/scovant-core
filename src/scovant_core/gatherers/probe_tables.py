"""Constant tables of well-known discovery and payment-challenge probe paths.

Each entry is a path (or header) an agent-facing protocol publishes for
discovery, together with what a positive detection looks like. Every path is
sourced from that protocol's own primary specification — never inferred or
guessed — so a scanner using these tables never asserts support for a
protocol it has not actually confirmed.

Payment-challenge protocols (`PAYMENT_PROBES`):
- `l402` — the L402 (formerly LSAT) HTTP 402 challenge scheme, registered
  under RFC 7235's `WWW-Authenticate` mechanism. A server SHOULD send both
  the legacy `LSAT` and current `L402` scheme names.
- `x402` — the x402 protocol's Bazaar catalog descriptor
  (`/.well-known/x402.json`) plus HTTP 402 responses on common API roots
  whose JSON body carries the spec-required `x402Version` field. A bare 402
  status alone is not x402 evidence, since other challenge protocols
  (including `l402`) and plain paywalls also answer 402.
- `acp` — a seller discovery document at `/.well-known/acp.json`.
- `mpp` — the `x-payment-info` OpenAPI extension, which may appear at any
  nesting level of `/openapi.json` since it is declared per-operation.

Agent/service discovery protocols (`DISCOVERY_PROBES`):
- `agents_txt` / `agents_json` — plain-text or JSON agent-facing manifests.
- `ai_plugin` — the `/.well-known/ai-plugin.json` plugin manifest.
- `openapi_root` / `openapi_well_known` — OpenAPI documents at the
  conventional root and well-known locations.
- `skill_md` — a `SKILL.md` capability description at the site root.
- `a2a_card` / `a2a_card_legacy` — the Agent-to-Agent protocol's agent card,
  at its current path (`/.well-known/agent-card.json`, since the reference
  SDK's v0.3.0) and its pre-v0.3.0 legacy path (`/.well-known/agent.json`),
  which SDK releases in that generation still commonly serve alongside the
  current one.
- `oauth_as` / `oauth_pr` — RFC 8414 OAuth authorization-server metadata and
  RFC 9728 protected-resource metadata.
- `agent_skills` / `agent_skills_legacy` — an Agent Skills capability index
  at its current and pre-v0.2.0 legacy well-known paths.
- `llms_full_txt` — an extended `llms-full.txt` companion to `llms.txt`.

A path that cannot be confirmed against its protocol's own primary
specification is left out of these tables rather than guessed; a protocol
whose discovery mechanism is still an unreleased proposal (not yet part of a
released spec version) is likewise omitted until it ships.
"""
from __future__ import annotations

# kind=well_known_json: GET path, exists iff 200 + parseable JSON object
#   (+ optional top-level json_marker key).
# kind=challenge_header: probe the homepage; detected iff the named response
#   header contains the marker (case-insensitive).
# kind=json_text_marker: GET path; detected iff 200 + parseable JSON + the
#   marker substring appears anywhere in the document (nested extensions).
# kind=x402: composite — Bazaar catalog descriptor (JSON object at
#   catalog_path) OR any status_path answering HTTP 402 whose JSON body
#   carries the top-level json_marker key.
PAYMENT_PROBES: dict[str, dict] = {
    "l402": {"kind": "challenge_header", "header": "www-authenticate", "marker": "l402"},
    "x402": {
        "kind": "x402",
        "catalog_path": "/.well-known/x402.json",
        "status_paths": ("/", "/api", "/api/v1"),
        "json_marker": "x402Version",
    },
    "acp": {"kind": "well_known_json", "path": "/.well-known/acp.json"},
    "mpp": {"kind": "json_text_marker", "path": "/openapi.json", "marker": "x-payment-info"},
}

DISCOVERY_PROBES: dict[str, dict] = {
    "agents_txt":         {"path": "/agents.txt", "content": "text"},
    "agents_json":        {"path": "/agents.json", "content": "json"},
    "ai_plugin":          {"path": "/.well-known/ai-plugin.json", "content": "json"},
    "openapi_root":       {"path": "/openapi.json", "content": "json"},
    "openapi_well_known": {"path": "/.well-known/openapi.json", "content": "json"},
    "skill_md":           {"path": "/SKILL.md", "content": "text"},
    "a2a_card":           {"path": "/.well-known/agent-card.json", "content": "json"},
    "a2a_card_legacy":    {"path": "/.well-known/agent.json", "content": "json"},
    "oauth_as":           {"path": "/.well-known/oauth-authorization-server", "content": "json"},
    "oauth_pr":           {"path": "/.well-known/oauth-protected-resource", "content": "json"},
    "agent_skills":        {"path": "/.well-known/agent-skills/index.json", "content": "json"},
    "agent_skills_legacy": {"path": "/.well-known/skills/index.json", "content": "json"},
    "llms_full_txt":       {"path": "/llms-full.txt", "content": "text"},
}
