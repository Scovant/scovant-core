"""Agent interface discovery-surface probe (agents.txt, ai-plugin, OpenAPI,
SKILL.md, A2A cards, agent-skills index, OAuth discovery). MCP is
deliberately excluded — it has its own probe module."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_TIMEOUT, _probe_json, _probe_text_exists, _ProbeClient
from .probe_tables import DISCOVERY_PROBES

_TEXT_CAP = 64 * 1024


def check_agent_discovery(
    client: _ProbeClient, domain: str, *, known: Mapping[str, bool] | None = None
) -> dict[str, Any]:
    """Probe every path in DISCOVERY_PROBES; a ``json``-kind entry is
    detected on 200 + parseable JSON, a ``text``-kind entry on 200 +
    non-HTML content type + non-empty body.

    ``known`` short-circuits any key already resolved by a document this
    scan already fetched for another purpose (e.g. the OpenAPI/OAuth
    gatherers) — that key is recorded as-is and never re-probed. Cloud
    never passes it, so its behaviour is unchanged.

    A ``json``-kind entry's ``exists`` is ``bool | None``: ``None`` means
    the candidate's body was cut off at the fetch cap before we could tell
    whether it parsed — "could not determine", never a claimed ``False``.
    Text-kind entries carry no such ambiguity (``_probe_text_exists`` only
    asks "is there SOME non-empty, non-HTML body", which a truncated read
    still answers honestly) — but EVERY surface, json or text or
    ``known``-seeded, still carries its own ``"truncated"`` key (always
    ``False`` for the latter two), so a caller can uniformly do
    ``any(s["truncated"] for s in surfaces.values())`` without a `KeyError`
    on a surface that happens to be text-kind or shared."""
    surfaces: dict[str, Any] = {}
    any_truncated = False
    for key, probe in DISCOVERY_PROBES.items():
        if known is not None and key in known:
            # Seeded from another gatherer's already-fetched record, never
            # probed here — nothing for THIS gatherer to have truncated, and
            # the source gatherer already carries its own "text" evidence
            # (this exact dict shape is pinned by test_hardening_followups.py,
            # so no "text" key is added here).
            surfaces[key] = {"exists": known[key], "source": "shared", "truncated": False}
            continue
        if probe["content"] == "json":
            data, truncated = _probe_json(client, f"{domain}{probe['path']}")
            any_truncated = any_truncated or truncated
            if data is not None:
                exists: bool | None = True
                text = json.dumps(data, ensure_ascii=False)[:_TEXT_CAP]
            elif truncated:
                exists = None  # cut off before we could tell — not a claimed absence
                text = ""
            else:
                exists = False
                text = ""
            surfaces[key] = {"exists": exists, "truncated": truncated, "text": text}
        else:  # text: 200 + non-HTML content type + non-empty body
            body_text = ""
            try:
                resp = client.get(f"{domain}{probe['path']}", timeout=_PROBE_TIMEOUT)
                exists = _probe_text_exists(resp)
                if exists:
                    body_text = resp.text[:_TEXT_CAP]
            except SoftTimeLimitExceeded:
                raise
            except Exception:
                exists = False
            # No ambiguity to report (see docstring) — always False, not
            # merely omitted, so every surface's shape is uniform.
            surfaces[key] = {"exists": exists, "truncated": False, "text": body_text}
    return {"any_found": any(s["exists"] for s in surfaces.values()), "surfaces": surfaces,
            "truncated": any_truncated}
