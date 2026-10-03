"""Agent interface discovery-surface probe (agents.txt, ai-plugin, OpenAPI,
SKILL.md, A2A cards, agent-skills index, OAuth discovery). MCP is
deliberately excluded — it has its own probe module."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import (
    _PROBE_TIMEOUT,
    _probe_json_ex,
    _probe_text_exists,
    _ProbeClient,
    _transport_error,
)
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
    on a surface that happens to be text-kind or shared.

    ``fetch_status`` is ``"error"`` when no surface was found and at least
    one probed candidate never got an HTTP answer (absence is only
    established when every candidate answered), ``"not_attempted"`` when
    every surface came from ``known`` and nothing was fetched here, else
    ``"ok"``; ``error`` names the first such failure."""
    surfaces: dict[str, Any] = {}
    any_truncated = False
    attempted = False
    errors: list[str] = []
    for key, probe in DISCOVERY_PROBES.items():
        if known is not None and key in known:
            # Seeded from another gatherer's already-fetched record, never
            # probed here — nothing for THIS gatherer to have truncated, and
            # the source gatherer already carries its own "text" evidence
            # (this exact dict shape is pinned by test_hardening_followups.py,
            # so no "text" key is added here).
            surfaces[key] = {"exists": known[key], "source": "shared", "truncated": False}
            continue
        attempted = True
        if probe["content"] == "json":
            data, truncated, err = _probe_json_ex(client, f"{domain}{probe['path']}")
            if err is not None:
                errors.append(err)
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
            except SoftTimeLimitExceeded:
                raise
            except Exception as exc:
                errors.append(_transport_error(exc))
                exists = False
            else:
                try:
                    exists = _probe_text_exists(resp)
                    if exists:
                        body_text = resp.text[:_TEXT_CAP]
                except Exception:
                    exists = False
            # No ambiguity to report (see docstring) — always False, not
            # merely omitted, so every surface's shape is uniform.
            surfaces[key] = {"exists": exists, "truncated": False, "text": body_text}
    any_found = any(s["exists"] for s in surfaces.values())
    if not attempted:
        fetch_status, error = "not_attempted", None
    elif errors and not any_found:
        fetch_status, error = "error", errors[0]
    else:
        fetch_status, error = "ok", None
    return {"any_found": any_found, "surfaces": surfaces, "truncated": any_truncated,
            "fetch_status": fetch_status, "error": error}
