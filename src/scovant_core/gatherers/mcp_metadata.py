"""MCP server-card discovery probe."""
from __future__ import annotations

from typing import Any

from scovant_core.parsers.mcp import _MCP_SERVER_CARD_PATHS

from ._http import _probe_json, _ProbeClient


def probe_mcp_server_card(client: _ProbeClient, domain: str) -> dict[str, Any]:
    """Probe both candidate server-card paths.

    Returns `{"exists": bool | None, "truncated": bool}`:

    - `exists=True` on a real JSON object at EITHER path (a truncated read
      at the OTHER path doesn't change this — a confirmed positive beats an
      inconclusive read elsewhere).
    - `exists=False` only when EVERY path gave a definitive non-JSON/absent
      answer (no truncation anywhere in the sequence).
    - `exists=None` when no path confirmed presence AND at least one path's
      body was cut off at the fetch cap — "we could not tell", never a
      claimed absence. This replaces the previous plain `bool` return,
      which collapsed a truncated-but-possibly-present server card into the
      same `False` as a genuinely absent one.
    """
    any_truncated = False
    for path in _MCP_SERVER_CARD_PATHS:
        data, truncated = _probe_json(client, f"{domain}{path}")
        any_truncated = any_truncated or truncated
        if isinstance(data, dict):
            return {"exists": True, "truncated": truncated}
    return {"exists": None if any_truncated else False, "truncated": any_truncated}
