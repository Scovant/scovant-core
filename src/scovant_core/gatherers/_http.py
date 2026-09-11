"""Shared HTTP probe helpers used by every network gatherer in this package.

`_PROBE_TIMEOUT` bounds each individual request a gatherer issues, so a
domain-level probe sequence of several sequential GETs stays well inside a
caller's own overall time budget instead of inheriting a much larger
per-request default. `_PROBE_BODY_CAP` bounds how much of a response body a
probe reads before giving up on parsing it, so a hostile or misbehaving
server can't force unbounded memory use.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Protocol

from scovant_core.compat import SoftTimeLimitExceeded
from scovant_core.parsers.mcp import _MCP_RESPONSE_HEADER_KEYS

# Mirrors the response-body cap used elsewhere in the crawl pipeline.
_PROBE_BODY_CAP = 512 * 1024

# A domain-level probe sequence issues many sequential GETs on top of the
# original page fetch; bounding each request keeps the whole sequence well
# inside the caller's own soft time limit instead of inheriting a much
# larger connection/read timeout meant for a single full-page fetch.
_PROBE_TIMEOUT = 5.0


class _ProbeResponse(Protocol):
    """The minimal response shape these probe helpers read — satisfied by
    both a real `httpx.Response` and `security.client._ProbeResponse` (the
    guarded-client adapter's own response wrapper). Declared as read-only
    properties (not plain attributes) so a real `httpx.Response` — whose
    `.text`/`.status_code` are themselves read-only properties — structurally
    matches; a plain-attribute Protocol member requires invariance and would
    reject it."""

    @property
    def status_code(self) -> int: ...
    @property
    def text(self) -> str: ...
    @property
    def headers(self) -> Mapping[str, str]: ...


class _ProbeClient(Protocol):
    """The minimal client shape these probe helpers call — satisfied by both
    a real `httpx.Client` and `security.client._FetchAdapter`. Several
    gatherers deliberately pass the guarded client's probe adapter (redirect
    -following, size-capped, deadline-aware) instead of a bare `httpx.Client`
    — this typing makes that legitimate duck-typing explicit."""

    def get(self, url: str, *, timeout: float | None = ...) -> _ProbeResponse: ...


def _capped_body(text: str, cap: int = _PROBE_BODY_CAP) -> tuple[str, bool]:
    """Slice `text` to `cap` chars and report whether anything was cut off.

    Several probes in this package read through a bare `httpx.Client` (or
    the guarded client's `_ProbeResponse` adapter, whose `.text` has
    already lost `security.client.FetchResult.truncated`) rather than
    `SecureClient.fetch` directly, so they have no fetch-layer truncation
    signal to read. `_PROBE_BODY_CAP` is itself a read boundary for exactly
    the same reason the fetch layer's own cap exists — bounding memory use
    against a hostile/oversized body — so a body that exceeds it is the
    same category of degraded evidence, one layer up: `"truncated": True`
    for any caller that slices through this helper instead of its own
    `text[:_PROBE_BODY_CAP]`.
    """
    if len(text) <= cap:
        return text, False
    return text[:cap], True


def _probe_json(client: _ProbeClient, url: str) -> tuple[Any, bool]:
    """GET url; return `(parsed, truncated)`.

    `parsed` is the body as JSON (dict/list) on 200 + valid JSON, else
    `None` — but a `None` here is NOT, on its own, evidence that the
    document is absent or invalid: `truncated` distinguishes "the body
    genuinely isn't valid JSON" (`truncated=False`) from "the body was cut
    off at `_PROBE_BODY_CAP` before we could tell" (`truncated=True`).
    Collapsing both to a bare `None` was the original defect this
    signature replaces — a caller that only checked "is `parsed` `None`"
    reported a truncated-but-genuinely-present document as absent/invalid,
    publishing our own read limit as a fact about the site. Every caller
    MUST check `truncated` before treating a `None` `parsed` as a
    confirmed negative; when truncated, the honest caller-side outcome is
    "could not determine" (e.g. `exists: None`), never `False`.
    """
    try:
        resp = client.get(url, timeout=_PROBE_TIMEOUT)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        return None, False
    if resp.status_code != 200:
        return None, False
    body, was_truncated = _capped_body(resp.text)
    truncated = was_truncated and body != ""
    try:
        return json.loads(body), truncated
    except (json.JSONDecodeError, ValueError):
        return None, truncated


def _probe_text_exists(resp: _ProbeResponse) -> bool:
    """Text-probe existence check: 200 + non-HTML content type + non-empty body."""
    ctype = resp.headers.get("content-type", "")
    return (
        resp.status_code == 200
        and "text/html" not in ctype
        and bool(resp.text[:_PROBE_BODY_CAP].strip())
    )


def _mcp_response_headers(resp: _ProbeResponse) -> dict[str, str]:
    """Lower-cased subset of MCP-relevant response headers (httpx headers are
    case-insensitive on lookup, so this normalizes regardless of the
    server's casing)."""
    return {
        key: resp.headers[key] for key in _MCP_RESPONSE_HEADER_KEYS if key in resp.headers
    }
