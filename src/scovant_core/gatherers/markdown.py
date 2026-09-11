"""Markdown-for-agents negotiation probe (Accept negotiation + .md mirror)."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from scovant_core.compat import SoftTimeLimitExceeded

from ._http import _PROBE_TIMEOUT, _probe_text_exists

if TYPE_CHECKING:
    import httpx


def _body_looks_markdown(body_prefix: str) -> bool:
    """PURE body heuristic — no Content-Type gate. True iff the first 1024
    chars of the body contain NEITHER ``<html`` NOR ``<!doctype``
    (case-insensitive) AND contain AT LEAST ONE of: a line starting ``# ``,
    or the substring ``](``.

    Deliberately decoupled from Content-Type: comparing "does the body look
    like Markdown" against "does the header claim Markdown" as two
    independent signals requires this heuristic to examine the body
    regardless of what the Content-Type header says — gating it on
    Content-Type (as the legacy ``_looks_markdown`` below does) makes one of
    the two mismatch directions (a markdown-looking body under a
    non-markdown Content-Type) mathematically unreachable, since a
    non-markdown Content-Type would short-circuit the heuristic to False
    before the body is ever examined.
    """
    prefix = body_prefix[:1024]
    lower_prefix = prefix.lower()
    if "<html" in lower_prefix or "<!doctype" in lower_prefix:
        return False
    if "](" in prefix:
        return True
    return any(line.startswith("# ") for line in prefix.splitlines())


def _looks_markdown(content_type: str | None, body_prefix: str) -> bool:
    """Cheap heuristic (pinned exactly for back-compat): does a response body
    look like actual Markdown, independent of whether its declared
    Content-Type says so?

    True iff content-type contains "markdown" or "text/plain" AND the first
    1024 chars of the body contain NEITHER ``<html`` NOR ``<!doctype``
    (case-insensitive) AND contain AT LEAST ONE of: a line starting ``# ``,
    or the substring ``](``.

    KEPT EXACTLY AS-IS for back-compat (other consumers/tests read this key
    unchanged) — content-type-gated, so it can only ever confirm a claim the
    header already made. New code that needs the independent body signal
    should use ``_body_looks_markdown`` above instead.
    """
    ctype = (content_type or "").lower()
    if "markdown" not in ctype and "text/plain" not in ctype:
        return False
    return _body_looks_markdown(body_prefix)


def check_markdown_negotiation(client: httpx.Client, domain: str) -> dict[str, Any]:
    """Homepage-only Markdown-for-agents check: Accept negotiation + .md mirror.

    The ``negotiation``/``mirror``/``markdown_tokens`` trio is the original,
    stable contract callers rely on. Extended in-place with the raw
    homepage-negotiation response shape: ``status``/``content_type``/``vary``
    of the SAME negotiation GET this function already made — no new request —
    plus ``looks_markdown`` (see ``_looks_markdown``) computed over that same
    response's body. Also carries ``body_looks_markdown`` (see
    ``_body_looks_markdown``) — the PURE body signal with no Content-Type
    gate, so a caller can compare "claims markdown" vs "body looks markdown"
    as two genuinely independent signals.
    """
    result: dict[str, Any] = {
        "negotiation": False, "mirror": False, "markdown_tokens": None,
        "status": None, "content_type": None, "vary": None, "looks_markdown": False,
        "body_looks_markdown": False,
        # `_probe_text_exists` DOES read under a cap (`_PROBE_BODY_CAP`) —
        # the honest claim isn't "no cap applies" but "truncation cannot
        # INVERT this module's verdicts": `negotiation`/`mirror`/
        # `looks_markdown`/`body_looks_markdown` are pure existence/pattern
        # checks over whatever was actually read, so a cap can only ever
        # cost evidence past the cut point (under-report), never fabricate
        # a marker/non-empty-body/content-type that isn't really there —
        # degrading toward a false NEGATIVE, never a false POSITIVE. See
        # `EXEMPT_NO_REAL_SIGNAL["markdown"]` in
        # `tests/test_truncation_contract.py` for the audited reasoning
        # this constant relies on.
        "truncated": False,
    }
    try:
        resp = client.get(f"{domain}/", headers={"Accept": "text/markdown"}, timeout=_PROBE_TIMEOUT)
        content_type = resp.headers.get("content-type")
        result["status"] = resp.status_code
        result["content_type"] = content_type
        result["vary"] = resp.headers.get("vary")
        result["looks_markdown"] = _looks_markdown(content_type, resp.text[:1024])
        result["body_looks_markdown"] = _body_looks_markdown(resp.text[:1024])
        if _probe_text_exists(resp) and "text/markdown" in (content_type or ""):
            result["negotiation"] = True
            tokens = resp.headers.get("x-markdown-tokens")
            if tokens and tokens.isdigit():
                result["markdown_tokens"] = int(tokens)
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        pass
    try:
        resp = client.get(f"{domain}/index.md", timeout=_PROBE_TIMEOUT)
        if _probe_text_exists(resp):
            result["mirror"] = True
    except SoftTimeLimitExceeded:
        raise
    except Exception:
        pass
    return result
