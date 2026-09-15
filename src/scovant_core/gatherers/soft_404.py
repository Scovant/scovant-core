"""Soft-404 probe (0.3.0, audit §21 / AgentReady AR-READ-02): ONE extra GET of a
path that cannot exist. A server that answers it with a 200 HTML page cannot
tell an agent a missing page from a real one. The path is derived from the
scan id, so it is unique per scan and stable for a fixed scan id (goldens)."""
from __future__ import annotations

import hashlib
import re

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient

PROBE_PREFIX = "/scovant-core-probe-"


def probe_token(scan_id: str) -> str:
    return hashlib.sha256(scan_id.encode()).hexdigest()[:8]


def _looks_html(content_type: str, text: str) -> bool:
    head = text.lstrip()[:64].lower()
    return "text/html" in (content_type or "").lower() or head.startswith("<!doctype") or head.startswith("<html")


# An empty mount point a client-side router fills in later: the whole page is
# `<div id="root"></div>` and a bundle. Matching the *empty* element (not the
# id alone) is what separates a shell from a real page that happens to wrap its
# server-rendered content in a container with the same id.
_EMPTY_MOUNT_RE = re.compile(
    r"<(div|main|section)\b[^>]*\bid\s*=\s*[\"']?(?:root|app|__next|__nuxt|_?_?svelte)[\"']?[^>]*>\s*</\1\s*>",
    re.I,
)
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=", re.I)
_TAG_RE = re.compile(r"<(script|style)\b.*?</\1\s*>|<[^>]+>", re.I | re.S)
_WS_RE = re.compile(r"\s+")
_SHELL_MAX_VISIBLE_CHARS = 100


def _visible_text_len(html: str) -> int:
    return len(_WS_RE.sub(" ", _TAG_RE.sub(" ", html or "")).strip())


def looks_spa_shell(html: str) -> bool:
    """True when an HTML body is an application shell rather than a rendered
    page: an empty client-router mount point, or almost no visible text next to
    a script bundle. Such a response is not a soft-404 with a wrong status —
    it is a page whose content only exists after JavaScript runs, which is a
    different defect with a different fix, so CORE-OPERABILITY-008 says so."""
    if _EMPTY_MOUNT_RE.search(html or ""):
        return True
    return _visible_text_len(html) < _SHELL_MAX_VISIBLE_CHARS and bool(_SCRIPT_SRC_RE.search(html or ""))


@register_gatherer("soft_404")
def gather_soft_404(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    origin = ctx.origin or ""
    url = f"{origin}{PROBE_PREFIX}{probe_token(getattr(ctx, 'scan_id', '') or ctx.input_url)}"
    res = client.try_fetch(url, kind="html")
    if isinstance(res, FetchError):
        return {"probed_url": url, "status": None, "final_url": None, "served_html": False,
                "looks_spa_shell": False, "redirected": False, "error": res.kind, "truncated": False}
    served_html = _looks_html(res.content_type, res.text)
    out = {
        "probed_url": url, "status": res.status, "final_url": res.final_url,
        "served_html": served_html,
        # only meaningful for an HTML body — a JSON or text error page is not a shell
        "looks_spa_shell": served_html and looks_spa_shell(res.text),
        "redirected": bool(res.redirect_chain),
        "error": None,
        "truncated": res.truncated,
    }
    if res.status == 429:
        out["retry_after"] = res.headers.get("retry-after")
    return out
