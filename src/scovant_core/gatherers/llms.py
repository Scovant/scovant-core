"""llms.txt gatherer: fetch + parse `/llms.txt`, probe `/llms-full.txt`, and
resolve (via a fresh GET) each linked reference so a downstream check can
tell a dead link from a live one without re-fetching itself."""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.llms_txt import parse_llms_txt
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

MAX_REFERENCES = 20


@register_gatherer("llms")
def gather_llms(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    url = f"{ctx.origin}/llms.txt"
    res = client.try_fetch(url, kind="text")
    if isinstance(res, FetchError):
        parsed = parse_llms_txt("", 0)
        return {"url": url, "status": None, "parsed": parsed, "full_exists": False, "references": [],
                "served_as_html": False, "truncated": False, "text": ""}

    status = res.status
    # A 200 carrying an HTML page (a catch-all router / soft-404 template) is
    # NOT a published llms.txt. Parsing it would report a document the site
    # never published as "present but malformed"; the honest reading is absent.
    served_as_html = is_soft_200_html(status, res.content_type, res.text, document="llms")
    content = res.text if status == 200 and not served_as_html else ""
    parsed = parse_llms_txt(content, 0 if served_as_html else status)
    truncated = bool(res.truncated) and content != ""

    full = client.try_fetch(f"{ctx.origin}/llms-full.txt", kind="text")
    full_exists = (
        not isinstance(full, FetchError)
        and full.status == 200
        and not is_soft_200_html(full.status, full.content_type, full.text, document="llms")
    )
    # Two documents contribute to this record (`/llms.txt` and, when it
    # exists, `/llms-full.txt`); `truncated` is true when EITHER was cut off
    # at the fetch cap with real bytes surviving — `full_exists` is derived
    # from `full.text` regardless of the soft-200 outcome, so a truncated
    # `llms-full.txt` degrades that boolean exactly as a truncated
    # `llms.txt` degrades `parsed` above.
    if not isinstance(full, FetchError):
        truncated = truncated or (bool(full.truncated) and full.text != "")

    references = []
    for ref_url in parsed["urls"][:MAX_REFERENCES]:
        r = client.try_fetch(ref_url, kind="text")
        ref = {"url": ref_url, "status": None if isinstance(r, FetchError) else r.status}
        if not isinstance(r, FetchError) and r.status == 429:
            ref["retry_after"] = r.headers.get("retry-after")
        references.append(ref)

    # NOT re-capped here — `content` is already bounded by the fetch layer's
    # own per-kind size limit (`SecurityPolicy.limit_for("text")`, 1 MB);
    # `machine_text` applies the tighter 64 KB per-surface cap and is the one
    # place that decides whether a document was truncated FOR THAT PURPOSE.
    out = {"url": url, "status": status, "parsed": parsed, "full_exists": full_exists, "references": references,
           "served_as_html": served_as_html, "truncated": truncated, "text": content}
    if status == 429:
        out["retry_after"] = res.headers.get("retry-after")
    return out
