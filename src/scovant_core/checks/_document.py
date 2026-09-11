"""`document_status()`: one shared readability/absence ladder for every check
that fetches a single well-known document (robots.txt, a sitemap, llms.txt,
an MCP/OpenAPI/OAuth/UCP/security.txt discovery document).

The ladder: `status is None` (our own fetch failed — DNS, connect, timeout)
is `ERROR`; a real `404`/`410` is `N/A` (genuinely absent, not a defect); a
`200` carrying an HTML catch-all body (`served_as_html`) is also `N/A` (the
document was never really published); any other non-`200` status (a 5xx, a
403/401 auth wall, an unexpected redirect target) is `ERROR` — the document
could not be read, which is a data-quality gap, not a confirmed absence; a
clean `200` returns `None` so the caller proceeds to its own PASS/WARN/FAIL
logic. A caller whose own product semantics treat confirmed absence as a
meaningful (non-`N/A`) finding — e.g. a missing sitemap on a commerce site —
should use only this helper's `ERROR` verdict and keep its own absence
handling; see `checks/access/core_access_005.py` for that pattern.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

from scovant_core.models import CheckStatus

__all__ = ["DocumentVerdict", "document_status"]


@dataclasses.dataclass(frozen=True)
class DocumentVerdict:
    status: CheckStatus  # ERROR or NA
    reason: str


def document_status(record: Mapping[str, Any], *, what: str) -> DocumentVerdict | None:
    status = record.get("status")
    if status is None:
        return DocumentVerdict(CheckStatus.ERROR, f"{what} could not be read")
    if status in (404, 410):
        return DocumentVerdict(CheckStatus.NA, f"{what} is not published")
    if record.get("served_as_html"):
        return DocumentVerdict(CheckStatus.NA, f"{what} is served by an HTML catch-all page (treated as absent)")
    if status != 200:
        return DocumentVerdict(CheckStatus.ERROR, f"{what} could not be read (HTTP {status})")
    return None
