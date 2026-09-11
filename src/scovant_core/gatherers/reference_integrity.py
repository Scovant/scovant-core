"""Machine-instruction reference-integrity gatherer: extracts and resolves
references (package names, domains, remote-exec instructions) named in
`llms.txt` and declared MCP server descriptions.

Gated on `ScanOptions.experimental` alone — the ONLY gatherer gated this way
— because it costs external lookups (DNS + allow-listed npm/PyPI GETs) for a
check that never scores outside `--experimental` (product spec §15,
CORE-OPERABILITY-007). A non-experimental scan issues zero network for this
gatherer, full stop."""
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

from scovant_core.analysis.integrity_probe import check_instruction_integrity
from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.security.client import FetchError, SecureClient


def _secure_fetch(
    client: SecureClient, truncated_flags: list[bool],
) -> Callable[[str], tuple[int, str] | None]:
    """Build a `(status, text) | None` fetcher for `check_instruction_integrity`
    over the same guarded client every other gatherer uses — SSRF guard, size
    cap, and (see below) no cross-host redirect, instead of a bare
    `httpx.Client` reaching npm/PyPI directly.

    `SecureClient.fetch`'s redirect loop follows any hop that passes the SSRF
    guard, INCLUDING a hop to a different public host — the guard checks
    "is this address safe to reach", not "is this still the host I asked
    for". A registry response is only trustworthy if it actually came from
    the registry we asked, so this wrapper additionally refuses a redirect
    that lands on a different host than the one requested.

    `check_instruction_integrity` may issue several such lookups per scan
    (one per extracted reference) and its `(status, text)` return shape has
    no room for a per-call truncation flag, so each fetch's own signal is
    appended to `truncated_flags`; the caller combines them."""

    def fetch(url: str) -> tuple[int, str] | None:
        res = client.try_fetch(url, kind="json")
        if isinstance(res, FetchError):
            return None
        requested_host = (urlsplit(url).hostname or "").lower()
        final_host = (urlsplit(res.final_url).hostname or "").lower()
        if final_host and final_host != requested_host:
            return None
        truncated_flags.append(bool(res.truncated) and res.text != "")
        return res.status, res.text

    return fetch


@register_gatherer("reference_integrity")
def gather_reference_integrity(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    if not ctx.options.experimental:
        return {"attempted": False, "reason": "experimental_off", "truncated": False}

    llms = store.get("llms")
    raw_content = (llms.get("parsed") or {}).get("raw_content") or ""

    mcp = store.get("mcp_discovery")
    servers = mcp.get("discovery", {}).get("servers", [])
    descriptions = [s["description"] for s in servers if s.get("description")]

    text = raw_content + "\n" + "\n".join(descriptions)
    self_domain = urlsplit(ctx.origin or "").hostname

    # `user_agent` is NOT passed here — `check_instruction_integrity` only
    # applies it to the internal `httpx.Client` it builds when no `fetch` is
    # given; passing `fetch=` (below) replaces that client entirely, and
    # `_secure_fetch`'s own `SecureClient` already sets the UA via
    # `CORE_USER_AGENT` on every request it makes.
    truncated_flags: list[bool] = []
    result = check_instruction_integrity(
        text, self_domain=self_domain, fetch=_secure_fetch(client, truncated_flags),
    )
    # The probe already signals its own internal failure via `attempted:
    # False` (an extraction exception) — never clobber that back to True.
    # Only fill it in when the probe's own result is silent about it.
    result.setdefault("attempted", True)
    # This gatherer's OWN reads are the registry lookups above (`raw_content`
    # and the MCP server descriptions are reused from the `llms`/
    # `mcp_discovery` records, which already carry their own `truncated`
    # flags) — true when ANY registry response contributing to this result
    # was cut off at the fetch cap.
    result["truncated"] = any(truncated_flags)
    return result
