"""Agent interface discovery-surface gatherer. Named `agent_discovery_surface`
(not `agent_discovery`) to avoid clashing with the shared module
`gatherers.agent_discovery`, whose `check_agent_discovery` this gatherer
wraps verbatim."""
from __future__ import annotations

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.gatherers.agent_discovery import check_agent_discovery
from scovant_core.gatherers.probe_tables import DISCOVERY_PROBES
from scovant_core.security.client import SecureClient


def _definitive_exists(rec: dict | None, *, parsed_key: str) -> bool | None:
    """A DEFINITIVE shared answer only — `True` on a real 200 + real JSON
    (never a soft-200 HTML catch-all), `False` only on a genuine 404/410 or
    a soft-200 HTML catch-all. Anything else — no record at all (a missing
    key, or a gatherer that raised and left `try_get` returning `None`), a
    5xx/401/403, or a status the fetch never got to record — is UNKNOWN, so
    the caller must omit the key and let it be probed the normal way.
    Guessing "absent" from an inconclusive read would be exactly the kind
    of absence-from-silence this codebase's evidence rules forbid
    everywhere else (see `checks/base.py`'s ERROR-vs-N/A docstring)."""
    if not rec:
        return None
    status = rec.get("status")
    served_as_html = bool(rec.get("served_as_html"))
    if status == 200 and not served_as_html and bool(rec.get(parsed_key)):
        return True
    if status in (404, 410) or (status == 200 and served_as_html):
        return False
    return None


@register_gatherer("agent_discovery_surface")
def gather_agent_discovery_surface(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    store.get("http")
    openapi = store.try_get("openapi") or {}
    oauth = store.try_get("oauth_metadata") or {}

    known: dict[str, bool] = {}
    # `openapi_root` seeds ONLY on the exact-match True case: the gatherer
    # aggregates several candidate paths (openapi.yaml, .well-known/
    # openapi.json, an entry-page link, ...) into one record, and
    # `found_url` may name a candidate OTHER than the exact
    # DISCOVERY_PROBES["openapi_root"] path — an `.endswith` check on that
    # path would also match `/.well-known/openapi.json`, a DIFFERENT,
    # separately-probed key. Exact equality only. The "exists" criterion is
    # deliberately the weaker "parsed as JSON" (`json_parseable`), matching
    # what `check_agent_discovery`'s own json-kind probe tests — not "is a
    # valid OpenAPI spec" (`parseable`), which is a stricter, different
    # question this probe never asks.
    #
    # There is no corresponding False seed for `openapi_root`: the
    # aggregate `status`/`served_as_html` fields answer "was an OpenAPI
    # document found among ANY conventional candidate", a broader question
    # than "did /openapi.json itself answer 404" — a 404 aggregate can
    # arise from a DIFFERENT candidate's real 404 while /openapi.json
    # itself merely failed to connect. Attributing that aggregate to this
    # one path would be a guess, so it is left out and probed directly.
    openapi_root_path = f"{ctx.origin or ''}{DISCOVERY_PROBES['openapi_root']['path']}"
    if (openapi.get("found_url") or "") == openapi_root_path:
        exists = _definitive_exists(openapi, parsed_key="json_parseable")
        if exists is not None:
            known["openapi_root"] = exists

    as_exists = _definitive_exists(oauth.get("authorization_server"), parsed_key="parseable")
    if as_exists is not None:
        known["oauth_as"] = as_exists
    pr_exists = _definitive_exists(oauth.get("protected_resource"), parsed_key="parseable")
    if pr_exists is not None:
        known["oauth_pr"] = pr_exists

    return check_agent_discovery(client.probe_adapter("json"), ctx.origin or "", known=known)
