"""OpenAPI/Swagger spec discovery: a fixed set of conventional paths plus any
same-origin entry-page link whose href names `openapi`/`swagger`."""
from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from scovant_core.context import ScanContext
from scovant_core.evidence import EvidenceStore, register_gatherer
from scovant_core.parsers.html import coerce_attr_str
from scovant_core.security.client import FetchError, SecureClient

from ._soft_200 import is_soft_200_html

_CANDIDATE_PATHS = ("/openapi.json", "/openapi.yaml", "/.well-known/openapi.json", "/swagger.json", "/api-docs")
_MAX_VERSION_LEN = 50
# Bounds the retained `text` well above machine_text's own 64 KB per-surface
# cap (so a real single-source overflow still exercises that cap, not this
# one) while still capping the 10 MB "json"-kind fetch ceiling down to
# something bounded before it's carried around as evidence.
_TEXT_CAP = 256 * 1024


def _entry_page_link_candidates(html: str, base_url: str, origin: str) -> list[str]:
    if not html:
        return []
    soup = BeautifulSoup(html, "lxml")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        href = coerce_attr_str(a.get("href")) or ""
        if "openapi" not in href.lower() and "swagger" not in href.lower():
            continue
        absolute = urljoin(base_url, href)
        p = urlsplit(absolute)
        if f"{p.scheme}://{p.netloc}" != origin:
            continue
        out.append(absolute)
    return out


def _check_parseable(text: str) -> tuple[bool, str | None]:
    """JSON with an `openapi`/`swagger` key, or a YAML doc whose first 20
    lines contain an `openapi:` key — either counts as a real spec."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return False, None
        if isinstance(data, dict):
            version = data.get("openapi") or data.get("swagger")
            if version:
                return True, str(version)[:_MAX_VERSION_LEN]
        return False, None

    for line in stripped.splitlines()[:20]:
        line = line.strip()
        if line.startswith("openapi:"):
            version = line.split(":", 1)[1].strip()
            return True, (version[:_MAX_VERSION_LEN] or None)
    return False, None


def _extract_paths_and_schemas(text: str) -> tuple[list[str], dict[str, dict[str, dict]]]:
    """Best-effort structural extraction over an already-confirmed-parseable
    OpenAPI JSON document — `paths` (the declared path keys, in document
    order) and `schemas` (`components.schemas[*].properties` reduced to
    `{property: {example, default}}`, values coerced to plain str/None so a
    non-string example/default never leaks a nested object into evidence).
    Never raises: a document that doesn't parse as JSON, or whose `paths`/
    `components` aren't the expected shape, degrades to `[]`/`{}` — this is
    additive evidence, not a second parseability gate."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], {}
    if not isinstance(data, dict):
        return [], {}
    paths_obj = data.get("paths")
    paths = [str(p) for p in paths_obj] if isinstance(paths_obj, dict) else []
    schemas: dict[str, dict[str, dict]] = {}
    components = data.get("components")
    raw_schemas = components.get("schemas") if isinstance(components, dict) else None
    if isinstance(raw_schemas, dict):
        for name, schema in raw_schemas.items():
            if not isinstance(schema, dict):
                continue
            props = schema.get("properties")
            if not isinstance(props, dict):
                continue
            out_props: dict[str, dict] = {}
            for prop, meta in props.items():
                if not isinstance(meta, dict):
                    continue
                example = meta.get("example")
                default = meta.get("default")
                out_props[str(prop)] = {
                    "example": example if isinstance(example, str) else None,
                    "default": default if isinstance(default, str) else None,
                }
            if out_props:
                schemas[str(name)] = out_props
    return paths, schemas


def _is_json_parseable(text: str) -> bool:
    """The body parses as JSON at all — deliberately weaker than
    `_check_parseable` (which additionally requires an `openapi`/`swagger`
    version key, i.e. "is a valid spec"). A caller that only cares whether
    *some* JSON document sits at this URL (e.g. the discovery-surface
    gatherer's `openapi_root` probe, which never checks for a spec shape)
    needs this distinct, weaker signal — conflating the two would silently
    seed "exists" on the narrower "valid spec" criterion."""
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return False
    try:
        json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return False
    return True


@register_gatherer("openapi")
def gather_openapi(client: SecureClient, ctx: ScanContext, store: EvidenceStore) -> dict:
    http = store.get("http")
    origin = ctx.origin or ""
    fixed = [f"{origin}{p}" for p in _CANDIDATE_PATHS]
    entry_links = [u for u in _entry_page_link_candidates(http["html"], ctx.final_url or ctx.input_url, origin)
                   if u not in fixed]
    candidates = fixed + entry_links

    found_url: str | None = None
    parseable = False
    json_parseable = False
    openapi_version: str | None = None
    paths: list[str] = []
    schemas: dict[str, dict[str, dict]] = {}
    served_as_html = False
    # `status`/`last_served_as_html` are AGGREGATED across every candidate
    # this loop examines — never "whichever candidate happened to answer
    # last" (that was order-dependent: 4x404 then a network error read as
    # ERROR, while a 500 then 4x404 read as absent, purely from iteration
    # order). Precedence, once no candidate is a real found spec (200 +
    # not served-as-html, handled by `found_url` below exactly as before):
    #   1. any candidate with a REAL non-200/non-404/410 status (5xx,
    #      401/403, an unexpected redirect target) wins — the FIRST such
    #      status is recorded as `status`, and CORE-INTERFACE-005 reads it
    #      as ERROR via `document_status` (a genuine read failure, not
    #      confirmed absence).
    #   2. else any candidate that answered 200 with an HTML catch-all body
    #      wins — `status = 200`, `last_served_as_html = True`, which
    #      `document_status` reads as N/A (the soft-200-is-absent branch).
    #   3. else any real 404/410 wins — `status = 404`, confirmed absence,
    #      read as N/A/WARN by the check's own not-found logic.
    #   4. else every candidate failed OUR fetch (DNS/connect/timeout) —
    #      `status = None`, ERROR.
    # This makes the verdict independent of which candidate is probed first
    # or last: any real read failure anywhere in the run always outranks a
    # clean 404/410 seen elsewhere.
    error_status: int | None = None
    error_retry_after: str | None = None
    saw_soft_html = False
    saw_absent = False
    truncated = False
    found_text = ""
    for url in candidates:
        res = client.try_fetch(url, kind="json")
        if isinstance(res, FetchError):
            continue
        if res.status == 200:
            if is_soft_200_html(res.status, res.content_type, res.text, document="openapi"):
                # A catch-all router answered with an HTML page. That candidate did
                # NOT publish a spec — keep probing the remaining candidates instead
                # of locking onto it and reporting "found but does not parse".
                served_as_html = True
                saw_soft_html = True
                continue
            found_url = url
            parseable, openapi_version = _check_parseable(res.text)
            json_parseable = _is_json_parseable(res.text)
            found_text = res.text[:_TEXT_CAP]
            # Only the candidate that actually became the found spec
            # contributes to the record — an earlier 404'd/errored candidate
            # never fed a document into `parseable`/`openapi_version`.
            truncated = bool(res.truncated) and res.text != ""
            if parseable:
                paths, schemas = _extract_paths_and_schemas(res.text)
            break
        if res.status in (404, 410):
            saw_absent = True
            continue
        if error_status is None:
            error_status = res.status
            if res.status == 429:
                error_retry_after = res.headers.get("retry-after")

    if found_url:
        status: int | None = 200
        last_served_as_html = False
    elif error_status is not None:
        status = error_status
        last_served_as_html = False
    elif saw_soft_html:
        status = 200
        last_served_as_html = True
    elif saw_absent:
        status = 404
        last_served_as_html = False
    else:
        status = None
        last_served_as_html = False

    out = {"found_url": found_url, "parseable": parseable, "json_parseable": json_parseable,
           "openapi_version": openapi_version,
           "candidates": candidates, "served_as_html": served_as_html,
           "status": status, "last_served_as_html": last_served_as_html,
           "truncated": truncated, "text": found_text,
           "paths": paths, "schemas": schemas}
    if status == 429:
        out["retry_after"] = error_retry_after
    return out
