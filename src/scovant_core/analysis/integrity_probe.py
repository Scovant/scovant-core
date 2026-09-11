"""Resolution half of agent-instruction reference integrity.

Takes the pure extractor's references and answers one question each: does
this thing exist? Deliberately narrow:

* **Allow-listed registries only** — `registry.npmjs.org` and `pypi.org`
  metadata endpoints. We never fetch package CONTENTS, never execute
  anything, and never touch a registry we have not listed here.
* **DNS only for domains** — an A/AAAA lookup, no HTTP request to a
  third-party host we found inside someone else's documentation.
* **Hard budget** per scan (:data:`LOOKUP_BUDGET`), short timeouts, and every
  failure degrades to "unchecked" rather than "missing".

The asymmetry is the point: a definitive 404 from a package registry is
evidence, while a timeout is not. Rules keyed on this data may only fire on
the former.
"""
from __future__ import annotations

import concurrent.futures
import logging
import socket
from collections.abc import Callable
from typing import Any

import httpx

log = logging.getLogger(__name__)

# Total lookups per scan across all reference kinds. Instruction integrity is
# a side-probe on an already-long domain-level pass; it must not become the
# thing that makes scans slow or noisy for the sites we check.
LOOKUP_BUDGET = 20

_TIMEOUT = httpx.Timeout(4.0, connect=2.0)
_DNS_TIMEOUT_SECONDS = 2.0

_REGISTRY_URLS = {
    "package_npm": "https://registry.npmjs.org/{name}",
    "package_pypi": "https://pypi.org/pypi/{name}/json",
}

# The identity a host presents to the registries it looks up. Callers with
# their own crawler identity (a User-Agent already registered with, or
# expected by, third-party services) should pass their own `user_agent` to
# `check_instruction_integrity` rather than relying on this default.
DEFAULT_USER_AGENT = "scovant-core/probe (+https://github.com/Scovant/scovant-core)"


def _resolve_domain(name: str) -> dict[str, Any]:
    """A/AAAA lookup. NXDOMAIN is evidence; any other failure is not.

    The lookup runs in a helper thread bounded by ``_DNS_TIMEOUT_SECONDS``:
    ``getaddrinfo`` is a blocking libc call that ignores socket timeouts, and
    the earlier ``socket.setdefaulttimeout`` approach did not bound it while
    silently changing the default timeout of EVERY socket the worker process
    opens afterwards. A lookup that outlives the budget is "unchecked" — the
    thread is left to finish on its own, never published as a dead domain.
    """
    # Not a `with` block: the executor's context exit JOINS the worker, which
    # would make the caller wait out a hung resolver anyway. `shutdown(
    # wait=False)` lets the stray thread finish on its own.
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(socket.getaddrinfo, name, None)
        future.result(timeout=_DNS_TIMEOUT_SECONDS)
        return {"checked": True, "exists": True}
    except concurrent.futures.TimeoutError:
        return {"checked": False, "error": "dns:timeout"}
    except socket.gaierror as exc:
        # Only a genuine "name does not exist" counts; a temporary resolver
        # failure (EAI_AGAIN) must not be published as a dead domain.
        if getattr(exc, "errno", None) in (socket.EAI_NONAME, socket.EAI_NODATA):
            return {"checked": True, "exists": False}
        return {"checked": False, "error": f"dns:{exc.errno}"}
    except Exception as exc:  # noqa: BLE001
        return {"checked": False, "error": type(exc).__name__}
    finally:
        pool.shutdown(wait=False)


def _resolve_package(
    client: httpx.Client | None, kind: str, name: str, *,
    fetch: Callable[[str], tuple[int, str] | None] | None = None,
) -> dict[str, Any]:
    """Registry metadata lookup. 404 is evidence; anything else is not.

    When `fetch` is given it REPLACES `client.get` entirely — used to route
    the registry GET through a hardened fetcher (e.g. Core's `SecureClient`)
    instead of a bare `httpx.Client`. Cloud never passes it, so its call is
    byte-identical."""
    url = _REGISTRY_URLS[kind].format(name=httpx.URL(path=name).path.lstrip("/"))
    if fetch is not None:
        try:
            fetched = fetch(url)
        except Exception as exc:  # noqa: BLE001
            return {"checked": False, "error": type(exc).__name__}
        if fetched is None:
            # The fetcher itself couldn't reach the registry (SSRF-refused,
            # a cross-host redirect refused, a network failure it already
            # degraded internally) — distinct from a real HTTP status we
            # just don't recognize, so it gets its own honest label rather
            # than the misleading `http:None`.
            return {"checked": False, "error": "unreachable"}
        status_code, _text = fetched
    else:
        assert client is not None  # invariant: caller only omits `fetch` with a real client
        try:
            resp = client.get(url)
        except Exception as exc:  # noqa: BLE001
            return {"checked": False, "error": type(exc).__name__}
        status_code = resp.status_code
    if status_code == 404:
        return {"checked": True, "exists": False}
    if status_code is not None and 200 <= status_code < 300:
        return {"checked": True, "exists": True}
    # 429/5xx/redirect oddity: we genuinely do not know.
    return {"checked": False, "error": f"http:{status_code}"}


def check_instruction_integrity(
    text: str,
    *,
    self_domain: str | None = None,
    budget: int = LOOKUP_BUDGET,
    user_agent: str = DEFAULT_USER_AGENT,
    fetch: Callable[[str], tuple[int, str] | None] | None = None,
) -> dict[str, Any]:
    """Extract references from `text` and resolve as many as the budget allows.

    Returns ``{attempted, checked, references: [...], remote_exec: [...],
    budget_exhausted}`` where each reference carries its classification.
    References beyond the budget stay ``UNCHECKED`` — recorded, never guessed.

    `user_agent` identifies this probe to the registries it queries; pass
    your own to present a caller-specific crawler identity instead of the
    package default.

    `fetch`, when given, replaces the internal bare `httpx.Client` for every
    package-registry lookup — a `(status, text) | None` callable, e.g. one
    built over a hardened client. Cloud never passes it, so its call stays
    byte-identical (this parameter is Core-only).

    Never raises: this is a best-effort side-probe on an already-long pass.
    """
    from scovant_core.analysis.instruction_integrity import (
        classify_reference,
        extract_references,
        find_remote_exec_instructions,
    )

    result: dict[str, Any] = {
        "attempted": True, "checked": 0, "references": [],
        "remote_exec": [], "budget_exhausted": False,
    }
    try:
        refs = extract_references(text or "", self_domain=self_domain)
        result["remote_exec"] = find_remote_exec_instructions(text or "")
    except Exception as exc:  # noqa: BLE001
        log.warning("integrity_probe.extract_failed %s", {"error": str(exc)[:200]})
        return {**result, "attempted": False}

    spent = 0
    # `fetch`, when given, REPLACES the bare `httpx.Client` entirely for
    # every package lookup — so there is no reason to open one at all in
    # that case (it would sit unused for the whole probe).
    client = None if fetch is not None else httpx.Client(
        timeout=_TIMEOUT, follow_redirects=True, headers={"User-Agent": user_agent},
    )
    try:
        for ref in refs:
            if spent >= budget:
                result["budget_exhausted"] = True
                resolution = None
            elif ref["kind"] == "domain":
                spent += 1
                resolution = _resolve_domain(ref["name"])
            elif ref["kind"] in _REGISTRY_URLS:
                spent += 1
                resolution = _resolve_package(client, ref["kind"], ref["name"], fetch=fetch)
            else:
                resolution = None
            result["references"].append({
                **ref,
                "status": classify_reference(ref, resolution),
                "resolution": resolution,
            })
    finally:
        if client is not None:
            client.close()
    result["checked"] = spent
    return result
