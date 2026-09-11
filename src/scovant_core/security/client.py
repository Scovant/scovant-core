"""SSRF-guarded, size- and time-capped HTTP client used by every gatherer.

Residual DNS-rebinding risk: the SSRF guard's own hostname resolution (inside
the shared `ssrf_guard` event-hook, via `assert_safe_public_url`) and the
actual TCP connect's resolution performed by httpx/the OS resolver are two
separate lookups a few milliseconds apart. An attacker controlling DNS could
answer the guard's lookup with a public IP and the connect's lookup with a
private one. Fully closing this needs an IP-pinned transport (resolve once,
connect to that pinned address, verify TLS against the original hostname) —
tracked as a follow-up, not implemented here.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

from scovant_core.security.policy import SecurityPolicy
from scovant_core.security.url_safety import (
    SSRFBlocked,
    UnresolvableHost,
    UnsafeURLError,
    assert_safe_public_url,
    ssrf_guard,
)

log = logging.getLogger(__name__)

_REDACTED_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
_ALLOWED_SCHEMES = ("http", "https")
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    def __init__(self, kind: str, message: str, url: str = ""):
        super().__init__(message)
        self.kind, self.message, self.url = kind, message, url


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    text: str
    bytes_len: int
    redirect_chain: list[str] = field(default_factory=list)
    elapsed_ms: int = 0
    truncated: bool = False
    content_type: str = ""


class SecureClient:
    def __init__(self, policy: SecurityPolicy, user_agent: str, transport: httpx.BaseTransport | None = None):
        self.policy = policy
        self.user_agent = user_agent
        self.requests: list[dict] = []
        self._started = time.monotonic()
        # the shared guard from url_safety — one implementation, shared with Cloud's
        # crawler/sitemap/domain-verification fetchers, so a fix lands everywhere at once.
        # ALWAYS attached — `_guard_hook` below is the narrow per-host carve-out
        # for `policy.private_hosts`, never a blanket skip.
        self.httpx = httpx.Client(
            timeout=httpx.Timeout(policy.request_timeout, connect=policy.connect_timeout),
            follow_redirects=False,  # we drive the redirect loop ourselves — see fetch()
            headers={"user-agent": user_agent, "accept": "*/*"},
            event_hooks={"request": [self._guard_hook]},
            transport=transport,
            cookies=None,
            trust_env=False,
        )

    def _guard_hook(self, request: httpx.Request) -> None:
        """Per-request SSRF guard, closest to the connect. Skips the
        resolved-address check ONLY when `policy.allow_private_networks` is
        set AND this specific request's host is in `policy.private_hosts` —
        a redirect hop or any discovered link on a different host is never
        exempt, even mid-scan."""
        host = (request.url.host or "").lower()
        if self.policy.allow_private_networks and host in self.policy.private_hosts:
            return
        ssrf_guard(request)

    def __enter__(self) -> SecureClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- pre-flight ------------------------------------------------------------
    def _precheck(self, url: str) -> None:
        """Structural-only checks (no DNS): scheme allow-list + the cheap
        literal-IP/localhost checks. The resolved (DNS-aware) check happens
        per-request in the shared `ssrf_guard` hook, closest to the connect —
        see the module docstring for the residual DNS-rebinding gap between
        the two lookups."""
        scheme = url.split(":", 1)[0].lower() if ":" in url else ""
        if scheme not in _ALLOWED_SCHEMES:
            raise FetchError("security", f"unsupported URL scheme: {scheme or 'none'}", url)
        host = (urlsplit(url).hostname or "").lower()
        if self.policy.allow_private_networks and host in self.policy.private_hosts:
            return
        try:
            assert_safe_public_url(url, require_https=False, resolve=False)
        except UnresolvableHost as exc:
            # DNS said the name does not exist. Nothing was blocked — there
            # was nothing to block — so this is a NETWORK failure, not a
            # security decision, and must not be reported as one.
            raise FetchError("network", str(exc), url) from exc
        except UnsafeURLError as exc:
            raise FetchError("security", str(exc), url) from exc

    def _check_deadline(self, url: str) -> None:
        if time.monotonic() > self._started + self.policy.total_budget_seconds:
            raise FetchError("timeout", "scan time budget exhausted", url)

    # -- fetch ---------------------------------------------------------------
    def fetch(self, url: str, kind: str = "html") -> FetchResult:
        limit = self.policy.limit_for(kind)
        t0 = time.monotonic()
        current = url
        chain: list[str] = []
        result: FetchResult | None = None
        hop_t0 = t0
        # The whole redirect loop runs under this try/finally so that ANY exit —
        # success, a mid-chain FetchError (too-many-redirects, a blocked hop), or
        # an httpx.RequestError from the guard hook or the network — clears the
        # cookie jar before returning control. Relying only on an inline `.clear()`
        # at the end of the happy path would leave a hop's Set-Cookie sitting in
        # the jar for the NEXT .fetch() call whenever this one raised instead.
        try:
            try:
                while True:
                    self._precheck(current)
                    self._check_deadline(current)
                    hop_t0 = time.monotonic()
                    with self.httpx.stream("GET", current) as resp:
                        if resp.status_code in _REDIRECT_STATUSES and "location" in resp.headers:
                            # never read an intermediate response's body — only headers,
                            # so an oversized redirect page can't be downloaded for nothing.
                            next_url = str(httpx.URL(current).join(resp.headers["location"]))
                            self._log(current, resp.status_code, 0, hop_t0)
                            chain.append(current)
                            self.httpx.cookies.clear()  # never forward a hop's cookie to the next hop
                            if len(chain) > self.policy.max_redirects:
                                raise FetchError(
                                    "network", f"too many redirects (> {self.policy.max_redirects})", url,
                                )
                            current = next_url
                            continue

                        # final response: only this one is streamed/decoded under the size cap.
                        chunks, total, truncated = [], 0, False
                        for chunk in resp.iter_bytes():
                            self._check_deadline(current)
                            if total + len(chunk) > limit:
                                chunks.append(chunk[: limit - total])
                                total = limit
                                truncated = True
                                break
                            chunks.append(chunk)
                            total += len(chunk)
                        body = b"".join(chunks)
                        # dict comprehension: a repeated header name collapses to the LAST
                        # value seen (httpx preserves response order) — documented
                        # last-wins behavior, not a bug.
                        headers = {
                            k.lower(): v for k, v in resp.headers.items() if k.lower() not in _REDACTED_HEADERS
                        }
                        result = FetchResult(
                            url=url, final_url=str(resp.url), status=resp.status_code, headers=headers,
                            text=body.decode(resp.encoding or "utf-8", errors="replace"), bytes_len=total,
                            redirect_chain=chain, elapsed_ms=int((time.monotonic() - t0) * 1000),
                            truncated=truncated, content_type=headers.get("content-type", ""),
                        )
                        self._log(current, resp.status_code, total, hop_t0)
                    break
            except FetchError:
                raise
            except httpx.RequestError as exc:
                self._log(current, None, 0, hop_t0)
                # An SSRFBlocked whose CAUSE is an unresolvable host is a DNS
                # failure the guard happened to notice first (it resolves the
                # name itself) — the guard blocked nothing, so it stays a
                # network error. Every other SSRFBlocked is a real block.
                blocked = isinstance(exc, SSRFBlocked) and not isinstance(exc.__cause__, UnresolvableHost)
                kind_ = "security" if blocked else "network"
                if isinstance(exc, httpx.TimeoutException):
                    kind_ = "timeout"
                raise FetchError(kind_, str(exc), url) from exc
        finally:
            self.httpx.cookies.clear()  # never let this fetch's cookies leak into the next .fetch() call
        assert result is not None
        return result

    def probe_adapter(self, kind: str = "text") -> _FetchAdapter:
        """A minimal `httpx.Client`-shaped view over `fetch()` for the shared
        probe helpers (`gatherers.sitemap.check_sitemap`,
        `gatherers.mcp_metadata.probe_mcp_server_card`).

        Those helpers were written against `httpx.Client.get`; handing them
        `self.httpx` directly would give them a client with
        `follow_redirects=False` and no scan-deadline or size cap — so a
        sitemap declared behind a 301 read as "absent". This adapter routes
        them through the same guarded, redirect-following, capped,
        deadline-aware `fetch()` every other gatherer uses."""
        return _FetchAdapter(self, kind)

    def try_fetch(self, url: str, kind: str = "html") -> FetchResult | FetchError:
        try:
            return self.fetch(url, kind)
        except FetchError as exc:
            return exc

    def _log(self, url: str, status: int | None, nbytes: int, t0: float) -> None:
        entry = {"url": url, "status": status, "bytes": nbytes, "ms": int((time.monotonic() - t0) * 1000)}
        self.requests.append(entry)
        log.debug("fetch %s", entry)

    def close(self) -> None:
        self.httpx.close()


class _ProbeResponse:
    """The read-only subset of `httpx.Response` the shared probe helpers use:
    `.status_code`, `.text`, `.headers`, `.url`. Backed by a `FetchResult`, so
    the body is already size-capped and the URL is the FINAL one after any
    redirects the guarded client followed."""

    __slots__ = ("headers", "status_code", "text", "url")

    def __init__(self, res: FetchResult):
        self.status_code = res.status
        self.text = res.text
        self.headers = res.headers  # already lower-cased by fetch()
        self.url = res.final_url


class _FetchAdapter:
    """`.get(url, timeout=None) -> _ProbeResponse` over `SecureClient.fetch`.

    A `FetchError` is re-raised as an `httpx.RequestError`, because that is
    exactly what the shared helpers' own `except` clauses already handle
    (`check_sitemap`/`_probe_json` catch broad `Exception` but re-raise
    `SoftTimeLimitExceeded`) — so a fetch failure keeps degrading to "this
    candidate did not answer" instead of escaping into the gatherer.

    `timeout` is accepted and ignored on purpose: the real bound is the
    client's own per-request timeout plus the scan-wide deadline, both of
    which are stricter and non-negotiable from a helper's point of view."""

    __slots__ = ("_client", "_kind")

    def __init__(self, client: SecureClient, kind: str = "text"):
        self._client, self._kind = client, kind

    def get(self, url: str, timeout: float | None = None) -> _ProbeResponse:  # noqa: ARG002 — see docstring
        try:
            return _ProbeResponse(self._client.fetch(url, kind=self._kind))
        except FetchError as exc:
            raise httpx.RequestError(f"{exc.kind}: {exc.message}", request=httpx.Request("GET", url)) from exc
