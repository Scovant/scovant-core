"""Shared SSRF guard: validate that a URL targets a public, non-reserved host."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class UnsafeURLError(ValueError):
    pass


class UnresolvableHost(UnsafeURLError):
    """The hostname could not be resolved at all (DNS NXDOMAIN/failure).

    A subclass of `UnsafeURLError` so every existing `except UnsafeURLError`
    catch site keeps behaving exactly as before; callers that want to report
    an unresolvable host as a NETWORK failure rather than a SECURITY block
    (nothing was blocked — there was nothing to block) can test for this
    type specifically."""


class SSRFBlocked(httpx.RequestError):
    """Raised by the shared SSRF guard event-hooks (`ssrf_guard`/`ssrf_guard_async`)
    when a request targets a private/reserved network. Kept as an
    `httpx.RequestError` subclass so every existing `except httpx.RequestError`
    catch site (Cloud crawler tasks, scan sitemap expansion, domain-verification
    meta fetch) stays unaffected; a caller that needs to distinguish an SSRF
    block from an ordinary network failure can `isinstance(exc, SSRFBlocked)`."""


def _ip_is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _PRIVATE_NETWORKS) or addr.is_private \
        or addr.is_loopback or addr.is_link_local or addr.is_reserved \
        or addr.is_multicast or addr.is_unspecified


def assert_safe_public_url(url: str, *, require_https: bool = True, resolve: bool = True) -> str:
    """Validate that ``url`` targets a public, non-reserved host.

    With ``resolve=True`` (default) the hostname is resolved via DNS and every
    returned A/AAAA record is checked — use this at the point of connection
    (the crawler request hook), where it is both authoritative and resists
    DNS-rebinding (the resolution happens closest to the actual fetch).

    With ``resolve=False`` only the cheap structural checks run (scheme,
    empty/localhost host, literal private/reserved IP) — no DNS. Use this at
    ingestion (API schema / target expansion) so creating a scan never blocks
    on a synchronous lookup and a transiently-unresolvable but legitimate
    domain isn't dropped; the per-request hook still blocks the actual fetch.
    """
    parsed = urlparse(url)
    if require_https and parsed.scheme != "https":
        raise UnsafeURLError("URL must be HTTPS")
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError("Unsupported URL scheme")
    host = (parsed.hostname or "").lower()
    if not host or host == "localhost":
        raise UnsafeURLError("URL host is empty or localhost")
    try:
        if _ip_is_blocked(host):
            raise UnsafeURLError(f"URL targets a private/reserved IP ({host})")
        return url
    except ValueError as exc:
        if isinstance(exc, UnsafeURLError):
            raise
        # not a literal IP — resolve it below
    if not resolve:
        return url
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise UnresolvableHost(f"Could not resolve host {host}") from exc
    for info in infos:
        ip = str(info[4][0])
        if _ip_is_blocked(ip):
            raise UnsafeURLError(f"Host {host} resolves to a private/reserved IP ({ip})")
    return url


# ── canonical httpx SSRF guard event-hooks ─────────────────────────────────
# One sync and one async hook to attach as `event_hooks={"request": [...]}`
# so every redirect hop is re-validated. Do not copy these into other
# modules: a single implementation is what keeps every fetcher equally safe.
# `require_https=False`: callers that require HTTPS enforce it up front.


def _guard(request: httpx.Request) -> None:
    try:
        assert_safe_public_url(str(request.url), require_https=False)
    except UnsafeURLError as exc:
        raise SSRFBlocked(
            f"SSRF guard blocked {request.url}: {exc}",
            request=request,
        ) from exc


def ssrf_guard(request: httpx.Request) -> None:
    """Sync SSRF guard event-hook for ``httpx.Client``."""
    _guard(request)


async def ssrf_guard_async(request: httpx.Request) -> None:
    """Async SSRF guard event-hook for ``httpx.AsyncClient``."""
    _guard(request)


__all__ = [
    "SSRFBlocked",
    "UnresolvableHost",
    "UnsafeURLError",
    "assert_safe_public_url",
    "ssrf_guard",
    "ssrf_guard_async",
]
