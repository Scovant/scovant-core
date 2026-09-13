"""Shared SSRF guard: validate that a URL targets a public, non-reserved host."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse, urlsplit, urlunsplit

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


# RFC 3986 path parameters (`;key=value` or bare `;key`) attached to a path
# SEGMENT — e.g. `/path;jsessionid=abc123`. These travel in `urlsplit().path`,
# not `.query`, so a query-only redaction misses them entirely; a session id
# riding a path param would otherwise round-trip unchanged.
_PATH_PARAM_RE = re.compile(r";([^=;/]+)(=[^;/]*)?")


def _redact_path_params(path: str) -> str:
    return _PATH_PARAM_RE.sub(lambda m: f";{m.group(1)}=[REDACTED]", path)


def has_userinfo(url: str) -> bool:
    """True iff `url` carries embedded credentials (`user:pw@host` or
    `user@host`). Tested against `netloc` containing "@", not the whole
    URL, so a query VALUE that happens to contain "@" (e.g. an email
    address, `?u=user@example.com`) is never mistaken for userinfo."""
    p = urlparse(url)
    return bool(p.username) or bool(p.password) or ("@" in p.netloc)


def display_url(url: str) -> str:
    """The URL as every report shows it: query VALUES replaced by
    [REDACTED] (keys kept), RFC 3986 path-parameter VALUES (`;key=value`
    segments in the path, e.g. a `;jsessionid=...`) redacted the same way,
    fragment dropped. The full URL exists only inside the engine's fetch
    path (audit §7)."""
    p = urlsplit(url)
    path = _redact_path_params(p.path)
    if not p.query:
        return urlunsplit((p.scheme, p.netloc, path, "", ""))
    keys = [kv.split("=", 1)[0] for kv in p.query.split("&") if kv]
    return urlunsplit((p.scheme, p.netloc, path, "&".join(f"{k}=[REDACTED]" for k in keys), ""))


def redact_message(message: str, url: str) -> str:
    """Replace any occurrence of the raw `url` (or its bare query string, or
    a raw `;key=value` path-parameter segment) inside an error `message`
    with its redacted display form — httpx exception text often embeds the
    full request URL verbatim."""
    if not message:
        return message
    return _apply_replacements(message, _replacements_for(url))


def _replacements_for(url: str) -> list[tuple[str, str]]:
    """Every raw substring of `url` that must never survive into a report,
    paired with its redacted replacement — longest-first so the full-URL
    replacement (when present) runs before any of its own substrings could
    partially match. Shared by `redact_message` (single string) and
    `redact_report_strings` (arbitrary nested structure) so the two never
    drift on what counts as "the secret part of this URL"."""
    if not url:
        return []
    p = urlsplit(url)
    redacted = display_url(url)
    replacements = [(url, redacted)]
    if p.query:
        replacements.append((p.query, urlsplit(redacted).query))
    if p.fragment:
        replacements.append((p.fragment, ""))
    for m in _PATH_PARAM_RE.finditer(p.path):
        replacements.append((m.group(0), f";{m.group(1)}=[REDACTED]"))
    replacements = [(raw, red) for raw, red in replacements if raw]
    replacements.sort(key=lambda kv: -len(kv[0]))
    return replacements


def _apply_replacements(text: str, replacements: list[tuple[str, str]]) -> str:
    out = text
    for raw, red in replacements:
        out = out.replace(raw, red)
    return out


def redact_report_strings(obj, url: str):
    """Pure recursive walker: replaces every raw fragment of `url` (the raw
    full URL, its raw query string, its raw fragment, and any raw
    `;key=value` path-parameter segment) with its display form, in EVERY
    string found anywhere inside `obj` (arbitrarily nested dict/list/str;
    any other value passes through unchanged).

    This is the belt to the ~20 at-source `display_url`/`redact_message`
    call sites' suspenders: those redact evidence at the point a check
    builds it, which is precise but has no single choke point — the next
    check that copies a URL into its evidence without routing it through
    `display_url` leaks again. `engine.scan` calls this ONCE over the
    finished `Report` right before returning, so a forgotten at-source
    call site degrades to "redacted late" instead of "never redacted"."""
    replacements = _replacements_for(url)

    def _walk(node):
        if isinstance(node, str):
            return _apply_replacements(node, replacements)
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v) for v in node]
        return node

    return _walk(obj)


def _ip_is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _PRIVATE_NETWORKS) or addr.is_private \
        or addr.is_loopback or addr.is_link_local or addr.is_reserved \
        or addr.is_multicast or addr.is_unspecified


def assert_public_address(ip: str, *, host: str) -> None:
    """Raise ``UnsafeURLError`` when ``ip`` — one resolved address of
    ``host`` — is private/reserved/loopback/link-local/multicast/unspecified.

    Extracted (audit §8) so the per-request SSRF guard's DNS-resolution loop
    (below) and `PinnedTransport`'s own resolve-then-connect share the exact
    same predicate — one implementation, not two that could drift."""
    if _ip_is_blocked(ip):
        raise UnsafeURLError(f"Host {host} resolves to a private/reserved IP ({ip})")


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
    if has_userinfo(url):
        raise UnsafeURLError("URL must not contain credentials")
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
        assert_public_address(str(info[4][0]), host=host)
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
    "assert_public_address",
    "assert_safe_public_url",
    "display_url",
    "has_userinfo",
    "redact_message",
    "redact_report_strings",
    "ssrf_guard",
    "ssrf_guard_async",
]
