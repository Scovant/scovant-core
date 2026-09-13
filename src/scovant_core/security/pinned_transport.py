"""IP-pinned HTTP transport (audit §8). The SSRF guard validates what a
hostname resolves to; without pinning, the OS resolver runs AGAIN inside
the connect and a rebinding DNS server can answer the guard with a public
address and the connect with a private one. This transport resolves once,
validates every address, and connects to the address it validated — with
`Host` and TLS SNI/verification still against the original hostname."""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable

import httpx

from scovant_core.security.policy import SecurityPolicy
from scovant_core.security.url_safety import UnsafeURLError, assert_public_address

Resolver = Callable[..., list[tuple]]


class PinnedTransport(httpx.BaseTransport):
    def __init__(self, policy: SecurityPolicy, *, resolver: Resolver = socket.getaddrinfo,
                 inner: httpx.BaseTransport | None = None, **transport_kwargs):
        self.policy = policy
        self._resolve = resolver
        self._inner = inner or httpx.HTTPTransport(**transport_kwargs)
        self._cache: dict[tuple[str, int], str] = {}

    # -- helpers ----------------------------------------------------------
    def _exempt(self, host: str) -> bool:
        return self.policy.allow_private_networks and host in self.policy.private_hosts

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _pin(self, host: str, port: int) -> str:
        key = (host, port)
        if key in self._cache:
            return self._cache[key]
        try:
            infos = self._resolve(host, port, 0, socket.SOCK_STREAM)
        except OSError as exc:
            raise httpx.ConnectError(f"could not resolve {host}") from exc
        addresses = [str(i[4][0]) for i in infos]
        if not addresses:
            raise httpx.ConnectError(f"could not resolve {host}")
        if not self._exempt(host):
            for ip in addresses:
                try:
                    assert_public_address(ip, host=host)
                except UnsafeURLError as exc:
                    raise httpx.ConnectError(f"blocked by security policy: {host} resolves to a non-public address") from exc
        v4 = [a for a in addresses if ":" not in a]
        chosen = (v4 or addresses)[0]
        self._cache[key] = chosen
        return chosen

    # -- transport --------------------------------------------------------
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = (request.url.host or "").lower()
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        if self._is_ip(host):
            if not self._exempt(host):
                try:
                    assert_public_address(host, host=host)
                except UnsafeURLError as exc:
                    raise httpx.ConnectError(str(exc)) from exc
            return self._inner.handle_request(request)
        ip = self._pin(host, port)
        pinned_host = f"[{ip}]" if ":" in ip else ip
        pinned_url = request.url.copy_with(host=pinned_host)
        headers = request.headers.copy()
        headers["host"] = host if request.url.port is None else f"{host}:{request.url.port}"
        try:
            content = request.stream
            pinned = httpx.Request(request.method, pinned_url, headers=headers, content=content,
                                    extensions={**request.extensions, "sni_hostname": host})
        except Exception:
            pinned = httpx.Request(request.method, pinned_url, headers=headers, content=request.read(),
                                    extensions={**request.extensions, "sni_hostname": host})
        return self._inner.handle_request(pinned)

    def close(self) -> None:
        self._inner.close()
