"""Audit §8: one resolution per host, validated, then pinned — the connect
can never see a different answer than the guard."""
import socket

import httpx
import pytest

from scovant_core.security.pinned_transport import PinnedTransport
from scovant_core.security.policy import SecurityPolicy


class _Inner(httpx.BaseTransport):
    def __init__(self):
        self.seen: list[httpx.Request] = []

    def handle_request(self, request):
        self.seen.append(request)
        return httpx.Response(200, text="ok")


def _resolver(*answers):
    calls = {"n": 0}
    def resolve(host, port, *a, **k):
        ip = answers[min(calls["n"], len(answers) - 1)]
        calls["n"] += 1
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(fam, socket.SOCK_STREAM, 6, "", (ip, port))]
    resolve.calls = calls
    return resolve


def _client(transport):
    return httpx.Client(transport=transport, follow_redirects=False)


def test_public_address_is_pinned_with_host_and_sni():
    inner = _Inner()
    t = PinnedTransport(SecurityPolicy(), resolver=_resolver("93.184.216.34"), inner=inner)
    r = _client(t).get("https://example.com/path?q=1")
    assert r.status_code == 200
    req = inner.seen[0]
    assert req.url.host == "93.184.216.34" and req.url.path == "/path" and req.url.query == b"q=1"
    assert req.headers["host"] == "example.com"
    assert req.extensions["sni_hostname"] == "example.com"


def test_private_address_is_blocked_before_connect():
    inner = _Inner()
    t = PinnedTransport(SecurityPolicy(), resolver=_resolver("10.0.0.1"), inner=inner)
    with pytest.raises(httpx.ConnectError, match="non-public"):
        _client(t).get("https://evil.example/")
    assert inner.seen == []


def test_rebinding_between_calls_cannot_change_the_pinned_address():
    inner = _Inner()
    res = _resolver("93.184.216.34", "10.0.0.1")
    t = PinnedTransport(SecurityPolicy(), resolver=res, inner=inner)
    c = _client(t)
    c.get("https://example.com/a"); c.get("https://example.com/b")  # noqa: E702
    assert [r.url.host for r in inner.seen] == ["93.184.216.34", "93.184.216.34"]
    assert res.calls["n"] == 1                       # resolved once per (host, port)


def test_mixed_public_and_private_answers_are_blocked():
    inner = _Inner()
    # A single resolve() call returning BOTH a public and a private address —
    # a rebinding-adjacent multi-answer response must be blocked wholesale,
    # not pinned to whichever address happens to sort first.
    resolve_calls = {"n": 0}

    def resolve(host, port, *a, **k):
        resolve_calls["n"] += 1
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
        ]

    t = PinnedTransport(SecurityPolicy(), resolver=resolve, inner=inner)
    with pytest.raises(httpx.ConnectError, match="non-public"):
        _client(t).get("https://example.com/")
    assert inner.seen == []
    assert resolve_calls["n"] == 1
    assert t._cache == {}


def test_exempt_private_host_is_pinned_not_blocked():
    inner = _Inner()
    policy = SecurityPolicy(allow_private_networks=True, private_hosts=frozenset({"staging.test"}))
    t = PinnedTransport(policy, resolver=_resolver("10.0.0.5"), inner=inner)
    assert _client(t).get("http://staging.test:8080/").status_code == 200
    assert inner.seen[0].url.host == "10.0.0.5" and inner.seen[0].headers["host"] == "staging.test:8080"


def test_other_private_host_still_blocked_under_allow_private():
    policy = SecurityPolicy(allow_private_networks=True, private_hosts=frozenset({"staging.test"}))
    t = PinnedTransport(policy, resolver=_resolver("10.0.0.5"), inner=_Inner())
    with pytest.raises(httpx.ConnectError):
        _client(t).get("http://other.test/")


def test_ipv6_is_bracketed_and_ip_literal_passes_through():
    inner = _Inner()
    t = PinnedTransport(SecurityPolicy(), resolver=_resolver("2606:2800:220:1:248:1893:25c8:1946"), inner=inner)
    _client(t).get("https://example.com/")
    assert inner.seen[0].url.host == "2606:2800:220:1:248:1893:25c8:1946"
    assert inner.seen[0].url.raw_host == b"[2606:2800:220:1:248:1893:25c8:1946]" or "[" in str(inner.seen[0].url)
    t2 = PinnedTransport(SecurityPolicy(), resolver=_resolver("1.1.1.1"), inner=inner)
    _client(t2).get("https://93.184.216.34/")
    assert inner.seen[-1].url.host == "93.184.216.34" and "sni_hostname" not in inner.seen[-1].extensions


def test_secure_client_defaults_to_pinned_transport():
    from scovant_core.security.client import SecureClient
    c = SecureClient(SecurityPolicy(), "ua")
    assert isinstance(c.httpx._transport, PinnedTransport) and c.transport_mode == "pinned"
    c2 = SecureClient(SecurityPolicy(), "ua", transport=_Inner())
    assert c2.transport_mode == "injected"
