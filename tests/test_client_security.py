import httpx
import pytest

from scovant_core.security.client import FetchError, SecureClient
from scovant_core.security.policy import SecurityPolicy
from tests.conftest import make_client

pytestmark = pytest.mark.security


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/x", "gopher://example.com", "data:text/html,hi",
    "javascript:alert(1)", "http://localhost/", "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.1/", "http://192.168.1.1/", "http://[::1]/", "http://[fd00::1]/", "http://0.0.0.0/",
])
def test_blocked_targets_raise_security_error(url):
    c = make_client(lambda r: httpx.Response(200, text="x"))
    with pytest.raises(FetchError) as ei:
        c.fetch(url)
    assert ei.value.kind == "security"


def test_redirect_to_private_is_blocked():
    def handler(r):
        if r.url.path == "/":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/"})
        return httpx.Response(200, text="x")
    with pytest.raises(FetchError) as ei:
        make_client(handler).fetch("https://example.com/")
    assert ei.value.kind == "security"


def test_redirect_loop_is_a_network_error():
    handler = lambda r: httpx.Response(302, headers={"location": "https://example.com/"})  # noqa: E731
    with pytest.raises(FetchError) as ei:
        make_client(handler).fetch("https://example.com/")
    assert ei.value.kind == "network"


def test_oversized_body_is_truncated_and_flagged():
    handler = lambda r: httpx.Response(200, content=b"x" * (2 * 1024 * 1024))  # noqa: E731
    res = make_client(handler, size_limits={"robots": 1024}).fetch("https://example.com/robots.txt", kind="robots")
    assert res.truncated is True and res.bytes_len == 1024


def test_user_agent_and_request_log():
    seen = {}
    def handler(r):
        seen["ua"] = r.headers["user-agent"]
        return httpx.Response(200, text="ok")
    c = make_client(handler)
    c.fetch("https://example.com/")
    assert seen["ua"].startswith("ScovantCore/")
    assert c.requests[0]["url"] == "https://example.com/" and c.requests[0]["status"] == 200


def test_redirect_chain_recorded():
    def handler(r):
        if r.url.path == "/":
            return httpx.Response(301, headers={"location": "https://example.com/home"})
        return httpx.Response(200, text="ok")
    res = make_client(handler).fetch("https://example.com/")
    assert res.redirect_chain == ["https://example.com/"] and res.final_url == "https://example.com/home"


def test_private_networks_only_with_explicit_policy():
    # `allow_private_networks` alone lifts nothing — the host must also be
    # named in `private_hosts` (see D8, docs/security.md § Private-network
    # targets (opt-in); `tests/test_private_networks.py` covers the full
    # narrow-scope contract, incl. that a DIFFERENT host stays blocked).
    c = SecureClient(
        SecurityPolicy(allow_private_networks=True, private_hosts=frozenset({"127.0.0.1"})),
        user_agent="ScovantCore/test",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text="x")),
    )
    assert c.fetch("http://127.0.0.1/").status == 200


def test_secret_headers_are_redacted_in_request_log():
    c = make_client(lambda r: httpx.Response(200, text="x", headers={"set-cookie": "a=b"}))
    res = c.fetch("https://example.com/")
    assert "set-cookie" not in res.headers  # never surfaced in evidence


@pytest.mark.parametrize("target", ["file:///etc/passwd", "ftp://example.com/"])
def test_redirect_to_disallowed_scheme_is_a_security_error(target):
    def handler(r):
        if r.url.path == "/":
            return httpx.Response(302, headers={"location": target})
        return httpx.Response(200, text="x")
    with pytest.raises(FetchError) as ei:
        make_client(handler).fetch("https://example.com/")
    assert ei.value.kind == "security"


def test_intermediate_redirect_body_is_never_read():
    def handler(r):
        if r.url.path == "/":
            return httpx.Response(
                302, headers={"location": "https://example.com/final"}, content=b"x" * (3 * 1024 * 1024),
            )
        return httpx.Response(200, text="ok")
    c = make_client(handler)
    res = c.fetch("https://example.com/")
    assert res.status == 200 and res.text == "ok"
    assert c.requests[0]["bytes"] == 0


def test_budget_exhaustion_is_a_timeout():
    c = make_client(lambda r: httpx.Response(200, text="ok"))
    c.fetch("https://example.com/")
    c.policy = SecurityPolicy(total_budget_seconds=0.0)
    with pytest.raises(FetchError) as ei:
        c.fetch("https://example.com/")
    assert ei.value.kind == "timeout"


def test_try_fetch_returns_a_fetch_error_instance():
    c = make_client(lambda r: httpx.Response(200, text="x"))
    result = c.try_fetch("http://127.0.0.1/")
    assert isinstance(result, FetchError) and result.kind == "security"


def test_limit_for_unknown_kind_falls_back_to_text():
    policy = SecurityPolicy()
    assert policy.limit_for("some-unknown-kind") == policy.size_limits["text"]


def test_no_cookie_or_auth_header_forwarded_across_hops():
    seen_second_hop_headers = {}

    def handler(r):
        if r.url.path == "/":
            return httpx.Response(302, headers={"location": "https://example.com/next", "set-cookie": "a=b"})
        seen_second_hop_headers.update(r.headers)
        return httpx.Response(200, text="ok")

    make_client(handler).fetch("https://example.com/")
    assert "cookie" not in seen_second_hop_headers
    assert "authorization" not in seen_second_hop_headers


def test_cookie_jar_cleared_even_when_redirect_chain_errors():
    """Hop 1 sets a cookie; hop 2 raises a network error mid-chain. The
    `try/finally` around the loop must still clear the jar, so a completely
    separate later .fetch() call on the SAME client sends no cookie."""
    seen: dict = {}

    def handler(r):
        if r.url.path == "/":
            return httpx.Response(302, headers={"location": "https://example.com/next", "set-cookie": "a=b"})
        if r.url.path == "/next":
            raise httpx.ConnectError("boom", request=r)
        seen["headers"] = dict(r.headers)
        return httpx.Response(200, text="ok")

    c = make_client(handler)
    with pytest.raises(FetchError) as ei:
        c.fetch("https://example.com/")
    assert ei.value.kind == "network"

    c.fetch("https://example.com/again")
    assert "cookie" not in seen["headers"]


def test_ssrf_blocked_via_rebinding_dns_is_classified_as_security(monkeypatch):
    """A hostname that passes the cheap structural precheck (not a literal
    private IP, not localhost) but resolves to a private IP is caught by the
    shared `ssrf_guard` hook at request time — pins that an `SSRFBlocked`
    raised from inside the guard hook is classified as kind == 'security',
    not 'network'."""
    import socket

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "rebind.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    c = make_client(lambda r: httpx.Response(200, text="x"))
    with pytest.raises(FetchError) as ei:
        c.fetch("https://rebind.example.com/")
    assert ei.value.kind == "security"


def test_unresolvable_host_is_a_network_error_not_a_security_block(monkeypatch):
    """DNS says the name does not exist. The guard blocked nothing — there was
    nothing to block — so the failure must be reported as `network`, never as
    a security decision the operator would read as "we refused this target"."""
    import socket

    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "nx.example.com":
            raise socket.gaierror("Name or service not known")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    c = make_client(lambda r: httpx.Response(200, text="x"))
    with pytest.raises(FetchError) as ei:
        c.fetch("https://nx.example.com/")
    assert ei.value.kind == "network"


def test_probe_adapter_follows_redirects_and_reports_the_final_response():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/a":
            return httpx.Response(301, headers={"location": "https://example.com/b"})
        return httpx.Response(200, text="final", headers={"content-type": "text/plain"})

    c = make_client(handler)
    resp = c.probe_adapter().get("https://example.com/a")
    assert resp.status_code == 200
    assert resp.text == "final"
    assert resp.headers["content-type"] == "text/plain"
    assert resp.url == "https://example.com/b"


def test_probe_adapter_raises_an_httpx_request_error_on_a_fetch_failure():
    """The shared probe helpers already handle `httpx.RequestError`/broad
    exceptions by moving on to the next candidate — the adapter must therefore
    surface a FetchError in that shape, not as a bare FetchError escaping into
    the gatherer."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("nope", request=request)

    c = make_client(handler)
    with pytest.raises(httpx.RequestError):
        c.probe_adapter().get("https://example.com/x")
