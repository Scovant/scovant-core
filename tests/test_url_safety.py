"""Tests for the SSRF guard in scovant_core.security.url_safety."""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from scovant_core.security.url_safety import UnsafeURLError, assert_safe_public_url

# ── Literal-IP tests (no DNS) ─────────────────────────────────────────────────


def test_public_ip_literal_ok():
    """1.1.1.1 is a globally routable IP — must pass."""
    result = assert_safe_public_url("https://1.1.1.1", require_https=True)
    assert result == "https://1.1.1.1"


def test_link_local_ip_raises():
    """169.254.169.254 (AWS IMDS) must be blocked."""
    with pytest.raises(UnsafeURLError, match="private/reserved"):
        assert_safe_public_url("http://169.254.169.254/latest/meta-data/", require_https=False)


def test_loopback_ip_raises():
    """127.0.0.1 is loopback — must be blocked."""
    with pytest.raises(UnsafeURLError, match="private/reserved"):
        assert_safe_public_url("http://127.0.0.1", require_https=False)


def test_rfc1918_10_raises():
    """10.0.0.5 is a private RFC-1918 address — must be blocked."""
    with pytest.raises(UnsafeURLError, match="private/reserved"):
        assert_safe_public_url("http://10.0.0.5", require_https=False)


def test_rfc1918_172_raises():
    """172.16.0.1 is a private RFC-1918 address — must be blocked."""
    with pytest.raises(UnsafeURLError, match="private/reserved"):
        assert_safe_public_url("http://172.16.0.1", require_https=False)


def test_rfc1918_192_raises():
    """192.168.1.1 is a private RFC-1918 address — must be blocked."""
    with pytest.raises(UnsafeURLError, match="private/reserved"):
        assert_safe_public_url("http://192.168.1.1", require_https=False)


# ── Hostname checks ───────────────────────────────────────────────────────────


def test_localhost_hostname_raises():
    """'localhost' must always be blocked."""
    with pytest.raises(UnsafeURLError, match="localhost"):
        assert_safe_public_url("https://localhost", require_https=True)


def test_empty_host_raises():
    """Malformed URL with no host must be blocked."""
    with pytest.raises(UnsafeURLError, match="empty"):
        assert_safe_public_url("https://", require_https=True)


def test_public_hostname_ok():
    """example.com resolves to public IPs — must pass (uses real DNS)."""
    result = assert_safe_public_url("https://example.com")
    assert result == "https://example.com"


def test_hostname_resolving_to_private_ip_raises():
    """A hostname that resolves only to a private IP must be blocked."""
    # Simulate DNS returning 10.0.0.1
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 443))]
    with (
        patch("socket.getaddrinfo", return_value=fake_addrinfo),
        pytest.raises(UnsafeURLError, match="private/reserved"),
    ):
        assert_safe_public_url("https://internal.test")


def test_hostname_resolving_to_loopback_raises():
    """A hostname that resolves to 127.0.0.1 must be blocked."""
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]
    with (
        patch("socket.getaddrinfo", return_value=fake_addrinfo),
        pytest.raises(UnsafeURLError, match="private/reserved"),
    ):
        assert_safe_public_url("https://evil.test")


def test_hostname_resolving_to_link_local_raises():
    """A hostname that resolves to 169.254.x.x must be blocked."""
    fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 443))]
    with (
        patch("socket.getaddrinfo", return_value=fake_addrinfo),
        pytest.raises(UnsafeURLError, match="private/reserved"),
    ):
        assert_safe_public_url("https://metadata.test")


# ── Scheme checks ─────────────────────────────────────────────────────────────


def test_http_with_require_https_raises():
    """HTTP URL with require_https=True must raise."""
    with pytest.raises(UnsafeURLError, match="must be HTTPS"):
        assert_safe_public_url("http://example.com", require_https=True)


def test_http_with_require_https_false_ok():
    """HTTP URL with require_https=False is allowed for public hosts."""
    # Use a literal public IP to avoid DNS in test
    result = assert_safe_public_url("http://1.1.1.1", require_https=False)
    assert result == "http://1.1.1.1"


def test_ftp_scheme_raises():
    """ftp:// is an unsupported scheme and must always raise."""
    with pytest.raises(UnsafeURLError, match="Unsupported URL scheme"):
        assert_safe_public_url("ftp://example.com", require_https=False)


def test_file_scheme_raises():
    """file:// is an unsupported scheme and must always raise."""
    with pytest.raises(UnsafeURLError, match="Unsupported URL scheme"):
        assert_safe_public_url("file:///etc/passwd", require_https=False)


# ── DNS failure ───────────────────────────────────────────────────────────────


def test_unresolvable_hostname_raises():
    """A hostname that cannot be resolved must raise UnsafeURLError."""
    with (
        patch("socket.getaddrinfo", side_effect=socket.gaierror("Name not resolved")),
        pytest.raises(UnsafeURLError, match="Could not resolve host"),
    ):
        assert_safe_public_url("https://does-not-exist.invalid")


def test_resolve_false_skips_dns_but_still_blocks_literal_private_ip():
    # resolve=False: a non-resolving host passes the cheap structural check
    # (the per-request worker hook does the authoritative DNS check at fetch).
    assert assert_safe_public_url("https://nonexistent-xyz-12345.invalid", resolve=False)
    # but a literal private/reserved IP is still blocked without any DNS
    with pytest.raises(UnsafeURLError):
        assert_safe_public_url("http://169.254.169.254/latest/meta-data/", require_https=False, resolve=False)
    with pytest.raises(UnsafeURLError):
        assert_safe_public_url("https://127.0.0.1", resolve=False)
