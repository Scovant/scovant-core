"""Keep the default Core test suite off the network.

Every test without the `network` marker runs with
`socket.getaddrinfo`, `socket.create_connection` and `socket.socket.connect`
/ `connect_ex` replaced: resolving or connecting to anything but a loopback
address raises
`RuntimeError("network access in an offline test")`. Loopback stays open
because the fixture server and the subprocess tests bind to 127.0.0.1.

Reserved documentation names get a deterministic answer instead of a lookup,
because they are the fixture hosts of most of the suite (the SSRF guard
resolves every request's host before it is sent):

- `example.com`, `example.org`, `example.net` and every subdomain of them
  answer `93.184.216.34` (the address IANA has long published for
  `example.com`, a public address the SSRF guard accepts);
- `.test`, `.invalid`, `.example` and `.localhost` names (RFC 2606 / RFC 6761)
  never resolve: they raise `socket.gaierror`, as a real resolver does.

A test that needs another answer patches `socket.getaddrinfo` itself (its
patch replaces this one for the duration of the test); a test whose purpose
is real DNS carries the `network` marker: it is excluded from the default
CI run and skipped unless SCOVANT_CORE_NETWORK_TESTS=1 is set.
"""
from __future__ import annotations

import ipaddress
import os
import socket

import pytest

OFFLINE_MESSAGE = "network access in an offline test"
NETWORK_OPT_IN = "SCOVANT_CORE_NETWORK_TESTS"
REAL_GETADDRINFO = socket.getaddrinfo
REAL_CREATE_CONNECTION = socket.create_connection
REAL_SOCKET_CONNECT = socket.socket.connect
REAL_SOCKET_CONNECT_EX = socket.socket.connect_ex
_LOOPBACK_NAMES = {"localhost", "localhost.", "ip6-localhost"}
DOCUMENTATION_ADDRESS = "93.184.216.34"
_DOCUMENTATION_DOMAINS = ("example.com", "example.org", "example.net")
_NEVER_RESOLVING_SUFFIXES = (".test", ".invalid", ".example", ".localhost")


def _name(host: object) -> str | None:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    return host.strip("[]").rstrip(".").lower() if isinstance(host, str) else None


def _is_documentation_name(name: str) -> bool:
    return any(name == d or name.endswith("." + d) for d in _DOCUMENTATION_DOMAINS)


def _never_resolves(name: str) -> bool:
    return any(name.endswith(s) or name == s[1:] for s in _NEVER_RESOLVING_SUFFIXES)


def _port(port: object) -> int:
    if isinstance(port, int):
        return port
    if isinstance(port, bytes):
        port = port.decode("ascii", "replace")
    if isinstance(port, str) and port:
        return int(port) if port.isdigit() else {"http": 80, "https": 443}.get(port, 0)
    return 0


def _is_loopback(host: object) -> bool:
    if host is None:
        return True  # getaddrinfo(None, port) resolves the local wildcard, never the network
    name = _name(host)
    if name is None:
        return False
    if name in _LOOPBACK_NAMES or name + "." in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(name.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _offline_getaddrinfo(host, port=None, *args, **kwargs):
    if _is_loopback(host):
        return REAL_GETADDRINFO(host, port, *args, **kwargs)
    name = _name(host)
    if name is not None and _is_documentation_name(name):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                 (DOCUMENTATION_ADDRESS, _port(port)))]
    if name is not None and _never_resolves(name):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    raise RuntimeError(OFFLINE_MESSAGE)


def _offline_create_connection(address, *args, **kwargs):
    if _is_loopback(address[0]):
        return REAL_CREATE_CONNECTION(address, *args, **kwargs)
    raise RuntimeError(OFFLINE_MESSAGE)


def _connect_allowed(address) -> bool:
    # AF_UNIX paths are local; an (host, port, ...) tuple must be loopback.
    return not isinstance(address, tuple) or _is_loopback(address[0])


def _offline_connect(self, address):
    if _connect_allowed(address):
        return REAL_SOCKET_CONNECT(self, address)
    raise RuntimeError(OFFLINE_MESSAGE)


def _offline_connect_ex(self, address):
    if _connect_allowed(address):
        return REAL_SOCKET_CONNECT_EX(self, address)
    raise RuntimeError(OFFLINE_MESSAGE)


def network_tests_enabled(environ=os.environ) -> bool:
    return environ.get(NETWORK_OPT_IN) == "1"


def needs_offline_guard(node) -> bool:
    return node.get_closest_marker("network") is None


def pytest_collection_modifyitems(config, items):
    """Tests marked `network` run only with SCOVANT_CORE_NETWORK_TESTS=1, so no
    invocation that forgets `-m "not network"` (e.g. a host repository running
    this suite by path) ever reaches the real network."""
    if network_tests_enabled():
        return
    skip = pytest.mark.skip(reason=f"needs the network; set {NETWORK_OPT_IN}=1 to run")
    for item in items:
        if item.get_closest_marker("network") is not None:
            item.add_marker(skip)


def install_offline_guard(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _offline_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _offline_create_connection)
    # asyncio connects through `socket.socket.connect` directly, after its
    # own `getaddrinfo` — so an address this module stubbed for a
    # documentation name can still never be reached.
    monkeypatch.setattr(socket.socket, "connect", _offline_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _offline_connect_ex)


@pytest.fixture(autouse=True)
def _offline_network_guard(request, monkeypatch):
    if needs_offline_guard(request.node):
        install_offline_guard(monkeypatch)
    yield
