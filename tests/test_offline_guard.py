"""The default Core suite cannot reach the network.

`tests/conftest_offline.py` replaces `socket.getaddrinfo` and
`socket.create_connection` for every test without the `network` marker;
a test that tries to resolve or connect to a non-loopback host fails with a
`RuntimeError` instead of silently depending on the network.
"""
from __future__ import annotations

import socket

import pytest

from tests.conftest_offline import DOCUMENTATION_ADDRESS, OFFLINE_MESSAGE


def test_offline_guard_blocks_dns():
    with pytest.raises(RuntimeError, match=OFFLINE_MESSAGE):
        socket.getaddrinfo("scovant.com", 80)


def test_offline_guard_blocks_connections():
    with pytest.raises(RuntimeError, match=OFFLINE_MESSAGE):
        socket.create_connection(("scovant.com", 80), timeout=1)
    # A stubbed documentation name still never opens a real connection.
    with pytest.raises(RuntimeError, match=OFFLINE_MESSAGE):
        socket.create_connection(("example.com", 80), timeout=1)


def test_documentation_names_get_a_deterministic_answer():
    """RFC 2606 fixture hosts resolve without a lookup; reserved TLDs never resolve."""
    infos = socket.getaddrinfo("www.example.com", 443)
    assert [info[4] for info in infos] == [(DOCUMENTATION_ADDRESS, 443)]
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("evil.example", 443)
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("nowhere.invalid", 443)


def test_offline_guard_blocks_public_ip_literals():
    with pytest.raises(RuntimeError, match=OFFLINE_MESSAGE):
        socket.create_connection(("192.0.2.1", 80), timeout=1)


def test_offline_guard_blocks_raw_socket_connects():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(
        RuntimeError, match=OFFLINE_MESSAGE
    ):
        sock.connect((DOCUMENTATION_ADDRESS, 80))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(
        RuntimeError, match=OFFLINE_MESSAGE
    ):
        sock.connect_ex((DOCUMENTATION_ADDRESS, 80))


def test_offline_guard_allows_loopback():
    assert socket.getaddrinfo("127.0.0.1", 80)
    assert socket.getaddrinfo("localhost", 80)


def test_network_marker_is_registered(pytestconfig):
    assert any(m.startswith("network:") for m in pytestconfig.getini("markers"))


class _Node:
    def __init__(self, *markers):
        self._markers = {m: pytest.Mark(m, (), {}) for m in markers}

    def get_closest_marker(self, name):
        return self._markers.get(name)


def test_only_unmarked_tests_get_the_guard():
    from tests import conftest_offline

    assert conftest_offline.needs_offline_guard(_Node())
    assert conftest_offline.needs_offline_guard(_Node("security"))
    assert not conftest_offline.needs_offline_guard(_Node("network"))


def test_network_marked_tests_are_skipped_without_the_opt_in(monkeypatch):
    from tests import conftest_offline

    class _Item(_Node):
        def __init__(self, *markers):
            super().__init__(*markers)
            self.added = []

        def add_marker(self, mark):
            self.added.append(mark)

    plain, networked = _Item(), _Item("network")
    monkeypatch.delenv(conftest_offline.NETWORK_OPT_IN, raising=False)
    conftest_offline.pytest_collection_modifyitems(None, [plain, networked])
    assert plain.added == []
    assert [m.name for m in networked.added] == ["skip"]

    opted = _Item("network")
    monkeypatch.setenv(conftest_offline.NETWORK_OPT_IN, "1")
    conftest_offline.pytest_collection_modifyitems(None, [opted])
    assert opted.added == []


def test_default_pinned_transport_resolves_through_the_guarded_getaddrinfo():
    """A default `PinnedTransport` (what a default `SecureClient` builds) must look
    `socket.getaddrinfo` up at call time — a default bound at import would do real
    DNS and bypass this guard."""
    import httpx

    from scovant_core.security.pinned_transport import PinnedTransport
    from scovant_core.security.policy import SecurityPolicy

    transport = PinnedTransport(SecurityPolicy(), inner=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert transport._pin("example.com", 443) == DOCUMENTATION_ADDRESS
    with pytest.raises(RuntimeError, match=OFFLINE_MESSAGE):
        transport._pin("scovant.com", 443)
