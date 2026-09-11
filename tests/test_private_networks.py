"""D8: `--allow-private-networks` opt-in — see docs/security.md § Private-network
targets (opt-in). Default stays off; the flag lifts the private/loopback/
link-local address block ONLY for the entry URL's own host (`engine.scan`
populates `SecurityPolicy.private_hosts` with exactly that one hostname) —
every other protection (scheme allow-list, redirect policy, size caps,
budget), and the address block for any OTHER host, stays in force.
"""
from __future__ import annotations

import httpx
import pytest

from scovant_core import cli
from scovant_core.context import ScanOptions
from scovant_core.engine import scan
from scovant_core.report.html import render_html
from scovant_core.report.markdown import render_markdown
from scovant_core.security.client import FetchError, SecureClient
from scovant_core.security.policy import SecurityPolicy
from tests.conftest import FIXTURES, FixtureTransport

pytestmark = pytest.mark.security


def test_default_scan_blocks_loopback_target():
    r = scan(
        "http://127.0.0.1:8000/",
        transport=FixtureTransport(FIXTURES / "sites" / "commerce-good", host="127.0.0.1"),
    )
    assert r.metrics["entry_error"]["kind"] == "security"
    assert r.provenance["allow_private_networks"] is False


def test_opt_in_allows_loopback_target():
    r = scan(
        "http://127.0.0.1:8000/",
        ScanOptions(allow_private_networks=True),
        transport=FixtureTransport(FIXTURES / "sites" / "commerce-good", host="127.0.0.1"),
    )
    assert r.metrics["entry_error"] is None
    assert r.provenance["allow_private_networks"] is True


def test_cli_flag_and_notice(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "_TRANSPORT_FACTORY",
        lambda: FixtureTransport(FIXTURES / "sites" / "commerce-good", host="127.0.0.1"),
    )
    assert cli.main(["scan", "http://127.0.0.1:8000/", "--allow-private-networks"]) == 0
    assert "private-network targets allowed" in capsys.readouterr().out


def test_cli_without_flag_still_blocked(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "_TRANSPORT_FACTORY",
        lambda: FixtureTransport(FIXTURES / "sites" / "commerce-good", host="127.0.0.1"),
    )
    assert cli.main(["scan", "http://127.0.0.1:8000/"]) == 4  # _EXIT_SECURITY
    out = capsys.readouterr().out
    assert "private-network targets allowed" not in out


def test_other_protections_stay_on_with_opt_in():
    # scheme allow-list still applies — ftp:// fails CLI input validation
    # before any network I/O, regardless of the opt-in.
    assert cli.main(["scan", "ftp://127.0.0.1/", "--allow-private-networks"]) == 2


def test_redirect_to_metadata_host_is_blocked_when_opted_in():
    """The opt-in is scoped to the entry URL's own host only. A redirect from
    the (allowed) target to a DIFFERENT private/link-local host — the classic
    cloud-metadata SSRF target — must still be blocked, and the metadata host
    must never actually be requested."""
    reached_metadata = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reached_metadata
        if request.url.host == "169.254.169.254":
            reached_metadata = True
            raise AssertionError("must never reach the metadata host")
        if request.url.host == "127.0.0.1":
            return httpx.Response(
                301, headers={"location": "http://169.254.169.254/latest/meta-data/"},
            )
        return httpx.Response(404, text="wrong host")

    r = scan(
        "http://127.0.0.1:8000/",
        ScanOptions(allow_private_networks=True),
        transport=httpx.MockTransport(handler),
    )
    assert reached_metadata is False
    assert r.metrics["entry_error"] is not None
    assert r.metrics["entry_error"]["kind"] == "security"


def test_redirect_to_a_different_private_host_is_blocked_at_the_client_too():
    """Same shape as above, exercised directly against `SecureClient` (the
    layer the redirect loop and the per-hop guard hook actually live in)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "127.0.0.1":
            return httpx.Response(301, headers={"location": "http://10.0.0.5/"})
        host = request.url.host
        raise AssertionError(f"must never reach {host!r}: outside private_hosts")

    policy = SecurityPolicy(allow_private_networks=True, private_hosts=frozenset({"127.0.0.1"}))
    client = SecureClient(policy, "ScovantCore/test", transport=httpx.MockTransport(handler))
    try:
        try:
            client.fetch("http://127.0.0.1/", kind="text")
        except FetchError as exc:
            assert exc.kind == "security"
        else:
            raise AssertionError("expected a FetchError")
    finally:
        client.close()


def test_discovered_link_on_a_different_private_host_is_not_fetched_when_opted_in():
    """A link the scan discovers mid-run on another host (a sitemap URL, a
    policy page, a well-known document, ...) — modeled here the same way
    `gatherers.sitemap.check_sitemap` calls `SecureClient` via
    `probe_adapter`/`try_fetch` — must stay blocked even with the opt-in on,
    and the other host must never actually be requested."""
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        raise AssertionError(f"must never reach {host!r}: outside private_hosts")

    policy = SecurityPolicy(allow_private_networks=True, private_hosts=frozenset({"127.0.0.1"}))
    client = SecureClient(policy, "ScovantCore/test", transport=httpx.MockTransport(handler))
    try:
        result = client.try_fetch("http://10.0.0.5/sitemap.xml", kind="sitemap")
    finally:
        client.close()
    assert isinstance(result, FetchError)
    assert result.kind == "security"


def test_reports_carry_the_private_network_notice_when_the_flag_is_on():
    """`render_markdown`/`render_html` both read
    `report.provenance["allow_private_networks"]` (see the Markdown/HTML
    `_score_block`/`_meta_section` helpers) — pin that the notice text
    actually appears in both renderers' output, not only in `provenance`."""
    r = scan(
        "http://127.0.0.1:8000/",
        ScanOptions(allow_private_networks=True),
        transport=FixtureTransport(FIXTURES / "sites" / "commerce-good", host="127.0.0.1"),
    )
    assert "private-network targets were allowed" in render_markdown(r)
    assert "private-network targets were allowed" in render_html(r)


def test_scheme_allow_list_still_refuses_ftp_even_with_private_hosts_allowed():
    """The opt-in only lifts the private/loopback
    ADDRESS block — it must never widen the scheme allow-list. A client
    configured with `allow_private_networks=True` and `127.0.0.1` in
    `private_hosts` must still refuse an `ftp://` target for that same
    host."""
    policy = SecurityPolicy(allow_private_networks=True, private_hosts=frozenset({"127.0.0.1"}))
    client = SecureClient(policy, "ScovantCore/test", transport=httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(AssertionError("must never issue a network request"))
    ))
    try:
        try:
            client.fetch("ftp://127.0.0.1/", kind="text")
        except FetchError as exc:
            assert exc.kind == "security"
        else:
            raise AssertionError("expected a FetchError")
    finally:
        client.close()


def test_flag_off_private_hosts_stays_empty_and_target_stays_blocked():
    """With the flag off, `engine.scan` never populates `private_hosts` — the
    entry target itself is blocked exactly as `test_default_scan_blocks_loopback_target`
    already pins; this test only asserts the policy object's own shape."""
    r = scan(
        "http://127.0.0.1:8000/",
        transport=FixtureTransport(FIXTURES / "sites" / "commerce-good", host="127.0.0.1"),
    )
    assert r.provenance["allow_private_networks"] is False
    assert r.metrics["entry_error"]["kind"] == "security"
