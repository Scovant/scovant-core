"""Offline security regression suite — product spec §47's mandatory case
list, run almost entirely against `httpx.MockTransport`/`FixtureTransport`
(never real network I/O). The one exception is
`test_an_oversized_llms_txt_is_declared_as_a_partial_read_end_to_end`, which
deliberately drives a real loopback HTTP server (`fixture_server`, see
`tests/conftest.py`) — the whole point of that test is proving the byte-cap
truncation signal survives an actual streamed socket read, not just an
in-process transport substitution.

Already covered by `tests/test_client_security.py` and intentionally NOT
duplicated here (see that file for the actual assertions):
- literal blocked hosts: localhost, 127.0.0.1, 169.254.169.254, 10.0.0.1,
  192.168.1.1, [::1], [fd00::1], 0.0.0.0
  (`test_blocked_targets_raise_security_error`)
- redirect to a metadata IP, at the raw-client level
  (`test_redirect_to_private_is_blocked`)
- redirect loop (`test_redirect_loop_is_a_network_error`)
- oversized robots body, truncated and flagged, at the raw-client level
  (`test_oversized_body_is_truncated_and_flagged`)
- DNS rebinding simulation (`test_ssrf_blocked_via_rebinding_dns_is_classified_as_security`)

This file adds the remaining §47 cases that file does not cover: redirect to
`localhost` specifically, oversized sitemap XML (at the gatherer level, not
just the raw client), malformed gzip, and a slow response tripping the scan
time budget. It also re-states the "zip bomb equivalent" case as a pointer
to the existing oversized-body truncation test — the client's size cap is
enforced on the decompressed byte stream regardless of how the origin server
produced it, so a genuine gzip bomb is defended by the same mechanism.

Two more cases are proven here end-to-end, through the real gatherer/engine
rather than just the raw client: an oversized robots.txt truncated at the
default 1 MiB cap and still parsed as present-and-readable evidence
(`test_oversized_robots_txt_is_truncated_and_parsed_as_present_not_crash`,
completing the §47 "oversized robots" case beyond the client-level check
above), and a redirect from an ordinary public entry URL to a cloud
metadata address, proven both unreachable and reported as a security-kind
entry error at the full `scan()` level
(`test_redirect_to_cloud_metadata_address_is_blocked_and_never_requested`).
"""
from __future__ import annotations

import gzip
import time

import httpx
import pytest

import scovant_core.gatherers._register  # noqa: F401 — registers robots_txt/sitemap_urls gatherers
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.engine import scan
from scovant_core.evidence import EvidenceStore
from scovant_core.models import CheckStatus, Confidence
from scovant_core.security.client import FetchError, SecureClient
from scovant_core.security.policy import SecurityPolicy
from tests.conftest import make_client

pytestmark = pytest.mark.security

# ---------------------------------------------------------------------------
# redirect -> localhost (the sibling case to the already-covered
# redirect -> metadata IP)
# ---------------------------------------------------------------------------

def test_redirect_to_localhost_is_blocked():
    def handler(r):
        if r.url.path == "/":
            return httpx.Response(302, headers={"location": "http://localhost/"})
        return httpx.Response(200, text="x")

    with pytest.raises(FetchError) as ei:
        make_client(handler).fetch("https://example.com/")
    assert ei.value.kind == "security"


# ---------------------------------------------------------------------------
# oversized XML — at the sitemap gatherer level, not just the raw client:
# a truncated-mid-tag body must fail XML parsing gracefully (`valid: False`,
# a recorded `parse_error`) rather than raise out of the gatherer.
# ---------------------------------------------------------------------------

def test_oversized_sitemap_xml_is_truncated_and_reported_invalid_no_crash():
    robots = "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\n"
    # A well-formed sitemap that is far bigger than the (deliberately tiny,
    # test-only) size cap below — truncation must land mid-element, so the
    # gatherer has to survive an XML parse failure without raising.
    entries = "".join(f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(5000))
    big_sitemap = f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{entries}</urlset>'
    assert len(big_sitemap.encode()) > 4096

    def handler(r):
        if r.url.path == "/robots.txt":
            return httpx.Response(200, text=robots, headers={"content-type": "text/plain"})
        if r.url.path == "/sitemap.xml":
            return httpx.Response(200, content=big_sitemap.encode(), headers={"content-type": "application/xml"})
        return httpx.Response(404, text="not found")

    client = make_client(handler, size_limits={"sitemap": 4096, "sitemap_index": 4096})
    store = EvidenceStore(client, ScanContext("https://example.com/", ScanOptions()))
    result = store.get("sitemap_urls")  # must not raise
    assert result["valid"] is False
    assert result["parse_error"] is not None
    assert result["entries"] == []


# ---------------------------------------------------------------------------
# "zip bomb equivalent" — same size-cap mechanism as the oversized-robots
# case in test_client_security.py, exercised here over a genuinely gzipped
# payload so the cap is proven to apply post-decompression, not just to the
# wire bytes.
# ---------------------------------------------------------------------------

def test_gzip_decompression_bomb_is_capped_not_decompressed_without_limit():
    huge_plain = b"a" * (5 * 1024 * 1024)  # 5 MiB of highly-compressible content
    compressed = gzip.compress(huge_plain)
    assert len(compressed) < 50_000  # a small wire payload expands to something much larger

    def handler(r):
        return httpx.Response(200, content=compressed, headers={"content-encoding": "gzip"})

    client = make_client(handler, size_limits={"html": 1024})
    res = client.fetch("https://example.com/", kind="html")
    assert res.truncated is True
    assert res.bytes_len == 1024  # capped, never the full 5 MiB decompressed body


# ---------------------------------------------------------------------------
# malformed gzip — a `content-encoding: gzip` response whose body is not
# actually valid gzip must degrade to a clean FetchError, never an unhandled
# decoding crash.
# ---------------------------------------------------------------------------

def test_malformed_gzip_body_is_a_network_error_not_a_crash():
    def handler(r):
        return httpx.Response(200, content=b"this is not gzip data at all", headers={"content-encoding": "gzip"})

    c = make_client(handler)
    with pytest.raises(FetchError) as ei:
        c.fetch("https://example.com/")
    assert ei.value.kind == "network"


# ---------------------------------------------------------------------------
# slow response — a handler that blocks past the scan's time budget must
# surface as a timeout, not hang the scan. `httpx.MockTransport` runs the
# handler in-process with no real socket, so it does not honor
# `request_timeout`/`connect_timeout` the way a real connection would; the
# enforceable, offline-simulatable deadline is `SecurityPolicy.total_budget_seconds`,
# checked by `SecureClient._check_deadline` right after the (slow) response
# starts arriving — functionally the same offline stand-in the product spec's
# "slow response" case calls for.
# ---------------------------------------------------------------------------

def test_slow_response_trips_the_scan_time_budget_as_a_timeout():
    def handler(r):
        time.sleep(0.2)
        return httpx.Response(200, text="ok")

    c = SecureClient(
        SecurityPolicy(total_budget_seconds=0.05),
        user_agent="ScovantCore/test",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(FetchError) as ei:
        c.fetch("https://example.com/")
    assert ei.value.kind == "timeout"


# ---------------------------------------------------------------------------
# oversized robots.txt — the real robots gatherer (not just the raw client)
# must truncate at the default 1 MiB cap, still parse the readable prefix,
# and CORE-ACCESS-002 must treat the result as present-and-readable (PASS),
# never ERROR: a truncated-but-parseable robots.txt is degraded evidence,
# not unreadable evidence.
# ---------------------------------------------------------------------------

def test_oversized_robots_txt_is_truncated_and_parsed_as_present_not_crash():
    body = "User-agent: *\nDisallow: /private\n" + ("# " + "x" * 1000 + "\n") * 2000
    assert len(body.encode()) > 1024 * 1024  # > the default 1 MiB robots cap

    def handler(r):
        if r.url.path == "/robots.txt":
            return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    # Raw-client level: the fetch itself must record the truncation.
    raw = make_client(handler).fetch("https://example.com/robots.txt", kind="robots")
    assert raw.status == 200
    assert raw.truncated is True
    assert raw.bytes_len == 1024 * 1024

    # Gatherer/engine level: a truncated-but-readable robots.txt is still
    # usable evidence — status 200, parsed policy present, no crash — and
    # CORE-ACCESS-002 must not misreport it as unreadable (ERROR).
    report = scan("https://example.com/", transport=httpx.MockTransport(handler))
    check = next(f for f in report.findings if f.id == "CORE-ACCESS-002")
    assert check.status != CheckStatus.ERROR
    assert check.evidence["status"] == 200
    # ...and the truncation must be visible in the report, not silently
    # published as a fully-read document: the flag reaches the evidence and
    # the finding drops to medium confidence.
    assert check.evidence["truncated"] is True
    assert check.confidence is Confidence.MEDIUM
    assert "read only in part" in check.summary


# ---------------------------------------------------------------------------
# ...and the same must hold for EVERY check that draws a verdict from the
# robots.txt body, not just the availability check: the policy verdicts are
# where a truncated read is actually consequential (CORE-ACCESS-003 is
# weight 4 / HIGH severity and would otherwise publish "all major crawlers
# are allowed" at high confidence off a prefix that omits two Disallow
# stanzas). The fixture below puts the GPTBot/PerplexityBot stanzas and a
# Content-Signal line PAST the 1 MiB cap on purpose.
# ---------------------------------------------------------------------------

ROBOTS_BODY_CHECKS = ("CORE-ACCESS-002", "CORE-ACCESS-003", "CORE-ACCESS-004", "CORE-ACCESS-010")


def _oversized_robots_report(prefix: str = "User-agent: *\nDisallow: /private\n"):
    body = prefix + ("# " + "x" * 1000 + "\n") * 2000 + (
        "User-agent: GPTBot\nDisallow: /\n\n"
        "User-agent: PerplexityBot\nDisallow: /\n\n"
        "Content-Signal: search=yes, ai-train=no\n"
    )
    assert len((prefix + ("# " + "x" * 1000 + "\n") * 2000).encode()) > 1024 * 1024

    def handler(r):
        if r.url.path == "/robots.txt":
            return httpx.Response(200, text=body, headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    return scan("https://example.com/", transport=httpx.MockTransport(handler))


def test_every_robots_derived_verdict_declares_the_truncated_read():
    report = _oversized_robots_report()
    for cid in ROBOTS_BODY_CHECKS:
        f = next(x for x in report.findings if x.id == cid)
        assert f.evidence["truncated"] is True, cid
        assert f.confidence is Confidence.MEDIUM, cid
        assert "read only in part" in f.summary, cid


def test_a_truncated_robots_fail_verdict_is_not_silent():
    """The verdict truncation is most likely to invert is a FAIL (an `Allow:`
    past the cap), so the note must not be limited to the PASS branch."""
    report = _oversized_robots_report(prefix="User-agent: *\nDisallow: /\n")
    f = next(x for x in report.findings if x.id == "CORE-ACCESS-002")
    assert f.status is CheckStatus.FAIL
    assert "read only in part" in f.summary
    assert f.evidence["truncated"] is True
    assert f.confidence is Confidence.MEDIUM


def test_a_fully_read_robots_txt_omits_the_truncated_flag_on_every_such_check():
    """The documented contract (docs/methodology.md § Truncated documents):
    across these four checks the key is present iff the body was cut off, so
    its absence on one of them means "read in full" — never "this check does
    not report truncation"."""
    def handler(r):
        if r.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /private\n",
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    report = scan("https://example.com/", transport=httpx.MockTransport(handler))
    for cid in ROBOTS_BODY_CHECKS:
        f = next(x for x in report.findings if x.id == cid)
        assert "truncated" not in f.evidence, cid
        assert "read only in part" not in f.summary, cid


# ---------------------------------------------------------------------------
# redirect to a cloud metadata address — the entry URL is an ordinary public
# host (no `--allow-private-networks` opt-in); a redirect hop to the AWS/GCP
# metadata IP must be blocked before it is ever requested, and the whole
# scan must surface the block as a security-classified entry error.
# ---------------------------------------------------------------------------

def test_redirect_to_cloud_metadata_address_is_blocked_and_never_requested():
    def handler(r):
        if r.url.host == "169.254.169.254":
            raise AssertionError("must never request the cloud metadata host")
        if r.url.path == "/":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(404, text="not found")

    report = scan("https://example.com/", transport=httpx.MockTransport(handler))
    assert report.metrics["entry_error"] is not None
    assert report.metrics["entry_error"]["kind"] == "security"


# ---------------------------------------------------------------------------
# oversized llms.txt, end to end: a REAL HTTP server (not a MockTransport)
# whose /llms.txt body exceeds the client's byte cap for a "text" document.
# Every earlier instance of this defect class (Tasks 1-4) passed its own
# unit tests happily — this is the one test that drives fetch -> gatherer ->
# check -> rendered finding together and would have caught them.
# ---------------------------------------------------------------------------

def test_an_oversized_llms_txt_is_declared_as_a_partial_read_end_to_end(fixture_server):
    from scovant_core.checks._truncation import TRUNCATION_NOTE
    from scovant_core.report.text import render_text
    from scovant_core.security.policy import DEFAULT_SIZE_LIMITS

    cap = DEFAULT_SIZE_LIMITS["text"]
    fixture_server.write("llms.txt", b"# llms\n" + b"x" * (cap + 1024))

    report = scan(
        fixture_server.url_for("/"),
        ScanOptions(allow_private_networks=True),
    )
    llms = next(f for f in report.findings if f.id == "CORE-ACCESS-009")
    assert llms.evidence.get("truncated") is True
    assert TRUNCATION_NOTE.strip(" .") in llms.summary
    assert llms.confidence.value == "medium"
    # ...and the signal survives into the RENDERED report, not just the
    # in-memory Finding object — the "rendered finding" this test's module
    # comment refers to.
    assert TRUNCATION_NOTE.strip(" .") in render_text(report)
