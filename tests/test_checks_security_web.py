"""CORE-SECURITY-001..006 — web security baseline + security.txt validity."""
from __future__ import annotations

import datetime

import httpx

import scovant_core.gatherers._register  # noqa: F401
from scovant_core.checks.security.web import (
    CookieAttributes,
    CspFraming,
    Hsts,
    HttpsBaseline,
    ReferrerMimeHygiene,
    SecurityTxtValidity,
)
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore
from scovant_core.gatherers import security_txt as sec_mod
from scovant_core.models import CheckStatus, Confidence, Severity
from scovant_core.profiles import apply_profile

from .conftest import FIXTURES, FixtureTransport, make_client

_MIN = "<!doctype html><html><head><title>T</title></head><body><h1>T</h1><p>" + "words " * 40 + "</p></body></html>"


def _fixture(name: str, url="https://example.com/"):
    client = make_client(FixtureTransport(FIXTURES / "security" / name))
    ctx = ScanContext(url, ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


def _mock(handler, url="https://example.com/"):
    client = make_client(handler)
    ctx = ScanContext(url, ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


def test_ids_and_families():
    pairs = [
        (HttpsBaseline, "CORE-SECURITY-001", "SEC-WEB-001"),
        (Hsts, "CORE-SECURITY-002", "SEC-WEB-002"),
        (CspFraming, "CORE-SECURITY-003", "SEC-WEB-003"),
        (CookieAttributes, "CORE-SECURITY-004", "SEC-WEB-004"),
        (ReferrerMimeHygiene, "CORE-SECURITY-005", "SEC-WEB-005"),
        (SecurityTxtValidity, "CORE-SECURITY-006", "SEC-TXT-001"),
    ]
    for cls, cid, fam in pairs:
        assert (cls.id, cls.family_id) == (cid, fam) and cls.fix_owner


def test_https_baseline_pass_on_good_fixture():
    store, ctx = _fixture("web-headers-good")
    r = HttpsBaseline().run(store, ctx)
    assert r.status == CheckStatus.PASS and r.evidence["redirected_to_https"] is True


def test_https_baseline_warn_when_http_serves_200():
    def handler(req):
        if req.url.scheme == "http":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN)
        return httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN)
    store, ctx = _mock(handler)
    assert HttpsBaseline().run(store, ctx).status == CheckStatus.WARN


def test_https_baseline_fail_when_entry_is_http():
    store, ctx = _mock(lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN), url="http://example.com/")
    r = HttpsBaseline().run(store, ctx)
    assert r.status == CheckStatus.FAIL and r.severity == Severity.MEDIUM


def test_hsts_pass_warn_na():
    good, ctx = _fixture("web-headers-good")
    assert Hsts().run(good, ctx).status == CheckStatus.PASS
    weak, ctx = _fixture("web-headers-weak")
    assert Hsts().run(weak, ctx).status == CheckStatus.WARN
    store, ctx = _mock(lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN), url="http://example.com/")
    assert Hsts().run(store, ctx).status == CheckStatus.NA


def test_csp_framing_pass_warn_fail():
    good, ctx = _fixture("web-headers-good")
    assert CspFraming().run(good, ctx).status == CheckStatus.PASS
    weak, ctx = _fixture("web-headers-weak")
    assert CspFraming().run(weak, ctx).status == CheckStatus.WARN  # CSP w/o frame-ancestors, no XFO
    store, ctx = _mock(lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN))
    assert CspFraming().run(store, ctx).status == CheckStatus.FAIL


def test_cookie_attributes_fail_on_weak_session_cookie_and_never_stores_values():
    store, ctx = _fixture("cookies-session-weak")
    r = CookieAttributes().run(store, ctx)
    assert r.status == CheckStatus.FAIL
    assert "SESSIONVALUE" not in str(r.evidence)
    assert r.evidence["cookies"][0]["classification"] == "session_like"


def test_cookie_attributes_na_without_cookies_and_analytics_ignored():
    store, ctx = _mock(lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text=_MIN))
    assert CookieAttributes().run(store, ctx).status == CheckStatus.NA
    store, ctx = _mock(lambda req: httpx.Response(200, headers=[("content-type", "text/html"), ("set-cookie", "_ga=1; Max-Age=1")], text=_MIN))
    assert CookieAttributes().run(store, ctx).status == CheckStatus.PASS


def test_referrer_mime_pass_and_warn_lists_missing():
    good, ctx = _fixture("web-headers-good")
    assert ReferrerMimeHygiene().run(good, ctx).status == CheckStatus.PASS
    weak, ctx = _fixture("web-headers-weak")
    r = ReferrerMimeHygiene().run(weak, ctx)
    assert r.status == CheckStatus.WARN and set(r.evidence["missing"]) == {"referrer-policy", "x-content-type-options"}


def test_security_txt_validity(monkeypatch):
    monkeypatch.setattr(sec_mod, "today", lambda: datetime.date(2026, 9, 16))
    ok, ctx = _fixture("security-txt-valid")
    assert SecurityTxtValidity().run(ok, ctx).status == CheckStatus.PASS
    exp, ctx = _fixture("security-txt-expired")
    r = SecurityTxtValidity().run(exp, ctx)
    assert r.status == CheckStatus.FAIL and r.evidence["expired"] is True
    none, ctx = _fixture("web-headers-good")
    assert SecurityTxtValidity().run(none, ctx).status == CheckStatus.NA
    assert SecurityTxtValidity.verification_mode == "DECLARED"


def test_security_txt_validity_declares_a_partial_read_when_truncated(monkeypatch):
    # A real security.txt document, long enough to be cut off by a small
    # size cap (`make_client(..., size_limits={"text": ...})`), but with its
    # Contact/Expires lines well inside that cap so the fields the check
    # reads still parse — proving the truncation note/confidence are wired
    # in ADDITION to (not instead of) a correctly-parsed verdict.
    monkeypatch.setattr(sec_mod, "today", lambda: datetime.date(2026, 9, 16))
    body = "Contact: mailto:security@example.com\nExpires: 2027-06-01T00:00:00Z\n" + ("x" * 2000)

    def handler(req):
        if req.url.path == "/.well-known/security.txt":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text=body)
        return httpx.Response(404, text="not found")

    client = make_client(handler, size_limits={"text": 100})
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)

    r = SecurityTxtValidity().run(store, ctx)
    assert r.status == CheckStatus.PASS
    assert r.evidence["truncated"] is True
    assert r.confidence == Confidence.MEDIUM
    assert "read only in part" in r.summary
