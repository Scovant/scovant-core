"""Score-neutrality tripwire (AS-1 §D3): SECURITY-category findings must
never move the Static Signal Score, a category score, or a readiness
finding's own verdict. Comparing a scan WITH security checks against the
same scan run with `exclude=("security",)` is the only way to prove that —
a passing test here means the security category really is layered on top
of the existing readiness engine, not wired into it."""
import httpx
import pytest

from scovant_core.checks.access import core_access_006
from scovant_core.context import ScanOptions
from scovant_core.engine import scan
from scovant_core.gatherers import security_txt
from scovant_core.models import CheckStatus
from tests.conftest import FIXTURES, FixtureTransport
from tests.test_golden import CLOCK, FROZEN_TODAY, SITES


@pytest.mark.parametrize("site", SITES)
def test_score_and_categories_identical_with_and_without_security(site, monkeypatch):
    # Freeze "today" exactly as test_golden.py does — CORE-ACCESS-006 and
    # gatherers.security_txt are the only checks that read real wall-clock
    # time, and a midnight rollover between the two scans below could
    # otherwise flip an expiry-dependent verdict between them and fail this
    # test for a reason that has nothing to do with score neutrality.
    monkeypatch.setattr(core_access_006, "today", lambda: FROZEN_TODAY)
    monkeypatch.setattr(security_txt, "today", lambda: FROZEN_TODAY)
    a = scan(
        "https://example.com/", ScanOptions(),
        transport=FixtureTransport(FIXTURES / "sites" / site), clock=CLOCK, scan_id="x",
    )
    b = scan(
        "https://example.com/", ScanOptions(exclude=("security",)),
        transport=FixtureTransport(FIXTURES / "sites" / site), clock=CLOCK, scan_id="x",
    )
    assert a.score.value == b.score.value and a.score.coverage == b.score.coverage
    assert {k: v.score for k, v in a.categories.items()} == {k: v.score for k, v in b.categories.items()}
    readiness_a = {f.id: (f.status, f.severity, f.evidence) for f in a.findings if f.category.value != "security"}
    readiness_b = {f.id: (f.status, f.severity, f.evidence) for f in b.findings}
    assert readiness_a == readiness_b


class _SecurityTxtUnreachable(FixtureTransport):
    """Serves the fixture site normally EXCEPT for the two security.txt
    paths, which raise a transport error — the shape of a host that answers
    every other request but times out (or resets) on that one document.
    `gatherers.security_txt` turns that into `status=None`, which is
    CORE-SECURITY-006's ERROR branch."""

    BLOCKED = ("/.well-known/security.txt", "/security.txt")

    def handle_request(self, request):
        if request.url.path in self.BLOCKED:
            raise httpx.ConnectError("connection reset", request=request)
        return super().handle_request(request)


def _content_scan(transport, monkeypatch):
    # `profile="content"` is the point of the scenario, not a convenience:
    # CORE-TRUST-006 is gated to saas/api/commerce, so on a content profile
    # security.txt is read for CORE-SECURITY-006 ALONE. An error there is
    # therefore a security-only error — the exact case that must not touch
    # the readiness score.
    monkeypatch.setattr(core_access_006, "today", lambda: FROZEN_TODAY)
    monkeypatch.setattr(security_txt, "today", lambda: FROZEN_TODAY)
    return scan(
        "https://example.com/", ScanOptions(profile="content"),
        transport=transport, clock=CLOCK, scan_id="x",
    )


def test_security_only_error_never_degrades_the_readiness_score(monkeypatch):
    site = FIXTURES / "sites" / "commerce-good"
    clean = _content_scan(FixtureTransport(site), monkeypatch)
    broken = _content_scan(_SecurityTxtUnreachable(site), monkeypatch)

    # The scenario is only meaningful if the clean run really did earn a
    # grade under a CANONICAL scope — otherwise "the score did not change"
    # would be trivially true of two ungraded reports.
    assert clean.score.grade is not None and clean.score.scope == "CANONICAL"
    sec006 = {f.id: f for f in broken.findings}["CORE-SECURITY-006"]
    assert sec006.status == CheckStatus.ERROR
    assert {f.id: f.status for f in broken.findings}["CORE-TRUST-006"] == CheckStatus.NA

    # The WHOLE Score object: value, grade, coverage, status AND scope.
    assert broken.score == clean.score
    assert {k: v.score for k, v in broken.categories.items()} == {k: v.score for k, v in clean.categories.items()}

    assert broken.metrics["security_error_count"] == 1
    assert broken.metrics["error_count"] == 1  # the total still reports it
    assert clean.metrics["security_error_count"] == 0
