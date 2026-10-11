"""Per-site coverage pin: which counted Technical rules Core cannot measure.

A "counted" rule is a Technical-manifest spec with maturity "required" and
score_effect WEIGHTED. On each golden site every counted rule must be measured
(PASS/WARN/FAIL) or N/A, except the explicit entries below.
"""
from __future__ import annotations

import datetime
import json

import pytest

from scovant_core.checks.access import core_access_006
from scovant_core.engine import scan
from scovant_core.gatherers import security_txt
from scovant_core.r2.manifest import ScoreEffect
from scovant_core.r2.technical import technical_manifest
from tests.conftest import FIXTURES, FixtureTransport

_MCP = "MCP_DISCOVERY_INVALID"  # endpoint declared; Core never performs the handshake

EXPECTED_NOT_MEASURED: dict[str, set[str]] = {
    "commerce-good": {_MCP},
    "commerce-bad": set(),
    "api-good": set(),
    "saas-mixed": set(),
    "security-good": {_MCP},
    "security-bad": {_MCP},
    "oauth-good": set(),
    "oauth-bad": set(),
}
MEASURED_STATES = {"PASS", "WARN", "FAIL", "N/A"}


def _counted() -> set[str]:
    return {s.rule_id for s in technical_manifest().specs
            if s.maturity == "required" and s.score_effect == ScoreEffect.WEIGHTED}


@pytest.fixture(scope="module")
def reports():
    today = datetime.date(2026, 9, 4)
    mp = pytest.MonkeyPatch()
    mp.setattr(core_access_006, "today", lambda: today)
    mp.setattr(security_txt, "today", lambda: today)
    out = {}
    for site in EXPECTED_NOT_MEASURED:
        r = scan("https://example.com/", transport=FixtureTransport(FIXTURES / "sites" / site),
                 clock=lambda: "2026-09-04T00:00:00Z", scan_id="local-golden")
        out[site] = json.loads(r.model_dump_json())
    mp.undo()
    return out


def test_counted_set_is_the_expected_size():
    assert len(_counted()) == 31


@pytest.mark.parametrize("site", sorted(EXPECTED_NOT_MEASURED))
def test_not_measured_counted_rules_are_exactly_the_expected_set(site, reports):
    listed = {x["rule"] for x in reports[site]["readiness"]["technical"]["not_measured"]}
    assert listed & _counted() == EXPECTED_NOT_MEASURED[site]


@pytest.mark.parametrize("site", sorted(EXPECTED_NOT_MEASURED))
def test_every_counted_outcome_is_measured_or_na_except_listed(site, reports):
    outcomes = {o["rule"]: o["state"] for o in reports[site]["technical_outcomes"]}
    counted = _counted()
    assert counted <= set(outcomes)
    unmeasured = {c for c in counted if outcomes[c] not in MEASURED_STATES}
    assert unmeasured == EXPECTED_NOT_MEASURED[site]
