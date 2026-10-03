"""scovant_core.rules: the contract a migrated rule implements."""
import pytest

from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, CoreRule, Finding, MeasureCtx, probe_measured, register_rule

CTX = MeasureCtx(site_category="blog", defaulted=frozenset())


def test_probe_measured_reads_like_the_cloud_probe():
    assert probe_measured(None, CTX, "sitemap") is OutcomeState.NOT_MEASURED
    assert probe_measured({}, CTX, "sitemap") is OutcomeState.NOT_MEASURED
    assert probe_measured({"sitemap": None}, CTX, "sitemap") is OutcomeState.NOT_MEASURED
    ctx = MeasureCtx(site_category=None, defaulted=frozenset({"sitemap"}))
    assert probe_measured({"sitemap": {"valid": True}}, ctx, "sitemap") is OutcomeState.NOT_MEASURED
    assert probe_measured({"sitemap": {"valid": True}}, CTX, "sitemap") is None
    # defaulted=None: the snapshot predates the marker — measured as before
    old = MeasureCtx(site_category=None, defaulted=None)
    assert probe_measured({"sitemap": {}}, old, "sitemap") is None


def test_register_rule_refuses_a_duplicate_code():
    before = list(RULES)

    @register_rule
    class _R(CoreRule):
        code, category, severity, title = "TEST-DUP-1", "discoverability", "low", "t"

        def evaluate(self, page, domain):
            return []

        def measure(self, page, domain, ctx):
            return None

    try:
        with pytest.raises(ValueError):
            @register_rule
            class _R2(_R):
                pass
    finally:
        RULES[:] = before


def test_finding_defaults_are_independent():
    a, b = Finding("t", "d", "r"), Finding("t", "d", "r")
    assert a.metadata == {} and a.metadata is not b.metadata and a.example is None and a.url is None
