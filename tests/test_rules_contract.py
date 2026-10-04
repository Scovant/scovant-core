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


def test_probe_measured_reads_a_reported_fetch_failure():
    failed = {"sitemap": {"exists": False, "valid": False, "fetch_status": "error",
                          "error": "ConnectError: boom"}}
    assert probe_measured(failed, CTX, "sitemap") is OutcomeState.NOT_MEASURED
    answered = {"sitemap": {"exists": False, "valid": False, "fetch_status": "ok", "error": None}}
    assert probe_measured(answered, CTX, "sitemap") is None
    # evidence written before the field existed, and a shared (not fetched) answer, are measured
    assert probe_measured({"sitemap": {"exists": False, "valid": False}}, CTX, "sitemap") is None
    assert probe_measured({"sitemap": {"exists": False, "fetch_status": "not_attempted"}}, CTX, "sitemap") is None


def test_every_rule_module_is_imported_by_the_package_init():
    import ast
    import pkgutil
    from pathlib import Path

    import scovant_core.rules as pkg

    tree = ast.parse(Path(pkg.__file__).read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module == "scovant_core.rules"
                for alias in node.names}
    modules = {m.name for m in pkgutil.iter_modules(pkg.__path__)} - {"base", "evidence"}
    assert modules <= imported, modules - imported


def test_finding_carries_an_optional_severity_and_weight():
    f = Finding("t", "d", "r")
    assert (f.severity, f.weight_multiplier) == (None, 1.0)
    g = Finding("t", "d", "r", severity="medium", weight_multiplier=0.25)
    assert (g.severity, g.weight_multiplier) == ("medium", 0.25)
    with pytest.raises(ValueError):
        Finding("t", "d", "r", severity="severe")
    for bad in (0.0, -0.5, 1.5):
        with pytest.raises(ValueError):
            Finding("t", "d", "r", weight_multiplier=bad)
