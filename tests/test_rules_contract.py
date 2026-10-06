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
        code, category, severity, title, since = "TEST-DUP-1", "discoverability", "low", "t", "0.12.0"

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


def test_a_finding_may_carry_another_issue_code():
    assert Finding("t", "d", "r").code is None
    assert Finding("t", "d", "r", code="TEST-ALIAS").code == "TEST-ALIAS"
    for bad in ("", "  ", 7):
        with pytest.raises(ValueError):
            Finding("t", "d", "r", code=bad)


def test_register_rule_refuses_a_code_or_alias_that_is_already_claimed():
    before = list(RULES)
    try:
        @register_rule
        class _A(CoreRule):
            code, category, severity, title, since = "TEST-ALIAS-1", "citability", "low", "t", "0.12.0"
            aliases = ("TEST-ALIAS-2",)

            def evaluate(self, page, domain):
                return []

            def measure(self, page, domain, ctx):
                return None

        assert _A.aliases == ("TEST-ALIAS-2",) and CoreRule.aliases == ()
        for code, aliases in (("TEST-ALIAS-2", ()), ("TEST-ALIAS-3", ("TEST-ALIAS-1",)),
                              ("TEST-ALIAS-4", ("TEST-ALIAS-2",))):
            with pytest.raises(ValueError):
                register_rule(type("_B", (_A,), {"code": code, "aliases": aliases}))
        register_rule(type("_C", (_A,), {"code": "TEST-ALIAS-5", "aliases": ()}))
    finally:
        RULES[:] = before


def test_register_rule_refuses_malformed_aliases():
    """`aliases` is a tuple of other codes: a bare string (a forgotten comma)
    would make every substring of it look declared, and claim its characters."""
    before = list(RULES)

    def _rule(code, aliases):
        return type("_M", (CoreRule,), {
            "code": code, "category": "citability", "severity": "low", "title": "t",
            "aliases": aliases, "since": "0.12.0",
            "evaluate": lambda self, page, domain: [],
            "measure": lambda self, page, domain, ctx: None,
        })

    try:
        for bad in ("TEST-MAL-POOR", ["TEST-MAL-POOR"], ("",), ("  ",), (7,), ("TEST-MAL-1",),
                    ("TEST-MAL-A", "TEST-MAL-A")):
            with pytest.raises(ValueError):
                register_rule(_rule("TEST-MAL-1", bad))
        assert [r.code for r in RULES] == [r.code for r in before]  # nothing was claimed
        register_rule(_rule("TEST-MAL-1", ("TEST-MAL-POOR",)))
    finally:
        RULES[:] = before


def test_register_rule_requires_a_release_in_since():
    """`since` names the release that first shipped the rule; a host's catalog
    states "computed by Scovant Core ≥ since", so it must be a real version
    string, never the empty default."""
    before = list(RULES)

    def _rule(since):
        return type("_S", (CoreRule,), {
            "code": "TEST-SINCE-1", "category": "citability", "severity": "low", "title": "t",
            "since": since,
            "evaluate": lambda self, page, domain: [],
            "measure": lambda self, page, domain, ctx: None,
        })

    try:
        for bad in ("", "0.9", "v0.9.0", 9, None, "0.9.0-rc1"):
            with pytest.raises(ValueError):
                register_rule(_rule(bad))
        assert [r.code for r in RULES] == [r.code for r in before]
        register_rule(_rule("0.9.0"))
    finally:
        RULES[:] = before


def test_every_rule_since_is_a_released_version_not_after_this_one():
    import re
    from pathlib import Path

    from packaging.version import Version

    import scovant_core

    changelog = (Path(scovant_core.__file__).resolve().parents[2] / "CHANGELOG.md").read_text(encoding="utf-8")
    released = set(re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, re.M))
    current = Version(scovant_core.__version__)
    for rule in RULES:
        assert rule.since in released, f"{rule.code}: since {rule.since} is not a CHANGELOG release"
        assert Version(rule.since) <= current, f"{rule.code}: since {rule.since} is after {current}"
