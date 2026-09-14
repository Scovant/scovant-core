import re

import httpx
import pytest

from scovant_core.checks import registry as registry_module
from scovant_core.checks.base import CoreCheck
from scovant_core.checks.registry import (
    CHECKS,
    RULESET_DIGEST,
    RULESET_VERSION,
    ruleset_digest,
    validate_registry,
)
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import EvidenceStore, EvidenceUnavailable, GatherError
from scovant_core.models import Category, CheckStatus, Severity
from tests.conftest import make_client


def test_registry_is_valid():
    validate_registry()
    assert re.fullmatch(r"\d{4}\.\d{2}", RULESET_VERSION) and re.fullmatch(r"[0-9a-f]{12}", RULESET_DIGEST)


def test_registry_has_fifty():
    # Ruleset 2026.10 adds five checks over the 2026.09 registry: the three
    # required HTTP-semantics checks (CORE-OPERABILITY-008/009/010) plus two
    # experimental discoverability/utility checks (CORE-ACCESS-011,
    # CORE-OPERABILITY-011).
    ids = {c.id for c in CHECKS}
    expected = {
        "CORE-ACCESS-001", "CORE-ACCESS-002", "CORE-ACCESS-003", "CORE-ACCESS-004", "CORE-ACCESS-005",
        "CORE-ACCESS-006", "CORE-ACCESS-007", "CORE-ACCESS-008", "CORE-ACCESS-009", "CORE-ACCESS-010",
        "CORE-ACCESS-011",
        "CORE-MACHINE-001", "CORE-MACHINE-002", "CORE-MACHINE-003", "CORE-MACHINE-004", "CORE-MACHINE-005",
        "CORE-MACHINE-006", "CORE-MACHINE-007", "CORE-MACHINE-008", "CORE-MACHINE-009", "CORE-MACHINE-010",
        "CORE-MACHINE-011", "CORE-MACHINE-012",
        "CORE-INTERFACE-001", "CORE-INTERFACE-002", "CORE-INTERFACE-003", "CORE-INTERFACE-004",
        "CORE-INTERFACE-005", "CORE-INTERFACE-006", "CORE-INTERFACE-007", "CORE-INTERFACE-008",
        "CORE-INTERFACE-009",
        "CORE-TRUST-001", "CORE-TRUST-002", "CORE-TRUST-003", "CORE-TRUST-004", "CORE-TRUST-005",
        "CORE-TRUST-006", "CORE-TRUST-007",
        "CORE-OPERABILITY-001", "CORE-OPERABILITY-002", "CORE-OPERABILITY-003", "CORE-OPERABILITY-004",
        "CORE-OPERABILITY-005", "CORE-OPERABILITY-006", "CORE-OPERABILITY-007", "CORE-OPERABILITY-008",
        "CORE-OPERABILITY-009", "CORE-OPERABILITY-010", "CORE-OPERABILITY-011",
    }
    assert ids == expected
    assert len(CHECKS) == 50
    assert RULESET_VERSION == "2026.10"
    validate_registry()


def test_experimental_set_is_exact():
    # D2: exactly these seven checks are experimental — emerging protocols
    # (INTERFACE-004/-008/-009, MACHINE-012), fragile heuristics
    # (OPERABILITY-007), and the two 2026.10 additions whose measurement is
    # declared/link-based rather than a direct observation
    # (ACCESS-011 llms.txt utility, OPERABILITY-011 discovery linkage) —
    # visible in reports but excluded from the score unless `--experimental`.
    expected = {
        "CORE-INTERFACE-004", "CORE-INTERFACE-008", "CORE-INTERFACE-009",
        "CORE-MACHINE-012", "CORE-OPERABILITY-007",
        "CORE-ACCESS-011", "CORE-OPERABILITY-011",
    }
    experimental_ids = {c.id for c in CHECKS if c.experimental}
    assert experimental_ids == expected


def test_every_check_has_docs_fields():
    for c in CHECKS:
        assert c.why_it_matters and c.limitations and c.references, c.id


def test_ruleset_digest_is_twelve_hex_chars():
    assert re.fullmatch(r"[0-9a-f]{12}", ruleset_digest())


def _ctx(profile: str = "web") -> ScanContext:
    ctx = ScanContext(input_url="https://example.com", options=ScanOptions())
    ctx.resolved_profile = profile
    return ctx


def _store(ctx: ScanContext) -> EvidenceStore:
    return EvidenceStore(make_client(lambda r: httpx.Response(404)), ctx)


class _BoomEvidenceCheck(CoreCheck):
    id = "CORE-ACCESS-999"
    title = "throwaway: raises EvidenceUnavailable"
    category = Category.ACCESS
    weight = 1
    severity_on_fail = Severity.LOW
    why_it_matters = "test fixture"
    limitations = "test fixture"
    references = ("https://example.com",)

    def evaluate(self, store, ctx):
        raise EvidenceUnavailable(GatherError(name="fixture", kind="TestError", message="boom"))


class _BoomBugCheck(CoreCheck):
    id = "CORE-ACCESS-998"
    title = "throwaway: raises a plain bug"
    category = Category.ACCESS
    weight = 1
    severity_on_fail = Severity.LOW
    why_it_matters = "test fixture"
    limitations = "test fixture"
    references = ("https://example.com",)

    def evaluate(self, store, ctx):
        raise ValueError("kaboom")


class _WebOnlyCheck(CoreCheck):
    id = "CORE-ACCESS-997"
    title = "throwaway: web-profile-only"
    category = Category.ACCESS
    profiles = frozenset({"web"})
    weight = 1
    severity_on_fail = Severity.LOW
    why_it_matters = "test fixture"
    limitations = "test fixture"
    references = ("https://example.com",)

    def evaluate(self, store, ctx):
        raise AssertionError("evaluate must not be called for a non-applicable profile")


def test_run_converts_evidence_unavailable_to_error():
    ctx = _ctx()
    result = _BoomEvidenceCheck().run(_store(ctx), ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["gather_error"] == {"name": "fixture", "kind": "TestError", "message": "boom"}


def test_run_converts_any_exception_to_error():
    ctx = _ctx()
    result = _BoomBugCheck().run(_store(ctx), ctx)
    assert result.status == CheckStatus.ERROR
    assert "ValueError" in result.summary


def test_run_returns_na_for_non_applicable_profile():
    ctx = _ctx(profile="api")
    result = _WebOnlyCheck().run(_store(ctx), ctx)
    assert result.status == CheckStatus.NA


class _BadIdCheck(CoreCheck):
    id = "CORE-ACCESS-001\n"
    title = "throwaway: trailing-newline id"
    category = Category.ACCESS
    weight = 1
    why_it_matters = "test fixture"
    limitations = "test fixture"
    references = ("https://example.com",)

    def evaluate(self, store, ctx):
        raise NotImplementedError


class _MismatchedCategoryCheck(CoreCheck):
    id = "CORE-TRUST-001"
    title = "throwaway: id/category mismatch"
    category = Category.ACCESS
    weight = 1
    why_it_matters = "test fixture"
    limitations = "test fixture"
    references = ("https://example.com",)

    def evaluate(self, store, ctx):
        raise NotImplementedError


def test_validate_registry_rejects_id_with_trailing_newline():
    registry_module.CHECKS.append(_BadIdCheck())
    try:
        with pytest.raises(ValueError):
            validate_registry()
    finally:
        registry_module.CHECKS.pop()


def test_validate_registry_rejects_category_mismatch():
    registry_module.CHECKS.append(_MismatchedCategoryCheck())
    try:
        with pytest.raises(ValueError):
            validate_registry()
    finally:
        registry_module.CHECKS.pop()
