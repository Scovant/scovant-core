import re
from pathlib import Path

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

# Ruleset freeze (CONTRIBUTING.md § Ruleset freeze): the scored (non-experimental)
# check set for ruleset 2026.10, generated once via
#   python3 -c "from scovant_core.checks.registry import CHECKS; \
#       print(sorted(c.id for c in CHECKS if not c.experimental))"
# Never compute this inside the test — a literal is what makes the freeze real.
SCORED_2026_10 = [
    "CORE-ACCESS-001",
    "CORE-ACCESS-002",
    "CORE-ACCESS-003",
    "CORE-ACCESS-004",
    "CORE-ACCESS-005",
    "CORE-ACCESS-006",
    "CORE-ACCESS-007",
    "CORE-ACCESS-008",
    "CORE-ACCESS-009",
    "CORE-ACCESS-010",
    "CORE-INTERFACE-001",
    "CORE-INTERFACE-002",
    "CORE-INTERFACE-003",
    "CORE-INTERFACE-005",
    "CORE-INTERFACE-006",
    "CORE-INTERFACE-007",
    "CORE-MACHINE-001",
    "CORE-MACHINE-002",
    "CORE-MACHINE-003",
    "CORE-MACHINE-004",
    "CORE-MACHINE-005",
    "CORE-MACHINE-006",
    "CORE-MACHINE-007",
    "CORE-MACHINE-008",
    "CORE-MACHINE-009",
    "CORE-MACHINE-010",
    "CORE-MACHINE-011",
    "CORE-OPERABILITY-001",
    "CORE-OPERABILITY-002",
    "CORE-OPERABILITY-003",
    "CORE-OPERABILITY-004",
    "CORE-OPERABILITY-005",
    "CORE-OPERABILITY-006",
    "CORE-OPERABILITY-008",
    "CORE-OPERABILITY-009",
    "CORE-OPERABILITY-010",
    "CORE-TRUST-001",
    "CORE-TRUST-002",
    "CORE-TRUST-003",
    "CORE-TRUST-004",
    "CORE-TRUST-005",
    "CORE-TRUST-006",
    "CORE-TRUST-007",
]


def test_registry_is_valid():
    validate_registry()
    assert re.fullmatch(r"\d{4}\.\d{2}", RULESET_VERSION) and re.fullmatch(r"[0-9a-f]{12}", RULESET_DIGEST)


def test_registry_has_sixty_six():
    # Ruleset 2026.10 (readiness) ships 50 checks (see the old docstring
    # this replaces for the five-check delta over 2026.09); AS-1 layers 16
    # unscored SECURITY-category checks (CORE-SECURITY-001..016) on top,
    # grouped into four families (SEC-WEB, SEC-TXT, MACHINE-DATA,
    # PROMPT-SURFACE) — see docs/security.md.
    ids = {c.id for c in CHECKS}
    readiness_expected = {
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
    security_expected = {f"CORE-SECURITY-{n:03d}" for n in range(1, 17)}
    assert ids == readiness_expected | security_expected
    assert len(readiness_expected) == 50
    assert len(security_expected) == 16
    assert len(CHECKS) == 66
    assert RULESET_VERSION == "2026.10"
    validate_registry()


def test_experimental_set_is_exact():
    # D2: emerging protocols (INTERFACE-004/-008/-009, MACHINE-012), fragile
    # heuristics (OPERABILITY-007), the two 2026.10 additions whose
    # measurement is declared/link-based rather than a direct observation
    # (ACCESS-011 llms.txt utility, OPERABILITY-011 discovery linkage), and
    # the agentic-security SECURITY-* families added on top of the 2026.10
    # ruleset (AS-1): MACHINE-DATA-003/004 (SECURITY-009/010, data exposure —
    # name-based classification of declared interfaces/schema fields) and the
    # full PROMPT-SURFACE-001..006 family (SECURITY-011..016 — heuristic
    # pattern matches over machine-facing text; see checks/security/
    # prompt_surface.py) — all visible in reports but excluded from the
    # score unless `--experimental`.
    expected = {
        "CORE-INTERFACE-004", "CORE-INTERFACE-008", "CORE-INTERFACE-009",
        "CORE-MACHINE-012", "CORE-OPERABILITY-007",
        "CORE-ACCESS-011", "CORE-OPERABILITY-011",
        "CORE-SECURITY-009", "CORE-SECURITY-010",
        "CORE-SECURITY-011", "CORE-SECURITY-012", "CORE-SECURITY-013",
        "CORE-SECURITY-014", "CORE-SECURITY-015", "CORE-SECURITY-016",
    }
    experimental_ids = {c.id for c in CHECKS if c.experimental}
    assert experimental_ids == expected


def test_scored_set_is_exact():
    """Ruleset freeze (CONTRIBUTING § Ruleset freeze): the scored set changes only
    in a dedicated, calibrated PR that also bumps RULESET_VERSION.

    "Scored" is computed by excluding the SECURITY category, not just by
    `not c.experimental` — every SECURITY-category check is unscored BY
    CATEGORY (see `docs/security.md`), independent of its `experimental`
    flag. A scored, non-experimental SECURITY check would still never move
    the Static Signal Score, so it must never appear in `SCORED_2026_10`.
    """
    scored = sorted(c.id for c in CHECKS if not c.experimental and c.category != Category.SECURITY)
    assert RULESET_VERSION == "2026.10"
    assert scored == SCORED_2026_10, (
        "scored check set changed — this needs its own calibrated PR and a RULESET_VERSION bump "
        "(see CONTRIBUTING.md § Ruleset freeze)"
    )


def test_security_checks_declare_family_domain_owner_and_mode():
    sec = [c for c in CHECKS if c.category == Category.SECURITY]
    assert len(sec) == 16
    assert sorted(c.family_id for c in sec) == sorted([
        "SEC-WEB-001", "SEC-WEB-002", "SEC-WEB-003", "SEC-WEB-004", "SEC-WEB-005", "SEC-TXT-001",
        "MACHINE-DATA-001", "MACHINE-DATA-002", "MACHINE-DATA-003", "MACHINE-DATA-004",
        "PROMPT-SURFACE-001", "PROMPT-SURFACE-002", "PROMPT-SURFACE-003", "PROMPT-SURFACE-004",
        "PROMPT-SURFACE-005", "PROMPT-SURFACE-006",
    ])
    for c in sec:
        assert c.security_domain in {"web_baseline", "disclosure", "data_exposure", "prompt_surface"}, c.id
        assert c.fix_owner in {
            "frontend", "backend", "identity", "mcp", "edge_cdn", "devops", "content", "commerce",
            "security", "platform",
        }, c.id
        assert c.verification_mode in ("DECLARED", "PASSIVE_OBSERVED"), c.id
        assert c.standards, c.id


def test_experimental_checks_declare_promotion_criteria():
    """An unscored experimental check must state what it would take to score it —
    otherwise "experimental" is an indefinite parking space, not a stage."""
    missing = [c.id for c in CHECKS if c.experimental and not c.promotion_criteria.strip()]
    assert missing == [], f"experimental checks without promotion_criteria: {missing}"


def test_promotion_criteria_are_distinct_per_check():
    texts = [c.promotion_criteria.strip() for c in CHECKS if c.experimental]
    assert len(set(texts)) == len(texts), "promotion_criteria must be specific to each check"


def test_scored_checks_declare_no_promotion_criteria():
    extra = [c.id for c in CHECKS if not c.experimental and c.promotion_criteria.strip()]
    assert extra == [], f"scored checks must not carry promotion_criteria: {extra}"


def test_checks_md_lists_promotion_criteria_for_every_experimental_check():
    md = (Path(__file__).resolve().parents[1] / "docs" / "checks.md").read_text(encoding="utf-8")
    for c in CHECKS:
        if c.experimental:
            assert c.promotion_criteria in md, c.id


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
