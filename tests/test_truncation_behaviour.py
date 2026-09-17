"""A verdict drawn from a truncated document must say so — on the PASS path
and on the FAIL path. Truncation most often inverts exactly the verdicts that
assert absence, so a note that appears only on PASS is the over-claim this
contract exists to remove."""
from __future__ import annotations

import pytest

from scovant_core.models import CheckStatus, Confidence

# The half of the note's wording that is invariant regardless of whether a
# caller named its document (record_truncation's `document=` kwarg) or fell
# back to the generic wording — CORE-ACCESS-009 names "llms.txt", so this
# must NOT assert the exact generic TRUNCATION_NOTE text, only the tail every
# variant shares.
_TRUNCATION_TAIL = "was read only in part, so anything past the cap is not reflected in this verdict"


def _finding(check, store, ctx):
    out = check.evaluate(store, ctx)   # registry.CHECKS holds INSTANCES
    return out[0] if isinstance(out, list) else out


# CORE-OPERABILITY-004 does NOT participate: its verdict is drawn entirely
# from HTTP status codes resolved by `machine_links` ("is this reference
# broken"), and that record carries no `truncated` key at all — a body cut
# off at the fetch cap never changes a real status code. This mirrors the
# already-excluded CORE-ACCESS-001: reading a record that HAS a
# `truncated` flag is not sufficient, the verdict must be drawn from BODY
# CONTENT that could have been cut off. CORE-OPERABILITY-001 (server-rendered
# core content) is used here instead — it reads the entry page's own parsed
# body text and raw HTML, exactly the shape CORE-MACHINE-001 already covers,
# and both categories still get one representative check exercised.
@pytest.mark.parametrize("check_id", ["CORE-ACCESS-009", "CORE-MACHINE-001",
                                       "CORE-INTERFACE-005", "CORE-TRUST-006", "CORE-OPERABILITY-001"])
def test_a_truncated_source_is_declared_on_every_branch(check_id, truncated_store, ctx):
    from scovant_core.checks import registry

    check = next(c for c in registry.CHECKS if c.id == check_id)
    f = _finding(check, truncated_store, ctx)
    assert f.evidence.get("truncated") is True
    assert f.confidence is Confidence.MEDIUM
    assert _TRUNCATION_TAIL in f.summary
    # whatever the verdict is, it is unchanged by truncation
    assert f.status in {CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL,
                        CheckStatus.NA, CheckStatus.ERROR}


@pytest.mark.parametrize("check_id", ["CORE-ACCESS-009", "CORE-MACHINE-001",
                                       "CORE-INTERFACE-005", "CORE-TRUST-006", "CORE-OPERABILITY-001"])
def test_an_untruncated_source_writes_no_flag_and_keeps_high_confidence(check_id, full_store, ctx):
    from scovant_core.checks import registry

    check = next(c for c in registry.CHECKS if c.id == check_id)
    f = _finding(check, full_store, ctx)
    assert "truncated" not in f.evidence
    assert _TRUNCATION_TAIL not in f.summary


# The check ids expected to actually carry `evidence["truncated"]` in the
# TRUNCATED run — pinned, not merely `any(...)`, so this test is
# self-defending: if a future fixture edit stops one of these checks from
# reaching its real truncation-aware branch (the exact class of defect this
# whole file exists to catch, one level up — `_pages_record()` was once too
# thin for CORE-MACHINE-002/003/008/009/010 in exactly this way), the SET
# comparison below fails loudly and names what disappeared, instead
# of the `any(...)` check quietly continuing to pass with fewer
# participants. Every id here is APPLICABLE under the `ctx` fixture's
# "auto" profile and reads a genuinely truncated record through a real
# `record_truncation()` call — the profile-restricted flag-capable checks
# (`oauth_metadata`/`ucp`/`agent_discovery_surface`/policy-page siblings
# other than privacy/`CORE-OPERABILITY-006`/`CORE-TRUST-006`) are excluded
# on purpose: `run()`'s `applicable()` gate returns the same NA on both
# sides for those before `evaluate()` is ever reached, so no fixture data
# could make them participate here (see `conftest.py`'s comment on the
# five new record builders for the full reasoning).
EXPECTED_TRUNCATION_FLAGGED_IDS = frozenset({
    "CORE-ACCESS-005", "CORE-ACCESS-006", "CORE-ACCESS-007", "CORE-ACCESS-008", "CORE-ACCESS-009",
    "CORE-MACHINE-001", "CORE-MACHINE-002", "CORE-MACHINE-003", "CORE-MACHINE-008", "CORE-MACHINE-009",
    "CORE-MACHINE-010",
    "CORE-INTERFACE-001", "CORE-INTERFACE-002", "CORE-INTERFACE-003", "CORE-INTERFACE-004",
    "CORE-TRUST-001", "CORE-TRUST-004",
    "CORE-OPERABILITY-001", "CORE-OPERABILITY-005", "CORE-OPERABILITY-007",
    # CORE-SECURITY-009 (PrivilegedEndpoint) reads `mcp_discovery["truncated"]`
    # and `openapi["truncated"]` directly (not through `machine_text`'s own
    # per-surface re-slicing), and both stub records set `truncated=True` —
    # a genuine participant, not an artifact of this fixture.
    "CORE-SECURITY-009",
    # CORE-SECURITY-010 (SensitiveSchemaField): `_openapi_record` in this
    # conftest carries no `schemas` key at all, so `api.get("schemas")` is
    # falsy on BOTH stores and the check reaches its N/A branch — which
    # (fix round 1) now checks `openapi["truncated"]` before declaring
    # absence and discloses it (`{"truncated": True}` + MEDIUM confidence)
    # on the truncated side. Also genuine, not a fixture artifact.
    "CORE-SECURITY-010",
})


def test_truncation_changes_confidence_and_evidence_but_never_status_or_score(
        truncated_store, full_store, ctx):
    """The whole plan is an honesty change, not a scoring change: every
    check's verdict (status) and the resulting composite score must be
    identical whether the underlying document was read in full or cut off
    at the fetch cap — only the evidence flag/confidence/summary wording may
    differ. Runs through `run()` (not the raw `evaluate()`), exactly the
    entry point the real engine uses, so a check whose evidence dependency
    isn't preloaded on these two stores degrades to ERROR the same way on
    both sides instead of raising out of the test."""
    import scovant_core.gatherers._register  # noqa: F401 — registers every real gatherer
    from scovant_core.checks import registry
    from scovant_core.scoring import score_results

    def run(store):
        return [check.run(store, ctx) for check in registry.CHECKS]

    a, b = run(full_store), run(truncated_store)
    assert [f.status for f in a] == [f.status for f in b]
    assert score_results(a) == score_results(b)
    flagged_ids = {f.id for f in b if f.evidence.get("truncated")}
    assert flagged_ids == EXPECTED_TRUNCATION_FLAGGED_IDS


# ---------------------------------------------------------------------------
# The runtime half of the per-branch guarantee. `test_truncation_check_
# completeness.py` proves statically that every verdict branch WIRES both
# halves of the disclosure in; what it cannot see is whether a branch's
# PREDICATE points the flag at the right cases — CORE-ACCESS-006's N/A, for
# instance, must declare when an invalid sitemap body was read only in part
# and must stay silent when the sitemap is simply absent. These reproduce
# both, over the same record two checks read, which is where the drift the
# whole contract exists to prevent actually showed up: one truncated sitemap
# produced CORE-ACCESS-005 `WARN` + note + MEDIUM beside CORE-ACCESS-006
# `N/A` + no flag + HIGH — two findings telling one report's reader two
# different stories about how completely we read one document.

def _check(check_id):
    from scovant_core.checks import registry

    return next(c for c in registry.CHECKS if c.id == check_id)


def test_a_truncated_unparseable_sitemap_is_declared_by_both_sitemap_checks(truncated_store, ctx):
    truncated_store._data["sitemap_urls"] = {
        **truncated_store._data["sitemap_urls"],
        "valid": False, "kind": None, "entries": [], "parse_error": "mismatched tag: line 1, column 0",
    }
    availability = _finding(_check("CORE-ACCESS-005"), truncated_store, ctx)
    freshness = _finding(_check("CORE-ACCESS-006"), truncated_store, ctx)

    assert availability.status is CheckStatus.WARN
    assert freshness.status is CheckStatus.NA
    for f in (availability, freshness):
        assert f.evidence.get("truncated") is True, f.id
        assert f.confidence is Confidence.MEDIUM, f.id
        assert _TRUNCATION_TAIL in f.summary, f.id


def test_an_absent_sitemap_stays_silent_even_when_some_other_body_was_cut(truncated_store, ctx):
    """The other direction, and the reason a blanket flag would be wrong: a
    soft-404 HTML catch-all establishes absence from the response's shape, not
    from the sitemap body — `body_truncated` here belongs to that unrelated
    oversized HTML page. Neither check may claim its own verdict was degraded."""
    truncated_store._data["sitemap_urls"] = {
        **truncated_store._data["sitemap_urls"],
        "exists": False, "url": None, "valid": False, "kind": None, "entries": [],
        "served_as_html": True, "probe_status": 200,
    }
    for check_id in ("CORE-ACCESS-005", "CORE-ACCESS-006"):
        f = _finding(_check(check_id), truncated_store, ctx)
        assert "truncated" not in f.evidence, check_id
        assert f.confidence is Confidence.HIGH, check_id
        assert _TRUNCATION_TAIL not in f.summary, check_id


@pytest.mark.parametrize("check_id", ["CORE-MACHINE-005", "CORE-MACHINE-006", "CORE-MACHINE-012"])
def test_a_delegating_na_over_truncated_pages_still_declares(check_id, truncated_store, ctx):
    """"No page exposes a Product entity" is an absence claim read out of the
    sampled page bodies — delegating the verdict to CORE-MACHINE-004 does not
    make silence honest, because this finding is published on its own, with
    its own confidence. The fixture's entry page carries no Product node, so
    all three checks reach their N/A branch."""
    ctx.resolved_profile = "commerce"
    f = _finding(_check(check_id), truncated_store, ctx)
    assert f.status is CheckStatus.NA
    assert f.evidence.get("truncated") is True
    assert f.confidence is Confidence.MEDIUM
    assert _TRUNCATION_TAIL in f.summary


def test_the_pricing_absence_verdict_declares_its_partly_read_sources(truncated_store, ctx):
    """CORE-TRUST-007's final N/A rests on three truncatable bodies at once —
    the entry page whose links are the only route to a pricing page, each
    fetched policy page, and the sampled product pages — so it declares
    whenever any of them was cut off."""
    ctx.resolved_profile = "commerce"
    f = _finding(_check("CORE-TRUST-007"), truncated_store, ctx)
    assert f.status is CheckStatus.NA
    assert f.evidence.get("truncated") is True
    assert f.confidence is Confidence.MEDIUM
    assert _TRUNCATION_TAIL in f.summary


def test_the_pricing_absence_verdict_is_silent_when_every_source_was_read_in_full(full_store, ctx):
    ctx.resolved_profile = "commerce"
    f = _finding(_check("CORE-TRUST-007"), full_store, ctx)
    assert f.status is CheckStatus.NA
    assert "truncated" not in f.evidence
    assert f.confidence is Confidence.HIGH
    assert _TRUNCATION_TAIL not in f.summary
