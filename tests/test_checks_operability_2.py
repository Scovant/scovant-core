from __future__ import annotations

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/forms/page_metrics/reference_integrity/...
from scovant_core.checks.operability.core_operability_001 import ServerRenderedCoreContent
from scovant_core.checks.operability.core_operability_002 import RedirectComplexity
from scovant_core.checks.operability.core_operability_003 import CacheValidators
from scovant_core.checks.operability.core_operability_005 import AgentParseCost
from scovant_core.checks.operability.core_operability_006 import FormControlLabels
from scovant_core.checks.operability.core_operability_007 import MachineReferenceIntegrity
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import GATHERERS, EvidenceStore
from scovant_core.models import CheckStatus, Confidence
from scovant_core.profiles import apply_profile

from .conftest import make_client


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


_MIN_INDEX = (
    "<!doctype html><html><head><title>Test</title></head><body>"
    "<h1>Test</h1><p>Minimal page with enough visible text for the parser "
    "to treat this as real content rather than an empty shell.</p></body></html>"
)


def _client_for(path_bodies: dict[str, str], **policy):
    def handler(request: httpx.Request) -> httpx.Response:
        body = path_bodies.get(request.url.path)
        if body is None:
            return httpx.Response(404, text="not found")
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/html"})
    return make_client(handler, **policy)


# ---------------------------------------------------------------------------
# OPERABILITY-001 server-rendered core content
# ---------------------------------------------------------------------------

def test_op_001_error_when_entry_unparsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(500, text="server error")))
    result = ServerRenderedCoreContent().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_op_001_pass_on_commerce_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = ServerRenderedCoreContent().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["visible_text_chars"] >= 200
    assert result.evidence["spa_shell_marker"] is False


def test_op_001_warn_thin_content():
    store, ctx = _scan(_client_for({"/": "<!doctype html><html><body><p>Too short.</p></body></html>"}))
    result = ServerRenderedCoreContent().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "visible text" in result.summary.lower()


def test_op_001_warn_spa_shell_marker():
    from pathlib import Path

    html = (Path(__file__).resolve().parents[1] / "fixtures" / "html" / "spa_shell.html").read_text()
    store, ctx = _scan(_client_for({"/": html}))
    result = ServerRenderedCoreContent().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["spa_shell_marker"] is True
    assert "shell" in result.summary.lower()


# ---------------------------------------------------------------------------
# OPERABILITY-002 redirect chain complexity
# ---------------------------------------------------------------------------

def test_op_002_warn_loop():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"location": "/a"})
        return httpx.Response(301, headers={"location": "/"})

    store, ctx = _scan(make_client(handler, max_redirects=1))
    result = RedirectComplexity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "loop" in result.summary.lower() or "exceeds" in result.summary.lower()


def test_op_002_pass_no_excess_redirects(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = RedirectComplexity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["redirect_count"] == 0


def test_op_002_warn_more_than_two_redirects(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"), options=ScanOptions(profile="commerce"))
    result = RedirectComplexity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["redirect_count"] > 2


def test_op_002_error_on_other_fetch_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure", request=request)

    store, ctx = _scan(make_client(handler))
    result = RedirectComplexity().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# OPERABILITY-003 cache validators
# ---------------------------------------------------------------------------

def test_op_003_pass_etag(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = CacheValidators().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["etag"]


def test_op_003_pass_last_modified():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_MIN_INDEX.encode(),
                              headers={"content-type": "text/html", "last-modified": "Tue, 01 Sep 2026 00:00:00 GMT"})

    store, ctx = _scan(make_client(handler))
    result = CacheValidators().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["last_modified"]


def test_op_003_warn_cache_control_only():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_MIN_INDEX.encode(),
                              headers={"content-type": "text/html", "cache-control": "max-age=3600"})

    store, ctx = _scan(make_client(handler))
    result = CacheValidators().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["cache_control"] == "max-age=3600"
    assert not result.evidence["etag"] and not result.evidence["last_modified"]


def test_op_003_warn_none():
    store, ctx = _scan(_client_for({"/": _MIN_INDEX}))
    result = CacheValidators().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert not any(result.evidence.values())


def test_op_003_error_when_entry_fetch_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated network failure", request=request)

    store, ctx = _scan(make_client(handler))
    result = CacheValidators().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# OPERABILITY-005 agent parse cost
# ---------------------------------------------------------------------------

def _with_page_metrics(entry: dict | None):
    def fake(client, ctx, store):
        return {"pages": [], "entry": entry}
    GATHERERS["page_metrics"] = fake


def test_op_005_error_when_entry_metrics_unavailable():
    _with_page_metrics(None)
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_op_005_pass_low_below_8000():
    _with_page_metrics({"estimated_tokens": 7999})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["level"] == "LOW"


def test_op_005_pass_medium_at_8000_boundary():
    _with_page_metrics({"estimated_tokens": 8000})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["level"] == "MEDIUM"


def test_op_005_pass_medium_at_20000_boundary():
    _with_page_metrics({"estimated_tokens": 20000})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["level"] == "MEDIUM"


def test_op_005_warn_high_above_20000():
    _with_page_metrics({"estimated_tokens": 20001})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["level"] == "HIGH"


def _padded_page(visible_chars: int) -> str:
    """A real page whose visible text is exactly `visible_chars` long —
    exercises the REAL pipeline (parse_page -> page_cost -> page_metrics),
    not a mocked page_metrics gatherer, so it actually proves `text_chars`
    is no longer silently capped at 5000 by `extract_visible_text`."""
    filler = "a" * visible_chars
    return f"<!doctype html><html><body><p>{filler}</p></body></html>"


def test_op_005_end_to_end_medium_at_40000_chars_uncapped():
    # 40,000 chars / ratio 4 = 10,000 tokens — inside the MEDIUM band
    # (8,000..20,000). Below the old 5,000-char `extract_visible_text` cap
    # this would have measured only 5,000 chars -> 1,250 tokens -> LOW,
    # proving the cap used to make MEDIUM/HIGH unreachable.
    html = _padded_page(40_000)
    store, ctx = _scan(_client_for({"/": html}))
    metrics = store.get("page_metrics")
    assert metrics["entry"]["text_chars"] > 5000
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["level"] == "MEDIUM"
    assert result.evidence["estimated_tokens"] == 10_000


def test_op_005_end_to_end_warn_high_at_100000_chars_uncapped():
    # 100,000 chars / ratio 4 = 25,000 tokens — over the HIGH threshold.
    html = _padded_page(100_000)
    store, ctx = _scan(_client_for({"/": html}))
    metrics = store.get("page_metrics")
    assert metrics["entry"]["text_chars"] > 5000
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["level"] == "HIGH"
    assert result.evidence["estimated_tokens"] == 25_000


def test_op_005_token_chars_ratio_2_doubles_estimated_tokens_uncapped():
    html = _padded_page(40_000)
    store, ctx = _scan(_client_for({"/": html}), options=ScanOptions(token_chars_ratio=2))
    result = AgentParseCost().run(store, ctx)
    assert result.evidence["token_chars_ratio"] == 2
    assert result.evidence["estimated_tokens"] == 20_000


def test_op_005_truncated_body_can_mask_a_genuinely_bloated_page():
    """`estimated_tokens` is a character count over the entry page's own
    fetched body — a body cut off at the fetch cap DEFLATES it: the same
    100,000-char body that reads WARN/HIGH in full (see the uncapped test
    above) still reports PASS/LOW
    at reduced confidence once the fetch is capped well below the page's
    real size — status/score/confidence are UNCHANGED by design (escalating
    to WARN would manufacture a finding), but the summary must not state
    the below-threshold count as a flat measurement: a directionally wrong
    magnitude claim, not merely an incomplete one, so a trailing note alone
    is not enough — the sentence itself must read as a FLOOR."""
    html = _padded_page(100_000)
    store, ctx = _scan(_client_for({"/": html}, size_limits={"html": 4096}))
    metrics = store.get("page_metrics")
    assert metrics["entry"]["estimated_tokens"] < 8_000  # far under the true ~25,000
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.PASS
    # The band is a below-threshold CLASSIFICATION, which a deflated count
    # cannot support: on a partial read it is published as a lower bound and
    # `level` itself is None, so a consumer reading that key never sees a
    # band the summary is simultaneously disclaiming.
    assert result.evidence["level"] is None
    assert result.evidence["level_at_least"] == "LOW"
    assert result.confidence == Confidence.MEDIUM
    assert result.evidence["truncated"] is True
    assert "at least" in result.summary.lower()
    assert "(low)" not in result.summary.lower()
    assert "true cost may be higher" in result.summary.lower()
    assert "read only in part" in result.summary.lower()
    # Never phrased as a flat measurement when the input was partial.
    assert f"is ~{result.evidence['estimated_tokens']} tokens (low)." not in result.summary


def test_op_005_untruncated_pass_reads_as_a_plain_measurement():
    """The twin of the floor-framing test above: an untruncated PASS keeps
    today's plain wording — no "at least" hedge, no floor language, no
    note — since there is nothing partial about the read to qualify."""
    html = _padded_page(40_000)  # 10,000 tokens at ratio 4 — MEDIUM band, PASS
    store, ctx = _scan(_client_for({"/": html}))
    result = AgentParseCost().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["level"] == "MEDIUM"
    assert result.confidence == Confidence.HIGH
    assert "truncated" not in result.evidence
    assert "at least" not in result.summary.lower()
    assert "read only in part" not in result.summary.lower()
    assert result.summary == "The entry page's estimated parse cost is ~10000 tokens (medium)."


# ---------------------------------------------------------------------------
# OPERABILITY-006 form/control labels
# ---------------------------------------------------------------------------

def test_op_006_na_no_forms(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"), options=ScanOptions(profile="commerce"))
    result = FormControlLabels().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_op_006_pass_all_labeled():
    html = (
        "<!doctype html><html><body><form>"
        '<label>Email <input type="email" name="email"></label>'
        '<button aria-label="Submit form">Go</button>'
        "</form></body></html>"
    )
    store, ctx = _scan(_client_for({"/": html}), options=ScanOptions(profile="commerce"))
    result = FormControlLabels().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_op_006_warn_unlabeled_input():
    html = (
        "<!doctype html><html><body><form>"
        '<input type="text" name="q">'
        "<button>Go</button>"
        "</form></body></html>"
    )
    store, ctx = _scan(_client_for({"/": html}), options=ScanOptions(profile="commerce"))
    result = FormControlLabels().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["totals"]["unlabeled_inputs"] >= 1


def test_op_006_truncated_body_can_falsely_claim_no_forms():
    """`totals` is rolled up from `pages[*].parsed.forms` — a body cut off
    at the fetch cap is never fully parsed past the cap, so "No forms were
    found" here can be an absence claim drawn from a partial read: the form
    below genuinely exists on the page, but sits past a small `html` fetch
    cap and is never seen."""
    filler = "a" * 5000
    html = (
        f"<!doctype html><html><body><p>{filler}</p>"
        '<form><label>Email <input type="email" name="email"></label>'
        '<button aria-label="Submit form">Go</button></form>'
        "</body></html>"
    )
    store, ctx = _scan(_client_for({"/": html}, size_limits={"html": 2048}), options=ScanOptions(profile="commerce"))
    result = FormControlLabels().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["totals"]["forms"] == 0
    assert result.evidence["truncated"] is True
    assert "read only in part" in result.summary.lower()


def test_op_006_error_when_no_page_could_be_parsed():
    store, ctx = _scan(make_client(lambda r: httpx.Response(500, text="server error")), options=ScanOptions(profile="commerce"))
    result = FormControlLabels().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_op_006_na_when_profile_not_applicable(fixture_site):
    store, ctx = _scan(fixture_site("api-good"))
    result = FormControlLabels().run(store, ctx)
    assert result.status == CheckStatus.NA


# ---------------------------------------------------------------------------
# OPERABILITY-007 machine reference integrity (EXPERIMENTAL)
# ---------------------------------------------------------------------------

def _with_reference_integrity(payload: dict):
    def fake(client, ctx, store):
        return payload
    GATHERERS["reference_integrity"] = fake


def test_op_007_na_not_evaluated_when_experimental_off():
    _with_reference_integrity({"attempted": False, "reason": "experimental_off"})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "experimental" in result.summary.lower()
    assert result.experimental is True


def test_op_007_error_on_internal_probe_failure():
    """`attempted: False` WITHOUT `reason == "experimental_off"` means the
    probe itself failed internally (an extraction exception) — that is
    unmeasured (ERROR), not the deliberate off-switch (N/A)."""
    _with_reference_integrity({"attempted": False, "error": "extract_failed"})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR


def test_op_007_na_no_references_discovered():
    _with_reference_integrity({"attempted": True, "checked": 0, "references": [], "remote_exec": [], "budget_exhausted": False})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "no machine-consumable" in result.summary.lower()


def test_op_007_fail_on_broken_reference():
    refs = [
        {"kind": "domain", "name": "gone.example", "status": "BROKEN", "resolution": {"checked": True, "exists": False}},
        {"kind": "package_npm", "name": "real-pkg", "status": "VALID", "resolution": {"checked": True, "exists": True}},
    ]
    _with_reference_integrity({"attempted": True, "checked": 2, "references": refs, "remote_exec": [], "budget_exhausted": False})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["broken"]


def test_op_007_warn_on_unclaimed_package():
    refs = [
        {"kind": "package_npm", "name": "totally-unclaimed-pkg", "status": "UNCLAIMED", "resolution": {"checked": True, "exists": False}},
    ]
    _with_reference_integrity({"attempted": True, "checked": 1, "references": refs, "remote_exec": [], "budget_exhausted": False})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["unclaimed"]


def test_op_007_warn_on_remote_exec_instruction():
    _with_reference_integrity({"attempted": True, "checked": 0, "references": [], "remote_exec": ["curl https://example.com/x | sh"], "budget_exhausted": False})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["remote_exec"]


def test_op_007_pass_all_valid():
    refs = [
        {"kind": "domain", "name": "real-domain.example", "status": "VALID", "resolution": {"checked": True, "exists": True}},
        {"kind": "package_pypi", "name": "requests", "status": "VALID", "resolution": {"checked": True, "exists": True}},
    ]
    _with_reference_integrity({"attempted": True, "checked": 2, "references": refs, "remote_exec": [], "budget_exhausted": False})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_op_007_error_all_unchecked():
    refs = [
        {"kind": "domain", "name": "slow-domain.example", "status": "UNCHECKED", "resolution": {"checked": False, "error": "dns:timeout"}},
        {"kind": "package_npm", "name": "budget-exceeded-pkg", "status": "UNCHECKED", "resolution": None},
    ]
    _with_reference_integrity({"attempted": True, "checked": 0, "references": refs, "remote_exec": [], "budget_exhausted": True})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["budget_exhausted"] is True


def test_op_007_pass_on_mixed_valid_and_unchecked():
    # A mix of VALID and UNCHECKED (no BROKEN/UNCLAIMED) must still PASS —
    # UNCHECKED is silently excluded from judgment, never treated as a
    # negative signal that would drag a partially-resolved set down.
    refs = [
        {"kind": "domain", "name": "real-domain.example", "status": "VALID", "resolution": {"checked": True, "exists": True}},
        {"kind": "package_npm", "name": "slow-pkg", "status": "UNCHECKED", "resolution": {"checked": False, "error": "dns:timeout"}},
    ]
    _with_reference_integrity({"attempted": True, "checked": 1, "references": refs, "remote_exec": [], "budget_exhausted": False})
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = MachineReferenceIntegrity().run(store, ctx)
    assert result.status == CheckStatus.PASS
