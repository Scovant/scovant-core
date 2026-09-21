from __future__ import annotations

from types import SimpleNamespace

import pytest

from scovant_core.models import Category, CheckResult, CheckStatus, Confidence, Severity
from scovant_core.report._cloud_matrix import CORE_VS_CLOUD
from scovant_core.report._common import (
    evaluated_experimental,
    grouped_by_status,
    has_experimental,
    scored_experimental,
    status_counts,
    top_findings,
)
from scovant_core.report._cta import CTA_TEXT, cta_url


def _f(id, status, weight=1, experimental=False):
    return CheckResult(id=id, title=id, category=Category.ACCESS, status=status,
                       severity=Severity.MEDIUM, confidence=Confidence.HIGH, weight=weight,
                       summary="s", experimental=experimental)


def test_cta_url_carries_medium_and_never_a_target():
    assert cta_url("github") == "https://scovant.com/scan?utm_source=scovant-core&utm_medium=github&utm_campaign=oss"
    with pytest.raises(ValueError):
        cta_url("email")


def test_cta_text_is_pinned():
    assert CTA_TEXT == "Verify with real agents:"


def test_top_findings_orders_fail_then_weight_then_id_and_caps_at_8():
    fs = [_f("B", CheckStatus.WARN, 3), _f("A", CheckStatus.FAIL, 1), _f("C", CheckStatus.WARN, 3)] + [
        _f(f"Z{i}", CheckStatus.WARN) for i in range(10)]
    ids = [f.id for f in top_findings(fs, scored=True)]
    assert ids[:3] == ["A", "B", "C"] and len(ids) == 8


def test_unscored_experimental_never_in_top_findings():
    fs = [_f("X", CheckStatus.FAIL, experimental=True)]
    assert top_findings(fs, scored=False) == [] and [f.id for f in top_findings(fs, scored=True)] == ["X"]


def test_evaluated_experimental_drops_na():
    fs = [_f("E1", CheckStatus.NA, experimental=True), _f("E2", CheckStatus.WARN, experimental=True)]
    assert [f.id for f in evaluated_experimental(fs)] == ["E2"]


def test_grouped_by_status_order():
    fs = [_f("p", CheckStatus.PASS), _f("f", CheckStatus.FAIL), _f("n", CheckStatus.NA)]
    assert list(grouped_by_status(fs).keys()) == [CheckStatus.FAIL, CheckStatus.WARN, CheckStatus.ERROR, CheckStatus.PASS, CheckStatus.NA]


def test_grouped_by_status_sorts_within_bucket():
    fs = [_f("b", CheckStatus.WARN), _f("a", CheckStatus.WARN)]
    assert [f.id for f in grouped_by_status(fs)[CheckStatus.WARN]] == ["a", "b"]


def test_status_counts_covers_every_status_even_at_zero():
    fs = [_f("a", CheckStatus.PASS)]
    counts = status_counts(fs)
    assert counts[CheckStatus.PASS] == 1
    assert counts[CheckStatus.FAIL] == 0
    assert set(counts) == set(CheckStatus)


def test_scored_experimental_reads_provenance_flag():
    assert scored_experimental(SimpleNamespace(provenance={"experimental": True})) is True
    assert scored_experimental(SimpleNamespace(provenance={"experimental": False})) is False
    assert scored_experimental(SimpleNamespace(provenance={})) is False


def test_has_experimental_true_iff_any_finding_is_experimental():
    assert has_experimental([_f("a", CheckStatus.PASS)]) is False
    assert has_experimental([_f("a", CheckStatus.PASS), _f("b", CheckStatus.NA, experimental=True)]) is True


def test_cloud_matrix_has_only_known_cells():
    assert all(core in ("✅", "✅ (experimental)", "❌", "—") and cloud in ("✅", "❌", "—") for _, core, cloud in CORE_VS_CLOUD)


def test_cta_claude_code_medium():
    from scovant_core.report._cta import cta_url

    assert cta_url("claude-code") == (
        "https://scovant.com/scan?utm_source=scovant-core&utm_medium=claude-code&utm_campaign=oss"
    )
