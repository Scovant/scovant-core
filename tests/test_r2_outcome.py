import pytest
from pydantic import ValidationError

from scovant_core.models import CheckStatus
from scovant_core.r2.outcome import MEASURED_STATES, STATE_VALUE, Outcome, OutcomeState, R2Category


def test_states_are_the_documented_eight():
    assert [s.value for s in OutcomeState] == [
        "PASS", "WARN", "FAIL", "N/A", "NOT_MEASURED", "ERROR", "BLOCKED_BY_POLICY", "UNKNOWN"]


def test_only_pass_warn_fail_are_measurements():
    assert {OutcomeState.PASS, OutcomeState.WARN, OutcomeState.FAIL} == MEASURED_STATES
    assert STATE_VALUE == {OutcomeState.PASS: 1.0, OutcomeState.WARN: 0.5, OutcomeState.FAIL: 0.0}


def test_report_check_status_is_not_extended():
    # The published report contract (schema 1.1) must not grow R2-only states.
    assert [s.value for s in CheckStatus] == ["PASS", "WARN", "FAIL", "N/A", "ERROR"]


def test_categories_are_the_seven_cloud_categories():
    assert [c.value for c in R2Category] == [
        "discoverability", "structured", "consistency", "actionability", "trust", "ucp", "citability"]


@pytest.mark.parametrize("pm,pf", [(5, None), (None, 1), (-1, 0), (3, 4), (2, -1)])
def test_inconsistent_page_counts_are_rejected(pm, pf):
    with pytest.raises(ValidationError):
        Outcome(rule_id="X", state=OutcomeState.FAIL, pages_measured=pm, pages_failed=pf)


def test_outcome_is_immutable():
    o = Outcome(rule_id="X", state=OutcomeState.PASS)
    with pytest.raises(ValidationError):
        o.state = OutcomeState.FAIL  # type: ignore[misc]
