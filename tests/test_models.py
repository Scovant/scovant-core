from scovant_core.models import (
    REPORT_SCHEMA_VERSION,
    Category,
    CheckResult,
    CheckStatus,
    Confidence,
    Severity,
)


def test_status_values_are_the_five_documented_ones():
    assert {s.value for s in CheckStatus} == {"PASS", "WARN", "FAIL", "N/A", "ERROR"}


def test_check_result_defaults():
    r = CheckResult(
        id="CORE-ACCESS-001",
        title="t",
        category=Category.ACCESS,
        status=CheckStatus.PASS,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        summary="ok",
    )
    assert r.evidence == {} and r.experimental is False and r.remediation == ""


def test_schema_is_2_0():
    assert REPORT_SCHEMA_VERSION == "2.1"
