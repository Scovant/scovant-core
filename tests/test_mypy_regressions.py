"""Branches mypy flagged: each is a real None that used to be silently coerced."""
from scovant_core.checks.access.core_access_011 import _summary_is_short
from scovant_core.gatherers.security_txt import _shape_out


def test_security_txt_429_without_retry_after_reports_none():
    out = _shape_out(last_status=429, last_retry_after=None, last_served_as_html=False)
    assert out["retry_after"] is None


def test_security_txt_429_with_retry_after_keeps_the_header_text():
    out = _shape_out(last_status=429, last_retry_after="120", last_served_as_html=False)
    assert out["retry_after"] == "120"


def test_llms_summary_without_a_summary_line_is_not_short():
    assert _summary_is_short("# Title\n\nno blockquote here\n") is False
