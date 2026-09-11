from __future__ import annotations

import pytest

from scovant_core.checks._document import document_status
from scovant_core.models import CheckStatus


@pytest.mark.parametrize("status,html,expected", [
    (None, False, CheckStatus.ERROR), (404, False, CheckStatus.NA), (410, False, CheckStatus.NA),
    (200, True, CheckStatus.NA), (500, False, CheckStatus.ERROR), (403, False, CheckStatus.ERROR),
    (401, False, CheckStatus.ERROR), (301, False, CheckStatus.ERROR), (200, False, None)])
def test_document_status_ladder(status, html, expected):
    v = document_status({"status": status, "served_as_html": html}, what="robots.txt")
    assert (v.status if v else None) == expected


def test_reasons_name_the_document_and_status():
    assert "robots.txt" in document_status({"status": 503}, what="robots.txt").reason
    assert "503" in document_status({"status": 503}, what="robots.txt").reason


def test_missing_served_as_html_key_is_treated_as_false():
    assert document_status({"status": 200}, what="robots.txt") is None


def test_none_status_wins_over_served_as_html():
    v = document_status({"status": None, "served_as_html": True}, what="robots.txt")
    assert v.status == CheckStatus.ERROR
