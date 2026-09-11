"""The truncation helpers are general: any gatherer record with a `truncated`
key, not just robots.txt. Behaviour is byte-for-byte what the robots checks
already relied on — write-when-true, cap at MEDIUM, one shared sentence."""
from __future__ import annotations

from scovant_core.checks._truncation import TRUNCATION_NOTE, record_truncation, truncated_confidence
from scovant_core.models import Confidence


def test_records_the_flag_and_returns_the_note_only_when_truncated():
    ev: dict = {}
    note, truncated = record_truncation({"truncated": True}, ev)
    assert ev["truncated"] is True and truncated is True and note == TRUNCATION_NOTE


def test_absent_or_false_writes_nothing():
    for source in ({"truncated": False}, {}):
        ev: dict = {}
        note, truncated = record_truncation(source, ev)
        assert ev == {} and truncated is False and note == ""


def test_confidence_is_capped_only_when_truncated():
    assert truncated_confidence(True) is Confidence.MEDIUM
    assert truncated_confidence(False) is Confidence.HIGH
    assert truncated_confidence(False, Confidence.MEDIUM) is Confidence.MEDIUM


def test_the_robots_module_still_exports_its_original_names():
    from scovant_core.checks.access import _robots_readability as r

    assert r.robots_truncation is record_truncation
    assert r.truncated_confidence is truncated_confidence
