"""The committed envelope schema equals its generator and enforces the
same invariants as the pydantic model."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from scovant_core import envelope as E

DOC = Path(__file__).resolve().parents[1] / "docs" / "evidence-envelope.schema.json"


def good(**kw) -> dict:
    d = {"envelope_version": "1.0", "id": str(uuid.uuid4()), "scan_id": None, "source": "CORE",
         "verification_mode": "DECLARED", "status": "PASS", "maturity": "EXPERIMENTAL",
         "scored": False, "rule_id": None, "check_id": "CORE-ACCESS-001",
         "capability": "access.robots", "principal": {}, "intent": {}, "environment": "PUBLIC",
         "observed_at": "2026-10-24T12:00:00+00:00", "collector_version": "0.23.0",
         "ruleset_version": None, "policy_id": None, "evidence": {}, "limitations": [],
         "fix_owner": None}
    d.update(kw)
    return d


def _v():
    return Draft202012Validator(E.envelope_schema())


def test_committed_schema_matches_generator():
    assert DOC.read_text() == E.render_envelope_schema(), "run: python -m scovant_core.envelope"


def test_schema_is_valid_and_identified():
    s = E.envelope_schema()
    Draft202012Validator.check_schema(s)
    assert s["$id"] == E.SCHEMA_ID
    assert s["properties"]["envelope_version"]["const"] == E.ENVELOPE_VERSION
    assert s["additionalProperties"] is False


def test_valid_envelope_passes_schema():
    assert not list(_v().iter_errors(good()))


@pytest.mark.parametrize("bad", [
    {"scored": True, "rule_id": None},
    {"verification_mode": "SYNTHETIC_AUTHORIZED", "environment": "PUBLIC"},
    {"status": "WARN", "fix_owner": None},
    {"status": "FAIL", "fix_owner": None},
    {"extra": 1},
    {"source": "BOGUS"},
])
def test_invariants_fail_in_schema_and_model(bad):
    doc = good(**bad)
    assert list(_v().iter_errors(doc)), f"schema accepted {bad}"
    with pytest.raises(ValidationError):
        E.validate_envelope(doc)


def test_main_stdout(capsys):
    assert E.main(["--stdout"]) == 0
    assert capsys.readouterr().out == E.render_envelope_schema()


def test_main_rejects_unknown_argument(capsys):
    assert E.main(["--nope"]) == 2
