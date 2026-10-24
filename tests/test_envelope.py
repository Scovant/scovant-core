"""The evidence envelope contract: values, invariants, vocabulary mapping."""
from __future__ import annotations

import typing
import uuid

import pytest
from pydantic import ValidationError

from scovant_core import envelope as E
from scovant_core.checks.registry import CHECKS


def good(**kw) -> dict:
    d = {
        "envelope_version": "1.0",
        "id": str(uuid.uuid4()),
        "scan_id": None,
        "source": "CLOUD",
        "verification_mode": "PASSIVE_OBSERVED",
        "status": "PASS",
        "maturity": "EXPERIMENTAL",
        "scored": False,
        "rule_id": None,
        "check_id": None,
        "capability": "access.diagnostics",
        "principal": {},
        "intent": {},
        "environment": "PUBLIC",
        "observed_at": "2026-10-24T12:00:00+00:00",
        "collector_version": "1.0.0",
        "ruleset_version": None,
        "policy_id": None,
        "evidence": {"http_status": 200},
        "limitations": [],
        "fix_owner": None,
    }
    d.update(kw)
    return d


def test_value_tuples_match_the_model_literals():
    hints = typing.get_type_hints(E.EvidenceEnvelope)
    for field, values in (("source", E.SOURCES), ("verification_mode", E.VERIFICATION_MODES),
                          ("status", E.STATUSES), ("maturity", E.MATURITIES),
                          ("environment", E.ENVIRONMENTS)):
        assert typing.get_args(hints[field]) == values, field
    assert tuple(a for a in typing.get_args(typing.get_args(hints["fix_owner"])[0])) == E.FIX_OWNERS


@pytest.mark.parametrize("mode", E.VERIFICATION_MODES)
def test_one_valid_envelope_per_mode(mode):
    env = "SANDBOX" if mode == "SYNTHETIC_AUTHORIZED" else "PUBLIC"
    m = E.validate_envelope(good(verification_mode=mode, environment=env))
    assert m.verification_mode == mode


@pytest.mark.parametrize("field", ["source", "verification_mode", "status", "maturity",
                                   "environment", "fix_owner"])
def test_unknown_enum_value_rejected(field):
    with pytest.raises(ValidationError):
        E.validate_envelope(good(**{field: "BOGUS"}))


def test_extra_top_level_key_rejected():
    with pytest.raises(ValidationError):
        E.validate_envelope(good(extra_field=1))


def test_open_objects_accept_any_keys():
    m = E.validate_envelope(good(evidence={"a": {"b": [1, 2]}}, principal={"kind": "agent"}))
    assert m.evidence["a"]["b"] == [1, 2]


def test_naive_observed_at_rejected():
    with pytest.raises(ValidationError):
        E.validate_envelope(good(observed_at="2026-10-24T12:00:00"))


def test_observed_at_z_suffix_accepted():
    m = E.validate_envelope(good(observed_at="2026-10-24T12:00:00Z"))
    assert m.observed_at.tzinfo is not None


@pytest.mark.parametrize("field", ["capability", "collector_version"])
def test_empty_required_strings_rejected(field):
    with pytest.raises(ValidationError):
        E.validate_envelope(good(**{field: ""}))


def test_wrong_envelope_version_rejected():
    with pytest.raises(ValidationError):
        E.validate_envelope(good(envelope_version="2.0"))


def test_invariant_scored_needs_rule_id():
    with pytest.raises(ValidationError):
        E.validate_envelope(good(scored=True, rule_id=None))
    assert E.validate_envelope(good(scored=True, rule_id="X-1")).scored is True


def test_invariant_synthetic_needs_sandbox():
    with pytest.raises(ValidationError):
        E.validate_envelope(good(verification_mode="SYNTHETIC_AUTHORIZED", environment="PUBLIC"))


@pytest.mark.parametrize("status", ["WARN", "FAIL"])
def test_invariant_warn_fail_need_fix_owner(status):
    with pytest.raises(ValidationError):
        E.validate_envelope(good(status=status, fix_owner=None))
    assert E.validate_envelope(good(status=status, fix_owner="edge_cdn")).fix_owner == "edge_cdn"


def test_mapping_targets_are_envelope_modes():
    assert set(E.VERIFICATION_MODE_MAPPING.values()) <= set(E.VERIFICATION_MODES)


def test_every_core_check_mode_is_mapped():
    used = {c.verification_mode for c in CHECKS}
    assert used, "registry empty — the test would prove nothing"
    assert used <= set(E.VERIFICATION_MODE_MAPPING), used - set(E.VERIFICATION_MODE_MAPPING)


def test_map_verification_mode():
    assert E.map_verification_mode("STATIC_DECLARED", "PUBLIC") == "DECLARED"
    assert E.map_verification_mode("ACTIVE_AUTHORIZED", "PRODUCTION_READ_ONLY") == "ACTIVE_SAFE"
    assert E.map_verification_mode("ACTIVE_AUTHORIZED", "SANDBOX") == "SYNTHETIC_AUTHORIZED"
    assert E.map_verification_mode("PASSIVE_OBSERVED", "SANDBOX") == "PASSIVE_OBSERVED"
    with pytest.raises(KeyError):
        E.map_verification_mode("NOPE", "PUBLIC")
