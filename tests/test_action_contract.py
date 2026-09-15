"""action.yml ⇄ action-smoke.yml: every input the action REQUIRES once
allow-private-networks is true must be passed by the smoke workflow —
this is the exact shape of the 2026-09-15 red run (trusted-target missing)."""
import re
from pathlib import Path

import yaml

from tests._smoke_assert import check

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
SMOKE = ROOT / ".github" / "workflows" / "action-smoke.yml"


def required_inputs_for_private_networks(action_text: str) -> set[str]:
    """Inputs whose description says they are required when allow-private-networks is true."""
    doc = yaml.safe_load(action_text)
    out = set()
    for name, spec in (doc.get("inputs") or {}).items():
        desc = str((spec or {}).get("description", ""))
        if re.search(r"required.*allow-private-networks is true", desc, re.I):
            out.add(name)
    return out


def test_the_action_declares_trusted_target_as_required_for_private_targets():
    assert "trusted-target" in required_inputs_for_private_networks(ACTION.read_text())


def test_smoke_workflow_passes_every_input_the_action_requires():
    smoke = yaml.safe_load(SMOKE.read_text())
    steps = [s for j in smoke["jobs"].values() for s in j["steps"] if s.get("uses") == "./"]
    assert steps, "smoke workflow must invoke the action from ./"
    with_ = steps[0].get("with") or {}
    if str(with_.get("allow-private-networks", "false")).lower() == "true":
        missing = {k for k in required_inputs_for_private_networks(ACTION.read_text())
                   if str(with_.get(k, "false")).lower() != "true"}
        assert not missing, f"action-smoke.yml enables private networks but omits {missing}"


def test_the_contract_rejects_a_workflow_without_trusted_target():
    bad = {"jobs": {"smoke": {"steps": [{"uses": "./", "with": {"url": "http://127.0.0.1:8765/", "allow-private-networks": "true"}}]}}}
    with_ = bad["jobs"]["smoke"]["steps"][0]["with"]
    missing = {k for k in required_inputs_for_private_networks(ACTION.read_text()) if str(with_.get(k, "false")).lower() != "true"}
    assert missing == {"trusted-target"}


def test_smoke_assert_check_passes_on_a_healthy_report():
    assert check({"score": {"status": "OK", "scope": "CANONICAL", "grade": "A", "value": 91}}) == []


def test_smoke_assert_check_reports_every_violated_invariant():
    problems = check({"score": {"status": "OK", "scope": "CANONICAL", "grade": "B", "value": 84}})
    assert problems == ["grade='B'", "value=84 < 85"]
