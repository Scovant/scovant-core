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


# --- cross-step $GITHUB_STEP_SUMMARY read (the 2026-09-14..15 always-red bug) ---
#
# Every step's $GITHUB_STEP_SUMMARY is a distinct, freshly-created file — the
# composite action's own "out" step writes the summary into ITS OWN summary
# file, so a LATER step in the job that reads "$GITHUB_STEP_SUMMARY" (a
# variable EXPANSION, `$GITHUB_STEP_SUMMARY`/`${GITHUB_STEP_SUMMARY}`) is
# always reading an empty file it never wrote to. Setting a NEW, local value
# via an env-var prefix (`GITHUB_STEP_SUMMARY="$own_file" some-command`, no
# leading `$`) is the correct escape hatch and must NOT trip this check.
_CROSS_STEP_SUMMARY_READ = re.compile(r"\$\{?GITHUB_STEP_SUMMARY\}?")


def offending_cross_step_summary_reads(smoke_doc: dict) -> list[str]:
    """`run:` blocks, from every step that does NOT `uses: ./`, which
    expand $GITHUB_STEP_SUMMARY — always empty for that step."""
    offenders = []
    for job in smoke_doc["jobs"].values():
        for step in job["steps"]:
            if step.get("uses") == "./":
                continue
            run = step.get("run") or ""
            if _CROSS_STEP_SUMMARY_READ.search(run):
                offenders.append(run)
    return offenders


def test_no_step_besides_the_action_reads_a_different_steps_empty_summary_file():
    smoke = yaml.safe_load(SMOKE.read_text())
    assert offending_cross_step_summary_reads(smoke) == []


def test_the_cross_step_summary_read_check_is_falsifiable():
    """Build the exact broken shape this test exists to catch and confirm it
    IS rejected — a check that can't fail on a genuinely bad input proves
    nothing."""
    bad = {
        "jobs": {
            "smoke": {
                "steps": [
                    {"uses": "./", "with": {}},
                    {"name": "Assert outputs", "run": 'grep -q "x" "$GITHUB_STEP_SUMMARY"'},
                ],
            },
        },
    }
    assert offending_cross_step_summary_reads(bad) == ['grep -q "x" "$GITHUB_STEP_SUMMARY"']


def test_the_cross_step_summary_read_check_permits_the_env_override_escape_hatch():
    """A step that ASSIGNS a fresh GITHUB_STEP_SUMMARY (no leading `$`) to
    re-render the summary into a file it owns must not be flagged."""
    ok = {
        "jobs": {
            "smoke": {
                "steps": [
                    {"uses": "./", "with": {}},
                    {
                        "name": "Assert outputs",
                        "run": (
                            'own="$RUNNER_TEMP/x.md"\n'
                            'GITHUB_STEP_SUMMARY="$own" python -m scovant_core.action summary "$RUNNER_TEMP/core.json"\n'
                            'grep -q "Static Signal Score:" "$own"\n'
                        ),
                    },
                ],
            },
        },
    }
    assert offending_cross_step_summary_reads(ok) == []
