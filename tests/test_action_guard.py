# tests/test_action_guard.py
"""Audit §15: allow-private-networks is fail-closed in the Action — it runs
only with trusted-target: true and never for a pull request from a fork.
The guard is a bash block in action.yml; this test extracts and runs it."""
import os
import re
import subprocess
from pathlib import Path

import pytest

ACTION = Path(__file__).resolve().parents[1] / "action.yml"


def _guard_block() -> str:
    text = ACTION.read_text()
    m = re.search(r"# --- private-network guard ---\n(.*?)# --- end guard ---", text, re.S)
    assert m, "guard block markers missing in action.yml"
    return "\n".join(line[8:] if line.startswith(" " * 8) else line for line in m.group(1).splitlines())


@pytest.mark.parametrize("allow,trusted,event,head,expect", [
    ("false", "false", "push", "", 0),
    ("true", "true", "push", "", 0),
    ("true", "false", "push", "", 2),
    ("true", "true", "pull_request", "someone/fork", 2),
    ("true", "true", "pull_request", "Scovant/scovant-core", 0),
    ("true", "true", "pull_request", "", 2),
    ("true", "true", "pull_request_target", "someone/fork", 2),
])
def test_guard(allow, trusted, event, head, expect):
    env = {**os.environ, "INPUT_ALLOW_PRIVATE_NETWORKS": allow, "INPUT_TRUSTED_TARGET": trusted,
           "EVENT_NAME": event, "EVENT_HEAD_REPO": head, "GITHUB_REPOSITORY": "Scovant/scovant-core"}
    p = subprocess.run(["bash", "-c", "set -euo pipefail\n" + _guard_block()], env=env, capture_output=True, text=True)
    assert p.returncode == expect, p.stderr
    if expect == 2:
        assert "allow-private-networks requires trusted-target: true" in p.stderr
