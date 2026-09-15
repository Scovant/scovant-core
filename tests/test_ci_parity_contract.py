"""Every command the public CI runs must also run in `scripts/ci_parity.sh`.

The package is developed inside a private monorepo and published to a public
mirror that runs `.github/workflows/ci.yml` on its own. Without a local
reproduction of that workflow, a change can be merged privately and only then
turn the mirror red, in public, with nobody watching. `scripts/ci_parity.sh`
is that reproduction; this test is what keeps it from drifting behind ci.yml.

The classification is TOTAL, deliberately: every non-empty, non-comment `run`
line of ci.yml is either REPRODUCED (must appear verbatim in the parity
script) or IGNORED (matched by an anchored rule below, each with its reason).
A line that is neither fails the test by name. A whitelist of "interesting"
prefixes was tried first and was worse than useless: a new `pip-audit --strict`
step could be added to ci.yml and this test stayed green, which is exactly the
silence it exists to break.

Ignore rules are anchored at the start of the line (never a substring search),
so a broad word like `node` or `twine` appearing mid-command cannot swallow a
real check.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
PARITY = ROOT / "scripts" / "ci_parity.sh"

# Line prefixes the parity script must reproduce verbatim. Includes the
# cli-smoke job's shell scaffolding: the readiness wait and the `code <= 1`
# rule are part of what the job asserts, not decoration around it.
_REPRODUCED = (
    "ruff ",
    "mypy ",
    "pytest ",
    "scovant ",
    "python -m tests.",
    "curl -sf http",
    "for i in $(seq",
    "sleep ",
    "done",
    "ready=0",
    "code=$?",
    "set +e",
    "set -e",
    "[[ ",
)

# (anchored prefix, why parity does not run it). Both fields are required —
# an ignore is a reviewed decision, not an accident of a prefix list.
_IGNORED = (
    ("pip install ", "environment setup: parity documents its own prerequisite install, "
                     "and cli-smoke installs the built wheel into a throwaway venv"),
    ("python -m build", "parity builds a wheel with --wheel --outdir (outside the tree); "
                        "the full sdist+wheel build is the release workflow's job"),
    ("twine check ", "needs the sdist+wheel pair produced by the `build` job; the release "
                     "workflow gates on it"),
    ("node ", "the `npm` job cannot run on an exported tree (see `git diff` below); "
              "it stays mirror-only, deliberately"),
    ("git diff --exit-code npm/", "needs a git repository, and `git archive` produces a "
                                  "plain directory"),
)


def classify(ci_text: str) -> tuple[set[str], list[str]]:
    """Split ci.yml's run lines into (reproduced, unclassified)."""
    doc = yaml.safe_load(ci_text)
    reproduced: set[str] = set()
    unclassified: list[str] = []
    for job in doc["jobs"].values():
        for step in job["steps"]:
            run = step.get("run")
            if not run:
                continue
            for raw in run.strip().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(_REPRODUCED):
                    reproduced.add(re.sub(r"\s+", " ", line))
                elif not any(line.startswith(prefix) for prefix, _ in _IGNORED):
                    unclassified.append(line)
    return reproduced, unclassified


def ci_commands() -> set[str]:
    return classify(CI.read_text(encoding="utf-8"))[0]


def executable_parity_text(script_text: str) -> str:
    """The parity script's RUNNABLE text, whitespace-normalised.

    `#` comment lines are dropped first: the script's header quotes the very
    commands it reproduces, and a command that is only mentioned (or has been
    commented out while debugging) must not satisfy the byte-identity match
    below. Only full-line comments are stripped — a `#` inside a command is
    not necessarily a comment, and no parity command relies on one.
    """
    lines = [ln for ln in script_text.splitlines() if not ln.lstrip().startswith("#")]
    return re.sub(r"\s+", " ", "\n".join(lines))


def test_parity_script_covers_every_ci_command():
    parity = executable_parity_text(PARITY.read_text(encoding="utf-8"))
    missing = {c for c in ci_commands() if c not in parity}
    assert not missing, f"ci.yml runs commands scripts/ci_parity.sh does not: {missing}"


def test_a_commented_out_parity_command_does_not_count_as_present():
    """Falsifiability: the match above must read what the script RUNS, not what
    it mentions. A parity script whose only `mypy src` is commented out has to
    read as missing that command."""
    commented = "set -euo pipefail\n# $PY -m mypy src; ok typecheck\nruff check src tests\n"
    text = executable_parity_text(commented)
    assert "mypy src" not in text
    assert "ruff check src tests" in text


def test_every_ci_command_is_classified():
    unclassified = classify(CI.read_text(encoding="utf-8"))[1]
    assert not unclassified, (
        "unclassified ci.yml command: "
        + "; ".join(unclassified)
        + " — either reproduce it in scripts/ci_parity.sh (add its prefix to _REPRODUCED) "
          "or add an anchored _IGNORED rule with a reason"
    )


def test_an_unknown_command_is_reported_unclassified():
    """The guarantee above is only worth the failure it produces: a step nobody
    thought about must be named, not quietly skipped."""
    synthetic = """
jobs:
  audit:
    steps:
      - run: pip install pip-audit
      - run: pip-audit --strict
"""
    reproduced, unclassified = classify(synthetic)
    assert unclassified == ["pip-audit --strict"]
    assert not reproduced


def test_ci_commands_are_actually_collected():
    """A collector that silently returns nothing would make the byte-identity
    test pass for every possible parity script, including an empty one."""
    cmds = ci_commands()
    assert any(c.startswith("mypy src") for c in cmds)
    assert any("--cov-fail-under=90" in c for c in cmds)
    assert any(c.startswith("ruff check") for c in cmds)
    assert any(c.startswith("scovant scan http") for c in cmds)
    assert any(c.startswith("python -m tests._smoke_assert") for c in cmds)
    # One per marker job plus the coverage run.
    assert len([c for c in cmds if c.startswith("pytest ")]) == 4
