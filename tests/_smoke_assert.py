"""Single source of the cli-smoke invariant (ci.yml + scripts/ci_parity.sh).

Not a literal score: the fixture server's live score moves with the ruleset
(90 under 2026.09, 91 under 2026.10) while the invariants below do not."""
from __future__ import annotations

import json
import sys


def check(report: dict) -> list[str]:
    s = report["score"]
    problems = []
    if s.get("status") != "OK":
        problems.append(f"status={s.get('status')!r}")
    if s.get("scope") != "CANONICAL":
        problems.append(f"scope={s.get('scope')!r}")
    if s.get("grade") != "A":
        problems.append(f"grade={s.get('grade')!r}")
    if not isinstance(s.get("value"), int) or s["value"] < 85:
        problems.append(f"value={s.get('value')!r} < 85")
    # AS-1: `Report.security` is never scored — a smoke report claiming
    # otherwise would mean the report/gate/action contract drifted.
    if report.get("security", {}).get("scored") is not False:
        problems.append("security.scored != false")
    return problems


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)
    problems = check(report)
    if problems:
        print("cli-smoke invariant violated:", ", ".join(problems), report["score"], file=sys.stderr)
        sys.exit(1)
    print("cli-smoke ok:", report["score"])
