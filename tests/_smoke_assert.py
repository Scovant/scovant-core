"""Single source of the cli-smoke invariant (ci.yml + scripts/ci_parity.sh).

Not a literal rating: the fixture server's live Technical Readiness moves with
the model (86/B today — a plain-http loopback target, canonical/references
hardcoded to https://example.com, no MCP handshake) while the invariants
below do not."""
from __future__ import annotations

import json
import sys

_MIN_RATING = 80
_REMOVED_KEYS = ("score", "categories")


def check(report: dict) -> list[str]:
    t = (report.get("readiness") or {}).get("technical")
    if t is None:
        return ["readiness.technical missing"]
    problems = []
    if t.get("status") != "OK":
        problems.append(f"technical.status={t.get('status')!r}")
    if t.get("grade") not in ("A", "B"):
        problems.append(f"technical.grade={t.get('grade')!r}")
    if not isinstance(t.get("rating"), int) or t["rating"] < _MIN_RATING:
        problems.append(f"technical.rating={t.get('rating')!r} < {_MIN_RATING}")
    scope = (report.get("provenance") or {}).get("scan_scope")
    if scope != "CANONICAL":
        problems.append(f"scan_scope={scope!r}")
    # AS-1: `Report.security` is never rated — a smoke report claiming
    # otherwise would mean the report/gate/action contract drifted.
    if report.get("security", {}).get("scored") is not False:
        problems.append("security.scored != false")
    # Schema 2.0 (0.19.0) removed the five-domain score.
    problems += [f"removed key present: {k}" for k in _REMOVED_KEYS if k in report]
    return problems


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        report = json.load(fh)
    problems = check(report)
    summary = (report.get("readiness") or {}).get("technical")
    if problems:
        print("cli-smoke invariant violated:", ", ".join(problems), summary, file=sys.stderr)
        sys.exit(1)
    print("cli-smoke ok:", summary)
