"""The package names the AgentReady STANDARD (one word) and never a scanner;
the two-word, spaced spelling of that scanner's name (see BANNED below) is a
competitor term in the monorepo's guard.

BANNED is assembled from fragments at runtime — never a contiguous literal
in this source file — so none of these competitor names / scanner hostnames
sit in the package tree for the publish guard's own boundary.competitor /
tests.hostname rules to trip on here (this file ships as part of the Core
test suite, which is scanned by the guard like everything else under
backend/scovant-core/), and so this test doesn't trip on its own BANNED
tuple when scanning the package tree it lives in.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNED = (
    "Agent" + " Ready",
    "ora" + ".ai",
    "is-" + "agentic",
    "isitagent" + "ready",
    "agent" + "grade",
)


def test_package_tree_has_no_scanner_names_or_spaced_spelling():
    hits = []
    for p in ROOT.rglob("*"):
        if p.is_dir() or any(part in ("node_modules", ".git", "__pycache__", "dist", "build") for part in p.parts):
            continue
        if p.suffix not in (".py", ".md", ".txt", ".yml", ".yaml", ".json", ".html", ".js", ".mjs", ".toml"):
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for term in BANNED:
            if re.search(rf"(?<!\w){re.escape(term)}(?!\w)", text, re.IGNORECASE):
                hits.append((str(p.relative_to(ROOT)), term))
    assert hits == [], hits
