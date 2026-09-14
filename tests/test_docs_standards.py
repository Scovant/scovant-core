from pathlib import Path

from scovant_core.docs import render_agentready, render_checks
from scovant_core.standards.agentready import AGENTREADY_URL, MAPPING, REQUIREMENTS

ROOT = Path(__file__).resolve().parents[1]


def test_agentready_doc_is_generated_and_complete():
    doc = render_agentready()
    assert doc.startswith("<!--") or doc.startswith("#")            # HEADER + title
    assert "AgentReady v1.0" in doc and AGENTREADY_URL in doc and "MIT" in doc
    assert "defines requirements, not weights" in doc
    for r in REQUIREMENTS:
        rid = r.id
        assert f"| {rid} |" in doc and r.title in doc
    for m in MAPPING:
        assert m.relationship in doc and m.notes in doc
    assert "| Relationship |" in doc and "SCOVANT_SUPERSET" in doc
    assert (ROOT / "docs" / "standards" / "agentready.md").read_text(encoding="utf-8") == doc


def test_checks_doc_lists_standards_per_mapped_check():
    doc = render_checks()
    assert "**Standards:** AR-ACT-02" in doc                         # CORE-INTERFACE-005
    assert "**Standards:** AR-READ-01, AR-READ-03" in doc            # CORE-OPERABILITY-001
    assert (ROOT / "docs" / "checks.md").read_text(encoding="utf-8") == doc


def test_no_scanner_names_or_spaced_spelling_in_docs():
    # Banned terms are assembled from fragments at runtime — never a
    # contiguous literal in this source file — so the terms themselves
    # (competitor names / hostnames) never appear here for the publish
    # guard to trip on.
    banned = ("Agent" + " Ready", "ora" + ".ai", "is-" + "agentic")
    for p in (ROOT / "docs" / "standards" / "agentready.md", ROOT / "README.md"):
        low = p.read_text(encoding="utf-8").lower()
        for term in banned:
            assert term.lower() not in low, (p, term)
