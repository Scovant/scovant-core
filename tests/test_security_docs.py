"""Pins the security-related docs to the live registry and to the shape the
AS-1 spec requires — see docs/security.md and docs/methodology.md's
"Security signals are reported, not scored" section."""
from pathlib import Path

from scovant_core.docs import render_checks

ROOT = Path(__file__).resolve().parents[1]


def test_checks_md_has_security_section_with_family_ids():
    # The docs/checks.md == render_checks() byte-equality itself is already
    # pinned by test_docs.py::test_checks_md_matches_generator and
    # test_docs_standards.py::test_checks_doc_lists_standards_per_mapped_check
    # — this test owns only the new-content assertions specific to the
    # SECURITY section.
    md = render_checks()
    assert "## Agentic Security & Trust" in md and "SEC-WEB-001" in md and "PASSIVE_OBSERVED" in md and "Fix owner" in md


def test_docs_state_counts_and_boundary():
    meth = (ROOT / "docs/methodology.md").read_text(encoding="utf-8")
    assert "66 checks" in meth and "16 security checks" in meth and "never enter the score" in meth
    sec = (ROOT / "docs/security.md").read_text(encoding="utf-8")
    for must in ("PASSIVE SIGNALS ONLY", "Core MUST NOT", "MACHINE-DATA-005", "RFC 9116", "RFC 9728", "No failures were observed"):
        assert must in sec
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Scovant Core is an open-source, evidence-first scanner for passive AI-agent readiness signals on websites" in readme
    assert "50 checks" not in readme or "50 readiness checks" in readme


def test_standards_mapping_table_is_derived_from_the_registry():
    """docs/security.md's per-check standards table must agree with the
    `standards` tuples the checks themselves declare — the tuples are the
    truth. Before this pin, the hand-written table mapped 009 to ASI03,
    007/008/010 to ASI04 and PROMPT-SURFACE-* to ASI01+ASI09, none of which
    matched the code."""
    import scovant_core.checks as _unused  # noqa: F401 — populates the registry
    from scovant_core.checks.registry import CHECKS
    from scovant_core.models import Category

    sec = (ROOT / "docs/security.md").read_text(encoding="utf-8")
    security_checks = [c for c in CHECKS if c.category == Category.SECURITY]
    assert security_checks
    for c in security_checks:
        assert c.standards, c.id
        # Bound outside the f-string: an attribute expression interpolated
        # into a string literal reads as a dotted bare token to the publish
        # guard's test-hostname heuristic (`.id` is a real ccTLD suffix).
        fam, cid = c.family_id, c.id
        for std in c.standards:
            kind = "OWASP mapping" if std.startswith("OWASP") else "reference"
            row = f"| {fam} | {cid} | {std} | {kind} | PARTIAL |"
            assert row in sec, row
    # And the reverse direction: no row may name a standard the check does
    # not declare, so a stale row cannot survive a `standards` edit.
    declared = {(c.family_id, c.id, std) for c in security_checks for std in c.standards}
    for line in sec.splitlines():
        if line.startswith(("| SEC-", "| MACHINE-DATA-", "| PROMPT-SURFACE-")):
            cells = [cell.strip() for cell in line.split("|")[1:-1]]
            assert tuple(cells[:3]) in declared, line
