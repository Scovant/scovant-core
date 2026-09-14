"""Pins the committed docs to their generator functions, and pins the README
to the required §43 section structure — see `docs.py` and `README.md`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import scovant_core.docs as _docs_module
from scovant_core.docs import main, render_checks, render_example, render_weights_table

PKG_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = PKG_ROOT / "docs" / "example-report.md"

if not (PKG_ROOT / "README.md").exists():
    # test-core-isolated copies tests/ + fixtures/ + docs/ + README.md (see
    # ci.yml's test-core-isolated step and test_no_cloud_imports.py) — but
    # only alongside the tests, never at the package root. These tests pin
    # the committed repo tree to its generator functions; they only make
    # sense running from within the checked-out repo, not from an
    # installed-package dir with no repo tree alongside it.
    pytestmark = pytest.mark.skip(reason="package docs/README not present (isolated run)")

# render_example() locates the `commerce-good` golden fixture relative to
# docs.py's OWN installed location (`Path(__file__).resolve().parents[2]`),
# not relative to this test file — and the wheel's `[tool.hatch.build.targets.wheel]`
# deliberately ships only `src/scovant_core` (fixtures/docs are sdist-only,
# dev tooling). In the isolated job, scovant-core is installed non-editably
# into the venv's site-packages, so that path can never resolve there even
# though we copied fixtures/ alongside the tests — this is a real gap in
# what the installed package can do, not a copy-list omission.
_golden_fixture_reachable = (
    Path(_docs_module.__file__).resolve().parents[2]
    / "fixtures" / "sites" / "expected" / "commerce-good.json"
).is_file()
skip_needs_golden_fixture = pytest.mark.skipif(
    not _golden_fixture_reachable,
    reason="commerce-good golden fixture not shipped alongside the installed package (isolated run)",
)

README_SECTIONS = (
    "Definition",
    "30-second install",
    "Example output",
    "What Core checks",
    "What Core does NOT test",
    "Core vs Cloud",
    "GitHub Action",
    "JSON, Markdown and HTML output",
    "MCP",
    "Methodology",
    "Security",
    "Contributing",
    "License",
)


def test_checks_md_matches_generator():
    committed = (PKG_ROOT / "docs" / "checks.md").read_text(encoding="utf-8")
    assert committed == render_checks()


def test_methodology_contains_weights_table_verbatim():
    methodology = (PKG_ROOT / "docs" / "methodology.md").read_text(encoding="utf-8")
    assert render_weights_table() in methodology


def test_readme_has_every_section_heading_in_order():
    readme = (PKG_ROOT / "README.md").read_text(encoding="utf-8")
    positions = []
    for heading in README_SECTIONS:
        pattern = re.compile(rf"^##+ {re.escape(heading)}\s*$", re.MULTILINE)
        m = pattern.search(readme)
        assert m, f"README.md is missing the {heading!r} section heading"
        positions.append(m.start())
    assert positions == sorted(positions), "README.md sections are out of order"


def test_readme_never_uses_the_cloud_score_name():
    readme = (PKG_ROOT / "README.md").read_text(encoding="utf-8")
    assert "Agent Readiness Score" not in readme


def test_cloud_matrix_matches_core_vs_cloud_doc():
    from scovant_core.report._cloud_matrix import CORE_VS_CLOUD

    doc = (PKG_ROOT / "docs" / "core-vs-cloud.md").read_text(encoding="utf-8")
    lines = doc.splitlines()
    start = lines.index("## Capability matrix")
    rows = []
    in_table = False
    for line in lines[start + 1:]:
        if line.startswith("| "):
            in_table = True
            if line.startswith("| Capability") or line.startswith("|---"):
                continue
            rows.append(line)
        elif in_table and line.strip() == "":
            break
    # The doc's sub-heading row wraps its capability cell in Markdown `**…**`
    # bold markup (so it renders bold on GitHub); CORE_VS_CLOUD carries that
    # cell's plain text (HTML rendering applies its own <strong> instead —
    # see report/html.py). Strip a cell-wrapping "**" pair before comparing.
    def _unbold(cell: str) -> str:
        return cell[2:-2] if cell.startswith("**") and cell.endswith("**") else cell

    parsed = tuple(tuple(_unbold(c.strip()) for c in r.strip("|").split("|")) for r in rows)
    assert parsed == CORE_VS_CLOUD


def test_core_boundary_sentence_matches_readme_and_doc():
    from scovant_core.report._cloud_matrix import CORE_BOUNDARY

    readme = (PKG_ROOT / "README.md").read_text(encoding="utf-8")
    doc = (PKG_ROOT / "docs" / "core-vs-cloud.md").read_text(encoding="utf-8")

    readme_lines = readme.splitlines()
    heading_idx = readme_lines.index("## Core vs Cloud")
    # The sentence is the first non-blank line after the heading.
    readme_sentence = next(
        line for line in readme_lines[heading_idx + 1:] if line.strip()
    )

    # docs/core-vs-cloud.md's own first line is its `#` title; the boundary
    # sentence is the first non-blank line after it.
    doc_lines = doc.splitlines()
    doc_sentence = next(line for line in doc_lines[1:] if line.strip())

    assert readme_sentence == CORE_BOUNDARY
    assert doc_sentence == CORE_BOUNDARY


@skip_needs_golden_fixture
def test_committed_example_matches_the_generator():
    assert EXAMPLE.read_text(encoding="utf-8") == render_example(), \
        "run: python -m scovant_core.docs --example"


@skip_needs_golden_fixture
def test_example_is_rendered_from_the_golden_fixture_not_a_live_site():
    text = render_example()
    assert "commerce-good" in text
    assert "https://example.com" in text
    # The report's own target is the RFC 2606 `example.com` fixture host, not
    # a real site — pinned on the title line itself, since a bare
    # `"scovant.com" not in text` assertion would also reject the CTA link
    # every report renders ("Verify with real agents: scovant.com/scan"),
    # which is intentional product copy, not a leaked internal reference.
    assert "# Scovant Core — https://example.com/" in text


def test_example_report_attributes_its_cta_to_the_docs_medium_not_cli():
    # docs/example-report.md is a committed static document, not CLI output —
    # attributing clicks from it to utm_medium=cli would misreport the
    # Core-to-Cloud funnel's per-medium breakdown. Pinned so render_example()
    # can't silently fall back to render_markdown's "cli" default.
    text = EXAMPLE.read_text(encoding="utf-8")
    assert "utm_medium=docs" in text
    assert "utm_medium=cli" not in text


@skip_needs_golden_fixture
def test_readme_example_output_matches_the_text_renderer():
    """README.md's "Example output" ```text``` block must be exactly
    `render_text`'s output over the same `commerce-good` golden fixture
    `docs/example-report.md` is generated from — never hand-typed, so it
    can't go stale the way it did before the 0.3.0 fix wave (the block still
    showed pre-0.3.0 tallies: 37/0/8, no CORE-ACCESS-011/CORE-OPERABILITY-011
    findings)."""
    import json

    from scovant_core.models import Report
    from scovant_core.report.text import render_text

    golden = (
        Path(_docs_module.__file__).resolve().parents[2]
        / "fixtures" / "sites" / "expected" / "commerce-good.json"
    )
    report = Report.model_validate(json.loads(golden.read_text(encoding="utf-8")))
    expected = render_text(report).rstrip("\n")

    readme = (PKG_ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"```text\n(.*?)\n```", readme, re.DOTALL)
    assert m, "README.md must carry a ```text``` example-output block"
    assert m.group(1) == expected, (
        "README.md's example-output block has drifted from the text renderer "
        "— regenerate it (see docs/example-report.md's own generation pattern)"
    )


def test_main_rejects_an_unknown_flag():
    assert main(["--nope"]) == 2


def test_readme_contains_both_pinned_sentences_verbatim():
    readme = (PKG_ROOT / "README.md").read_text(encoding="utf-8")
    assert (
        "Scovant Core is an open-source passive scanner for machine-facing website "
        "signals used by AI agents. It checks crawler policy, structured data, agent "
        "discovery surfaces, protocol metadata, commerce signals and basic operability."
    ) in readme
    assert (
        "A high Core Score does not prove that autonomous agents can complete real "
        "workflows on the site."
    ) in readme


def test_methodology_named_truncation_example_is_a_label_the_code_really_emits():
    """The 'Truncated documents' section quotes a named-document variant of
    the truncation note (`record_truncation(..., document=...)`) as a
    worked example. That label must be one some real check actually passes
    — pinned against the audited call-site list in
    test_truncation_document_labels.py — so a hand-picked example can never
    go stale the way "llms.txt" did: that label was deliberately DROPPED
    from the code (the llms gatherer record folds llms.txt and
    llms-full.txt into one flag, and `test_no_document_label_is_attached_
    to_a_folded_multi_document_record` forbids attaching a document label to
    a folded record), so a doc still quoting it would describe a sentence
    our own tool never produces."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "truncation_labels", Path(__file__).with_name("test_truncation_document_labels.py")
    )
    labels_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(labels_mod)
    real_labels = {label for (_, _, label) in labels_mod.AUDITED_DOCUMENT_CALLS}

    methodology = (PKG_ROOT / "docs" / "methodology.md").read_text(encoding="utf-8")
    matches = [label for label in real_labels if f'"The {label} body' in methodology]
    assert matches, (
        f"methodology.md's named-document truncation example doesn't match any label "
        f"a real check actually passes to record_truncation(document=...); real labels: {sorted(real_labels)}"
    )
    assert len(matches) == 1, f"ambiguous — more than one real label matched: {matches}"
    section = methodology.split("## Truncated documents", 1)[1].split("## Scoring formula", 1)[0]
    assert "llms.txt" not in section, (
        "the dropped 'llms.txt' document label must not reappear in the Truncated documents section"
    )
    # `sitemap` joined `llms.txt` as a dropped label: `sitemap_urls`'
    # `body_truncated` is an OR across the sitemap index, a followed child
    # sitemap and the direct probe, so no single document name is honest
    # there and CORE-ACCESS-005/-006 now use the unnamed form.
    assert '"The sitemap body' not in section, (
        "the dropped 'sitemap' document label must not reappear as a named-document example"
    )
