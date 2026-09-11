"""Pins the committed docs to their generator functions, and pins the README
to the required §43 section structure — see `docs.py` and `README.md`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from scovant_core.docs import main, render_checks, render_example, render_weights_table

PKG_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = PKG_ROOT / "docs" / "example-report.md"

if not (PKG_ROOT / "README.md").exists():
    # test-core-isolated copies only tests/ + fixtures/ into the isolated run
    # (see test_no_cloud_imports.py) — README.md/docs/ live at the package
    # root and are deliberately absent there. These tests pin the committed
    # repo tree to its generator functions; they only make sense running
    # from within the checked-out repo, not from an installed-package dir
    # with no repo tree alongside it.
    pytestmark = pytest.mark.skip(reason="package docs/README not present (isolated run)")

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
    parsed = tuple(tuple(c.strip() for c in r.strip("|").split("|")) for r in rows)
    assert parsed == CORE_VS_CLOUD


def test_committed_example_matches_the_generator():
    assert EXAMPLE.read_text(encoding="utf-8") == render_example(), \
        "run: python -m scovant_core.docs --example"


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
