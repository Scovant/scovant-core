"""The curated crosswalk between the Core checks and the readiness rules.

Pins completeness both ways (every check, every rule, exactly once), the
relationship/rules consistency, derived counts, and the generated
`docs/crosswalk.md` byte-equal to its renderer.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from scovant_core import crosswalk
from scovant_core.checks.registry import CHECKS
from scovant_core.docs import main
from scovant_core.models import Category
from scovant_core.rules import RULES

ROOT = Path(__file__).resolve().parents[1]

_CORE_CODES = {r.code for r in RULES}
_CHECK_IDS = {c.id for c in CHECKS}
_ALL_RULES = _CORE_CODES | set(crosswalk.AGENT_ONLY_RULES)


def test_every_check_appears_exactly_once():
    ids = Counter(row.check_id for row in crosswalk.CHECK_ROWS)
    dupes = sorted(i for i, n in ids.items() if n > 1)
    assert not dupes, f"checks listed more than once: {dupes}"
    missing = sorted(_CHECK_IDS - set(ids))
    assert not missing, f"checks without a crosswalk row: {missing}"
    unknown = sorted(set(ids) - _CHECK_IDS)
    assert not unknown, f"crosswalk rows naming no registered check: {unknown}"


def test_every_rule_appears_exactly_once():
    rules = Counter(row.rule for row in crosswalk.RULE_ROWS)
    dupes = sorted(r for r, n in rules.items() if n > 1)
    assert not dupes, f"rules listed more than once: {dupes}"
    missing = sorted(_ALL_RULES - set(rules))
    assert not missing, f"rules without a crosswalk row: {missing}"
    unknown = sorted(set(rules) - _ALL_RULES)
    assert not unknown, f"rule rows naming no registered rule: {unknown}"


def test_rule_rows_say_who_evaluates_them():
    for row in crosswalk.RULE_ROWS:
        expected = "core" if row.rule in _CORE_CODES else "cloud_execution_only"
        assert row.evaluated_by == expected, row.rule


def test_agent_only_rules_are_not_core_rules():
    assert len(crosswalk.AGENT_ONLY_RULES) == len(set(crosswalk.AGENT_ONLY_RULES)) == 9
    assert not set(crosswalk.AGENT_ONLY_RULES) & _CORE_CODES


def test_check_rows_name_only_registered_rules():
    for row in crosswalk.CHECK_ROWS:
        unknown = sorted(set(row.rules) - _ALL_RULES)
        assert not unknown, f"{row.check_id} names unknown rule(s): {unknown}"
        assert len(row.rules) == len(set(row.rules)), row.check_id


def test_relationship_and_rules_agree():
    for row in crosswalk.CHECK_ROWS:
        assert row.relationship in ("same_signal", "partial", "diagnostic_only", "no_rule"), row.check_id
        if row.relationship == "no_rule":
            assert not row.rules, f"{row.check_id} is no_rule but names {row.rules}"
        else:
            assert row.rules, f"{row.check_id} is {row.relationship} but names no rule"
        if row.relationship in ("same_signal", "partial"):
            assert set(row.rules) - set(crosswalk.DIAGNOSTIC_RULES), (
                f"{row.check_id} is {row.relationship} but names only diagnostic rules")
        if row.relationship == "diagnostic_only":
            stray = sorted(set(row.rules) - set(crosswalk.DIAGNOSTIC_RULES))
            assert not stray, f"{row.check_id} is diagnostic_only but names non-diagnostic {stray}"


def test_diagnostic_rules_are_core_rules():
    assert set(crosswalk.DIAGNOSTIC_RULES) <= _CORE_CODES


def test_diagnostic_rules_are_the_technical_manifest_markers():
    from scovant_core.r2.technical import MARKER_CODES

    assert tuple(sorted(MARKER_CODES)) == crosswalk.DIAGNOSTIC_RULES


def test_rule_rows_carry_the_rules_own_maturity():
    by_code = {r.code: r.maturity for r in RULES}
    for row in crosswalk.RULE_ROWS:
        assert row.maturity == by_code.get(row.rule), row.rule
    doc = crosswalk.render_markdown()
    assert "| Rule | Evaluated by | Maturity |" in doc
    assert "experimental rules are reported but do not count toward the rating" in doc.lower()


def test_intro_does_not_claim_checks_carry_no_score():
    doc = crosswalk.render_markdown()
    assert "carries no score" not in doc
    assert "no weight in the Technical Readiness rating" in doc
    # 0.19.0 removed the five-domain score: the intro speaks of it in the past tense.
    assert "removed in 0.19.0" in doc and "due to be removed" not in doc and "deprecated" not in doc


def test_security_checks_are_no_rule():
    security = {c.id for c in CHECKS if c.category is Category.SECURITY}
    for row in crosswalk.CHECK_ROWS:
        if row.check_id in security:
            assert row.relationship == "no_rule", row.check_id


def test_notes_are_one_line_and_short():
    for row in crosswalk.CHECK_ROWS:
        assert row.note and "\n" not in row.note and "|" not in row.note, row.check_id
        assert len(row.note) <= 160, (row.check_id, len(row.note))


def test_counts_are_derived_from_the_registries():
    security = sum(1 for c in CHECKS if c.category is Category.SECURITY)
    expected = {
        "checks": len(CHECKS),
        "readiness_checks": len(CHECKS) - security,
        "security_checks": security,
        "rules": len(RULES) + len(crosswalk.AGENT_ONLY_RULES),
        "core_rules": len(RULES),
        "cloud_only_rules": len(crosswalk.AGENT_ONLY_RULES),
    }
    got = crosswalk.counts()
    assert {k: got[k] for k in expected} == expected
    # The published numbers this release describes (the Wave 4 keys are
    # derived in test_counts_carry_gathered_and_experimental).
    assert got == {"checks": 69, "readiness_checks": 51, "security_checks": 18,
                   "rules": 65, "core_rules": 56, "cloud_only_rules": 9,
                   "core_rules_gathered": 47, "core_rules_handshake": 9, "experimental_checks": 18,
                   "experimental_readiness_checks": 8, "experimental_security_checks": 10,
                   "experimental_core_rules": 24, "categories": 7}


def test_render_lists_every_row_and_the_counts():
    doc = crosswalk.render_markdown()
    for row in crosswalk.CHECK_ROWS:
        assert f"| {row.check_id} |" in doc and row.note in doc
    for row in crosswalk.RULE_ROWS:
        assert f"| {row.rule} | {row.evaluated_by} |" in doc
    c = crosswalk.counts()
    assert f"{c['checks']} checks" in doc and f"{c['rules']} readiness rules" in doc


def test_public_text_carries_no_private_policy_words():
    doc = crosswalk.render_markdown()
    # Built from parts so this test file does not itself carry the private
    # names the publish guard keeps out of the package.
    # "ai_bot_policy.identity" guards the identity-probe internals, which
    # stay out of every public text.
    banned_words = ("AGENT_" + "CAP", "AGENT_" + "POLICY", "agent-" + "private", "overlay" + "@",
                    "ai_bot_policy.identity")
    for banned in banned_words:
        assert banned not in doc


def test_committed_crosswalk_matches_the_generator():
    committed = (ROOT / "docs" / "crosswalk.md").read_text(encoding="utf-8")
    assert committed == crosswalk.render_markdown()


def test_main_crosswalk_flag_writes_the_doc(tmp_path, monkeypatch):
    import scovant_core.docs as docs_module

    target = tmp_path / "crosswalk.md"
    monkeypatch.setattr(docs_module, "_CROSSWALK_PATH", target)
    assert main(["--crosswalk"]) == 0
    assert target.read_text(encoding="utf-8") == crosswalk.render_markdown()


def _row(check_id):
    return next(r for r in crosswalk.CHECK_ROWS if r.check_id == check_id)


def test_reviewed_mappings_hold():
    # Remote-exec hits in the reference probe are LLMS-SUPPLY-006's evidence.
    assert "LLMS-SUPPLY-006" in _row("CORE-OPERABILITY-007").rules
    # The labelled-control share is JS_ONLY_CRITICAL_CONTENT's third condition.
    assert _row("CORE-OPERABILITY-006").rules == ("JS_ONLY_CRITICAL_CONTENT",)
    # The agent-only challenge rule judges Cloud's own fetch, and says so.
    assert "own agent fetch" in _row("CORE-OPERABILITY-010").note


def test_access_003_note_names_the_rules_own_tokens():
    from scovant_core.rules.robots_policy import AI_CRAWLERS

    note = _row("CORE-ACCESS-003").note
    assert all(token in note for token in AI_CRAWLERS)


def test_counts_carry_gathered_and_experimental():
    from scovant_core.checks.registry import CHECKS
    from scovant_core.crosswalk import counts
    from scovant_core.models import Category
    from scovant_core.r2.readiness import gathered_by_core

    c = counts()
    assert c["core_rules_gathered"] == sum(1 for r in RULES if gathered_by_core(r.code))
    assert c["core_rules_gathered"] < c["core_rules"]          # some rules are never gathered by the CLI
    from scovant_core.r2.readiness import MCP_HANDSHAKE_RULES
    assert c["core_rules_handshake"] == sum(1 for r in RULES if r.code in MCP_HANDSHAKE_RULES)
    assert c["experimental_checks"] == sum(1 for k in CHECKS if k.experimental)
    assert c["experimental_security_checks"] == sum(
        1 for k in CHECKS if k.experimental and k.category is Category.SECURITY)
    assert c["experimental_checks"] == c["experimental_readiness_checks"] + c["experimental_security_checks"]
    assert c["experimental_core_rules"] == sum(1 for r in RULES if r.maturity == "experimental")
    assert c["categories"] == 7


def test_core_evidence_values():
    from scovant_core.r2.readiness import core_evidence
    assert core_evidence("WEBMCP-001") == "not_gathered"
    assert core_evidence("MCP_DISCOVERY_INVALID") == "handshake_required"
    assert core_evidence("PAGE_TOKEN_BLOAT") == "tokenizer_optional"
    assert core_evidence("SITEMAP_MISSING_OR_INVALID") == "passive"


def test_every_no_rule_row_has_a_reason():
    from scovant_core.crosswalk import CHECK_ROWS
    bad = [r.check_id for r in CHECK_ROWS if r.relationship == "no_rule" and not (r.note or "").strip()]
    assert bad == []


def test_header_says_implemented_not_evaluated():
    """A Core rule whose evidence the CLI does not gather is implemented, not
    evaluated, by a plain scan — the header must not claim evaluation."""
    text = crosswalk.render_markdown()
    c = crosswalk.counts()
    assert "evaluated by Core" not in text
    assert f"{c['core_rules']} implemented in Core" in text


def test_ungathered_evidence_list_is_derived_from_the_rules():
    """The parenthetical naming the evidence a plain scan does not gather is
    built from the rules that read it, never hand-typed."""
    from scovant_core.r2.readiness import NOT_GATHERED_SOURCES, core_evidence

    used = [label for key, label in NOT_GATHERED_SOURCES
            if any(r.code == key or (key.endswith("-") and r.code.startswith(key)) for r in RULES)]
    assert used, "no Core rule reads ungathered evidence — the sentence would be empty"
    assert crosswalk.ungathered_evidence_phrase() in crosswalk.render_markdown()
    for label in used:
        assert label in crosswalk.ungathered_evidence_phrase()
    # every not-gathered rule is covered by some source
    for r in RULES:
        if core_evidence(r.code) == "not_gathered":
            assert any(r.code == k or (k.endswith("-") and r.code.startswith(k))
                       for k, _ in NOT_GATHERED_SOURCES), r.code
