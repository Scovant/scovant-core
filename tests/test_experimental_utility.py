from scovant_core.checks.access.core_access_011 import LlmsTxtUtility, llms_signals
from scovant_core.checks.operability.core_operability_011 import DiscoveryLinkage, linkage

ORIGIN = "https://example.com"


def test_llms_signals_flags_no_useful_references():
    s = llms_signals("# Site\n\n> Summary of the site\n\n## Docs\n\n- [Guide](https://elsewhere.test/guide)\n", ["https://elsewhere.test/guide"], ORIGIN, False, False)
    assert s["no_useful_references"] is True and s["same_origin_links"] == 0


def test_llms_signals_policy_misuse_only_without_robots_declaration():
    raw = "# Site\n\n> Summary\n\nUser-agent: GPTBot\nDisallow: /\n\n## Docs\n\n- [Guide](https://example.com/guide)\n"
    assert llms_signals(raw, ["https://example.com/guide"], ORIGIN, False, False)["policy_misuse"] is True
    assert llms_signals(raw, ["https://example.com/guide"], ORIGIN, True, False)["policy_misuse"] is False


def test_llms_signals_generic_template():
    raw = "# Title\n\n> Description of the project\n\n## Docs\n\n- [Docs](https://example.com/docs)\n\n## Optional\n"
    s = llms_signals(raw, ["https://example.com/docs"], ORIGIN, False, False)
    assert s["generic_template"] is True


def test_llms_signals_generic_template_optional_empty_alone_is_not_enough():
    raw = ("# Site\n\n> This site publishes documentation and API references for developers.\n\n"
           "## Docs\n\n- [Docs](https://elsewhere.test/docs)\n\n## Optional\n")
    s = llms_signals(raw, ["https://elsewhere.test/docs"], ORIGIN, False, False)
    assert s["generic_template"] is False


def test_llms_signals_generic_template_short_summary_alone_is_not_enough():
    raw = "# Site\n\n> Site info\n\n## Docs\n\n- [Docs](https://elsewhere.test/docs)\n"
    s = llms_signals(raw, ["https://elsewhere.test/docs"], ORIGIN, False, False)
    assert s["generic_template"] is False


def test_llms_signals_generic_template_placeholders_alone_is_not_enough():
    raw = ("# Site\n\n> This site provides documentation and API references for developers to explore.\n\n"
           "## Docs\n\n- [Docs](https://elsewhere.test/docs)\n\n"
           "Description of the project details are included below for reference.\n")
    s = llms_signals(raw, ["https://elsewhere.test/docs"], ORIGIN, False, False)
    assert s["generic_template"] is False


def test_llms_signals_generic_template_any_two_signals_trip_it():
    # optional_empty + placeholders (the existing generic-template test covers
    # this pair too, via a different raw shape).
    both_optional_and_placeholder = (
        "# Title\n\n> Description of the project\n\n## Docs\n\n- [Docs](https://example.com/docs)\n\n## Optional\n"
    )
    assert llms_signals(both_optional_and_placeholder, ["https://example.com/docs"], ORIGIN, False, False)["generic_template"] is True

    # short_summary + placeholders, with no "## Optional" heading at all.
    both_short_and_placeholder = "# Site\n\n> example.com\n\n## Docs\n\n- [Docs](https://elsewhere.test/docs)\n"
    assert llms_signals(both_short_and_placeholder, ["https://elsewhere.test/docs"], ORIGIN, False, False)["generic_template"] is True

    # optional_empty + short_summary, with no template phrase at all.
    both_optional_and_short = "# Site\n\n> Site\n\n## Docs\n\n- [Docs](https://elsewhere.test/docs)\n\n## Optional\n"
    assert llms_signals(both_optional_and_short, ["https://elsewhere.test/docs"], ORIGIN, False, False)["generic_template"] is True


def test_llms_signals_clean_file():
    raw = "# Acme\n\n> Acme sells widgets; docs, pricing and API below.\n\n## Docs\n\n- [API](https://example.com/api)\n- [Pricing](https://example.com/pricing)\n"
    s = llms_signals(raw, ["https://example.com/api", "https://example.com/pricing"], ORIGIN, False, False)
    assert not any(s[k] for k in ("no_useful_references", "policy_misuse", "generic_template"))


def test_linkage_counts_present_and_linked():
    out = linkage({"llms_txt": "https://example.com/llms.txt", "openapi": "https://example.com/openapi.json", "mcp": None},
                  {"https://example.com/llms.txt": {"entry_page"}, "https://example.com/openapi.json": set()})
    assert out["present"] == 2 and out["linked"] == 1
    assert out["surfaces"]["llms_txt"]["linked_from"] == ["entry_page"] and out["surfaces"]["openapi"]["linked_from"] == []
    assert out["surfaces"]["mcp"]["present"] is False


def test_checks_are_experimental_and_registered():
    from scovant_core.checks.registry import CHECKS
    ids = {c.id: c for c in CHECKS}
    assert ids["CORE-ACCESS-011"].experimental and ids["CORE-OPERABILITY-011"].experimental
    assert isinstance(ids["CORE-ACCESS-011"], LlmsTxtUtility) and isinstance(ids["CORE-OPERABILITY-011"], DiscoveryLinkage)
