"""Pure, I/O-free analysis helpers: visible-price extraction, static WebMCP
`registerTool` extraction, form-label semantics, and page-cost estimation."""
from __future__ import annotations

from scovant_core.analysis.form_semantics import analyse_forms
from scovant_core.analysis.page_cost import page_cost
from scovant_core.analysis.prices import find_visible_prices, parse_price_value
from scovant_core.analysis.webmcp_static import extract_webmcp_tools

# ---------------------------------------------------------------------------
# prices
# ---------------------------------------------------------------------------


def test_find_visible_prices_matches_symbol_prefixed_amount():
    assert find_visible_prices("Buy now for $19.99 today.") == ["$19.99"]


def test_find_visible_prices_matches_currency_code_suffix():
    assert find_visible_prices("Total: 1.299,00 EUR including VAT.") == ["1.299,00 EUR"]


def test_find_visible_prices_matches_symbol_with_space():
    assert find_visible_prices("Only € 5 per item.") == ["€ 5"]


def test_find_visible_prices_ignores_dates():
    assert find_visible_prices("Published on 2026-09-05.") == []


def test_find_visible_prices_ignores_version_strings():
    assert find_visible_prices("Requires scovant-core v1.2.3 or later.") == []


def test_find_visible_prices_preserves_order_and_caps_at_limit():
    text = " ".join(f"${n}.00" for n in range(1, 30))
    prices = find_visible_prices(text)
    assert len(prices) == 20
    assert prices[0] == "$1.00" and prices[-1] == "$20.00"


def test_parse_price_value_comma_thousands_period_decimal():
    assert parse_price_value("1,299.00") == 1299.0


def test_parse_price_value_period_thousands_comma_decimal():
    assert parse_price_value("1.299,00") == 1299.0


def test_parse_price_value_plain_decimal():
    assert parse_price_value("19.99") == 19.99


def test_parse_price_value_space_thousands():
    assert parse_price_value("1 299") == 1299.0


def test_parse_price_value_unparseable_returns_none():
    assert parse_price_value("not a price") is None


# ---------------------------------------------------------------------------
# webmcp_static
# ---------------------------------------------------------------------------


def test_extract_webmcp_tools_parses_a_valid_registration():
    html = (
        "<html><body><script>"
        "navigator.modelContext.registerTool({name:'add', description:'Add to cart',"
        "inputSchema:{type:'object',properties:{sku:{}}}});"
        "</script></body></html>"
    )
    tools, errors = extract_webmcp_tools(html)
    assert errors == 0
    assert len(tools) == 1
    tool = tools[0]
    assert tool["name"] == "add"
    assert tool["description"] == "Add to cart"
    assert tool["input_schema_keys"] == ["sku"]
    assert tool["has_schema"] is True


def test_extract_webmcp_tools_ignores_external_scripts():
    html = '<html><body><script src="/app.js">registerTool({name:"x"})</script></body></html>'
    tools, errors = extract_webmcp_tools(html)
    assert tools == [] and errors == 0


def test_extract_webmcp_tools_counts_unbalanced_literal_as_a_parse_error():
    html = (
        "<html><body><script>"
        "registerTool({name:'x', description:'y');"
        "</script></body></html>"
    )
    tools, errors = extract_webmcp_tools(html)
    assert tools == []
    assert errors == 1


def test_extract_webmcp_tools_reports_no_schema_when_input_schema_absent():
    html = "<html><body><script>registerTool({name:'ping'});</script></body></html>"
    tools, errors = extract_webmcp_tools(html)
    assert errors == 0
    assert tools[0]["input_schema_keys"] == []
    assert tools[0]["has_schema"] is False


def test_extract_webmcp_tools_ignores_a_call_inside_a_line_comment():
    html = (
        "<html><body><script>"
        "// registerTool({name:'x', description:'y'});\n"
        "console.log('noop');"
        "</script></body></html>"
    )
    tools, errors = extract_webmcp_tools(html)
    assert tools == [] and errors == 0


def test_extract_webmcp_tools_ignores_a_call_inside_a_block_comment():
    html = (
        "<html><body><script>"
        "/* registerTool({name:'x', description:'y'}); */"
        "console.log('noop');"
        "</script></body></html>"
    )
    tools, errors = extract_webmcp_tools(html)
    assert tools == [] and errors == 0


def test_extract_webmcp_tools_ignores_a_call_inside_a_string_literal():
    html = (
        "<html><body><script>"
        "var s = \"registerTool({name:'x'});\";"
        "console.log(s);"
        "</script></body></html>"
    )
    tools, errors = extract_webmcp_tools(html)
    assert tools == [] and errors == 0


def test_extract_webmcp_tools_still_finds_a_real_call_whose_description_has_slashes_and_braces():
    html = (
        "<html><body><script>"
        "registerTool({name:'docs', description:'See http://example.com/{ref} for details'});"
        "</script></body></html>"
    )
    tools, errors = extract_webmcp_tools(html)
    assert errors == 0
    assert len(tools) == 1
    assert tools[0]["name"] == "docs"
    assert tools[0]["description"] == "See http://example.com/{ref} for details"


def test_extract_webmcp_tools_skips_a_call_whose_argument_is_an_identifier_not_a_literal():
    """`registerTool(cfg)` references a variable we can't statically resolve
    — skipped silently (not a parse error), since no object-literal argument
    was ever present to fail parsing."""
    html = "<html><body><script>registerTool(cfg);</script></body></html>"
    tools, errors = extract_webmcp_tools(html)
    assert tools == [] and errors == 0


# ---------------------------------------------------------------------------
# form_semantics
# ---------------------------------------------------------------------------


def test_analyse_forms_counts_labelled_via_wrap_for_and_aria():
    html = (
        "<html><body><form>"
        '<label>Name <input type="text" name="name"></label>'
        '<label for="email-input">Email</label><input type="text" id="email-input" name="email">'
        '<input type="text" name="phone" aria-label="Phone">'
        '<input type="text" name="mystery">'
        "</form></body></html>"
    )
    result = analyse_forms(html)
    assert result["forms"] == 1
    assert result["inputs"] == 4
    assert result["unlabeled_inputs"] == 1


def test_analyse_forms_excludes_hidden_and_submit_inputs():
    html = (
        "<html><body><form>"
        '<input type="hidden" name="csrf" value="x">'
        '<input type="submit" value="Go">'
        '<input type="text" name="q">'
        "</form></body></html>"
    )
    result = analyse_forms(html)
    assert result["inputs"] == 1
    assert result["unlabeled_inputs"] == 1


def test_analyse_forms_counts_unnamed_buttons():
    html = "<html><body><form><button></button><button>Submit</button></form></body></html>"
    result = analyse_forms(html)
    assert result["unnamed_buttons"] == 1


def test_analyse_forms_counts_unlabelled_selects():
    html = (
        "<html><body><form>"
        "<select><option>a</option></select>"
        '<label for="s2">Pick</label><select id="s2"><option>a</option></select>'
        "</form></body></html>"
    )
    result = analyse_forms(html)
    assert result["unlabeled_selects"] == 1


def test_analyse_forms_no_forms_returns_zeros():
    result = analyse_forms("<html><body><p>Nothing here.</p></body></html>")
    assert result == {"forms": 0, "inputs": 0, "unlabeled_inputs": 0, "unnamed_buttons": 0, "unlabeled_selects": 0}


# ---------------------------------------------------------------------------
# page_cost
# ---------------------------------------------------------------------------


def test_page_cost_counts_dom_nodes_and_estimates_tokens():
    html = "<html><body><p>hello world</p></body></html>"
    visible_text = "hello world"
    cost = page_cost(html, token_chars_ratio=4)
    assert cost["text_chars"] == len(visible_text)
    assert cost["estimated_tokens"] == len(visible_text) // 4
    assert cost["html_bytes"] == len(html.encode())
    assert cost["dom_nodes"] > 0


def test_page_cost_script_ratio_is_bounded():
    html = "<html><body><script>var x = 1;</script><p>hi</p></body></html>"
    cost = page_cost(html, token_chars_ratio=4)
    assert 0 <= cost["script_ratio"] <= 1
    assert cost["script_bytes"] > 0


def test_page_cost_script_ratio_zero_on_empty_html():
    cost = page_cost("", token_chars_ratio=4)
    assert cost["script_ratio"] == 0
    assert cost["html_bytes"] == 0


def test_page_cost_counts_structured_bytes_and_links():
    html = (
        "<html><body>"
        '<script type="application/ld+json">{"@type":"Organization"}</script>'
        '<a href="/one">One</a><a href="/two">Two</a>'
        "</body></html>"
    )
    cost = page_cost(html, token_chars_ratio=4)
    assert cost["structured_bytes"] > 0
    assert cost["link_count"] == 2


def test_page_cost_text_chars_is_not_capped_at_5000():
    """`parsers.html.extract_visible_text` caps at 5000 chars for ITS OWN
    callers; `page_cost` must derive `text_chars`/`estimated_tokens` from an
    UNCAPPED extraction of the raw HTML — otherwise CORE-OPERABILITY-005
    can never measure a real page's true parse cost past 5000 chars (1250
    tokens at the default ratio), well below its own MEDIUM/HIGH
    thresholds."""
    filler = "a" * 40_000
    html = f"<html><body><p>{filler}</p></body></html>"
    cost = page_cost(html, token_chars_ratio=4)
    assert cost["text_chars"] > 5000
    assert cost["text_chars"] == 40_000
    assert cost["estimated_tokens"] == 10_000
