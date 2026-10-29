"""Representation comparator (Markdown vs HTML) — real bodies, not hand-built facts."""
from scovant_core.representations.compare import (
    classify,
    compare,
    html_facts,
    markdown_facts,
)

PAGE = "https://shop.test/p/widget"

HTML = """<!doctype html><html><head>
<link rel="canonical" href="https://shop.test/p/widget">
<script type="application/ld+json">{"@type":"Product","name":"Blue Widget",
 "offers":{"@type":"Offer","price":"89.99","priceCurrency":"USD"}}</script></head>
<body><nav><a href="/login">Log in</a></nav>
<main><h1>Blue Widget</h1><h2>Specifications</h2>
<p>Only $89.99 today.</p>
<a href="/p/widget/reviews">Reviews</a> <a href="https://shop.test/p/gadget">Gadget</a>
<a href="/help/shipping">Shipping</a></main>
<footer><a href="/terms">Terms</a></footer></body></html>"""

MD_GOOD = """# Blue Widget

Source: https://shop.test/p/widget

## Specifications

Only $89.99 today.

[Reviews](/p/widget/reviews) · [Gadget](https://shop.test/p/gadget) · [Shipping](/help/shipping)
"""


def _cmp(md):
    return compare(html_facts(HTML, PAGE), markdown_facts(md, PAGE))


def test_html_facts_skip_chrome_and_read_jsonld():
    f = html_facts(HTML, PAGE)
    assert f["links"] == {"https://shop.test/p/widget/reviews", "https://shop.test/p/gadget",
                          "https://shop.test/help/shipping"}          # nav + footer dropped
    assert {"blue widget", "specifications"} <= f["entities"]
    assert f["prices"] == {89.99}
    assert f["canonical"] == "https://shop.test/p/widget"


def test_equivalent_markdown_passes():
    c = _cmp(MD_GOOD)
    assert c["links"]["covered_pct"] == 100.0 and c["entities"]["covered_pct"] == 100.0
    assert c["prices"]["missing"] == [] and c["prices"]["applicable"] is True
    assert c["attribution"] is True
    assert classify(c, content_type_ok=True) == "PASS"


def test_missing_price_fails():
    c = _cmp(MD_GOOD.replace("Only $89.99 today.", "Great value."))
    assert c["prices"]["missing"] == [89.99]
    assert classify(c, content_type_ok=True) == "FAIL"


def test_links_below_70_fail_and_85_warn():
    two_missing = MD_GOOD.replace(" · [Gadget](https://shop.test/p/gadget) · [Shipping](/help/shipping)", "")
    c = _cmp(two_missing)
    assert round(c["links"]["covered_pct"], 1) == 33.3
    assert classify(c, content_type_ok=True) == "FAIL"
    many = HTML.replace("</main>", "".join(f'<a href="/p/x{i}">x{i}</a>' for i in range(17)) + "</main>")
    md_many = MD_GOOD + "".join(f" [x{i}](/p/x{i})" for i in range(14))
    c2 = compare(html_facts(many, PAGE), markdown_facts(md_many, PAGE))
    assert c2["links"]["covered_pct"] == 85.0
    assert classify(c2, content_type_ok=True) == "WARN"


def test_missing_entities_warn():
    c = _cmp(MD_GOOD.replace("## Specifications\n", ""))
    assert c["entities"]["covered_pct"] < 90.0 and "specifications" in c["entities"]["missing_examples"]
    assert classify(c, content_type_ok=True) == "WARN"


def test_wrong_content_type_warns():
    assert classify(_cmp(MD_GOOD), content_type_ok=False) == "WARN"


def test_no_recognised_price_is_not_applicable():
    html = HTML.replace("$89.99", "₹7,499").replace('"price":"89.99","priceCurrency":"USD"', '"name":"x"')
    c = compare(html_facts(html, PAGE), markdown_facts(MD_GOOD.replace("$89.99", ""), PAGE))
    assert c["prices"]["applicable"] is False and c["prices"]["missing"] == []
    assert classify(c, content_type_ok=True) != "FAIL"


def test_page_without_links_has_no_coverage_not_zero():
    html = "<html><body><main><h1>Hello</h1></main></body></html>"
    c = compare(html_facts(html, PAGE), markdown_facts("# Hello\n", PAGE))
    assert c["links"]["covered_pct"] is None
    assert classify(c, content_type_ok=True) == "PASS"


def test_examples_are_capped():
    html = HTML.replace("</main>", "".join(f'<a href="/p/y{i}">y</a>' for i in range(20)) + "</main>")
    c = compare(html_facts(html, PAGE), markdown_facts("# Blue Widget\n", PAGE))
    assert len(c["links"]["missing_examples"]) == 5


def test_jsonld_price_in_unmatched_currency_is_not_applicable():
    # INR is outside the matcher's currency list: the JSON-LD Offer must not
    # make the price sub-check applicable, or a correct Markdown is marked FAIL.
    html = (
        '<html><head><script type="application/ld+json">'
        '{"@type":"Product","name":"Blue Widget","offers":{"@type":"Offer",'
        '"price":"7499","priceCurrency":"INR"}}</script></head>'
        "<body><main><h1>Blue Widget</h1><p>Price ₹7,499</p></main></body></html>"
    )
    md = "# Blue Widget\n\nPrice ₹7,499\n"
    c = compare(html_facts(html, PAGE), markdown_facts(md, PAGE))
    assert c["prices"]["applicable"] is False
    assert c["prices"]["missing"] == []
    assert classify(c, content_type_ok=True) != "FAIL"


def test_entities_ignore_punctuation_and_inline_markup():
    h = html_facts("<html><body><main><h2>Find out in about a <em>minute</em>.</h2></main></body></html>", PAGE)
    m = markdown_facts("## Find out in about a minute.\n", PAGE)
    assert compare(h, m)["entities"]["covered_pct"] == 100.0


def _many_prices_html(n):
    items = "".join(f"<li>Item {i} ${i}.99</li>" for i in range(1, n + 1))
    return ("<html><body><header><p>Free shipping over $50</p></header>"
            f"<main><h1>Catalog</h1><ul>{items}</ul></main></body></html>")


def _many_prices_md(n):
    return "Free shipping over $50\n\n# Catalog\n\n" + "".join(f"- Item {i} ${i}.99\n" for i in range(1, n + 1))


def test_more_than_twenty_prices_all_carried_is_not_a_fail():
    # Finding 1: each side used to keep only its first 20 prices; chrome removal
    # shifts the HTML order, so a price the Markdown does carry read "missing".
    c = compare(html_facts(_many_prices_html(30), PAGE), markdown_facts(_many_prices_md(30), PAGE))
    assert c["prices"]["applicable"] is True
    assert c["prices"]["missing"] == []
    assert classify(c, content_type_ok=True) == "PASS"


def test_price_scan_hitting_the_cap_is_not_applicable(monkeypatch):
    import scovant_core.representations.compare as cmp_mod
    monkeypatch.setattr(cmp_mod, "PRICE_SCAN_LIMIT", 10)
    # The Markdown drops item 30, but neither side was read in full: no verdict on prices.
    c = cmp_mod.compare(cmp_mod.html_facts(_many_prices_html(30), PAGE),
                        cmp_mod.markdown_facts(_many_prices_md(29), PAGE))
    assert c["prices"]["applicable"] is False and c["prices"]["missing"] == []
    assert c["prices"]["capped"] is True
    assert classify(c, content_type_ok=True) != "FAIL"


def test_missing_prices_list_stays_capped():
    c = compare(html_facts(_many_prices_html(30), PAGE), markdown_facts("# Catalog\n", PAGE))
    assert len(c["prices"]["missing"]) == 5


# Markdown representations link to the Markdown representation of other pages
# (`/docs/x.md`, `/index.md`), the shape real documentation sites' Markdown
# answers use; the HTML links to `/docs/x`. Both are the same page.
DOCS_PAGE = "https://docs.example.test/"
DOCS_HTML = """<!doctype html><html><body><main><h1>Docs</h1>
<a href="/get-started/installation">Install</a>
<a href="/deploy/web">Deploy to the web</a>
<a href="/guides/">Guides</a>
<a href="/">Home</a></main></body></html>"""
DOCS_MD = """# Docs

- [Install](https://docs.example.test/get-started/installation.md)
- [Deploy to the web](https://docs.example.test/deploy/web.md#export-your-web-project)
- [Guides](/guides/index.md)
- [Home](/index.md)
"""


def test_links_to_markdown_twins_cover_the_html_links():
    c = compare(html_facts(DOCS_HTML, DOCS_PAGE), markdown_facts(DOCS_MD, DOCS_PAGE))
    assert c["links"]["covered_pct"] == 100.0
    assert c["links"]["missing_examples"] == []



# Links that are not content a Markdown answer is expected to carry: the page
# itself, the site root, account pages, and "ask an AI about this page" buttons.
SCOPE_PAGE = "https://docs.example.test/guides/tv/"
# Ask-an-AI links are built from the module's own table, so the test names no
# third-party host and still covers every entry.
from scovant_core.representations import compare as _cmp_mod  # noqa: E402

_ASK_AI_LINKS = "".join(
    f'<a href="https://{host}{prefix.rstrip("/")}/x?q=Read%20this">ask</a>\n'
    for host, prefix in _cmp_mod._ASK_AI.items())
SCOPE_HTML = f"""<!doctype html><html><body><main><h1>TV</h1>
<a href="/">Docs home</a>
<a href="/guides/tv/">This page</a>
<a href="https://dashboard.example.test/login?redirect=x">Log in</a>
<a href="https://dashboard.example.test/register/billing">Sign up</a>
{_ASK_AI_LINKS}<a href="/guides/tv/remote">Remote control</a></main></body></html>"""


def test_self_root_account_and_ask_ai_links_are_out_of_scope():
    c = compare(html_facts(SCOPE_HTML, SCOPE_PAGE), markdown_facts("[Remote](/guides/tv/remote)", SCOPE_PAGE))
    assert c["links"]["base_n"] == 1
    assert c["links"]["covered_pct"] == 100.0


def test_a_content_link_is_still_required():
    c = compare(html_facts(SCOPE_HTML, SCOPE_PAGE), markdown_facts("# TV\n", SCOPE_PAGE))
    assert c["links"]["covered_pct"] == 0.0
    assert c["links"]["missing_examples"] == ["https://docs.example.test/guides/tv/remote"]


def test_ask_ai_host_without_a_prompt_is_an_ordinary_link():
    host = next(h for h, prefix in _cmp_mod._ASK_AI.items() if prefix == "/")
    html = f'<main><h1>x</h1><a href="https://{host}/">assistant</a></main>'
    c = compare(html_facts(html, SCOPE_PAGE), markdown_facts("# x\n", SCOPE_PAGE))
    assert c["links"]["base_n"] == 1


def test_the_canonical_self_link_still_counts_as_attribution():
    html = ('<html><head><link rel="canonical" href="https://docs.example.test/guides/tv/"></head>'
            '<body><main><h1>TV</h1></main></body></html>')
    c = compare(html_facts(html, SCOPE_PAGE),
                markdown_facts("# TV\n\n[source](https://docs.example.test/guides/tv/)", SCOPE_PAGE))
    assert c["attribution"] is True


def test_dollar_in_code_is_not_a_price():
    md = ("# Notes\n\nReplace with `[@$1](https://github.test/$1)`.\n\n"
          "```sh\nsed 's/x/$2/'\necho $1\n```\n")
    assert markdown_facts(md, PAGE)["prices"] == set()
    html = "<html><body><main><p>Use <code>$1</code></p><pre>echo $2</pre></main></body></html>"
    assert html_facts(html, PAGE)["prices"] == set()


def test_price_outside_code_still_counts():
    md = "# Widget\n\nOnly $89.99 today. Run `echo $1`.\n"
    assert markdown_facts(md, PAGE)["prices"] == {89.99}
    html = "<html><body><main><p>Only $89.99</p><code>$1</code></main></body></html>"
    assert html_facts(html, PAGE)["prices"] == {89.99}
