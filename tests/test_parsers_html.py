"""Tests for the HTML parsers (scovant_core.parsers.html)."""
from pathlib import Path

import pytest

from scovant_core.parsers.html import (
    extract_headings,
    extract_metadata,
    extract_og_meta,
    extract_policy_links,
    extract_product_data,
    extract_schema_org,
    extract_semantic_signals,
    extract_visible_text,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "html"


@pytest.fixture
def product_html() -> str:
    return (FIXTURES / "product_page.html").read_text()


@pytest.fixture
def spa_html() -> str:
    return (FIXTURES / "spa_shell.html").read_text()


@pytest.fixture
def blog_html() -> str:
    return (FIXTURES / "blog_page.html").read_text()


# ---------------------------------------------------------------------------
# extract_metadata
# ---------------------------------------------------------------------------

class TestExtractMetadata:
    def test_returns_title(self, product_html):
        result = extract_metadata(product_html)
        assert result["title"] == "Blue Running Shoes - AcmeShop"

    def test_returns_meta_description(self, product_html):
        result = extract_metadata(product_html)
        assert "Blue Running Shoes" in result["meta_description"]

    def test_returns_canonical_url(self, product_html):
        result = extract_metadata(product_html)
        assert result["canonical_url"] == "https://example.com/products/blue-running-shoes"

    def test_returns_robots_meta(self, product_html):
        result = extract_metadata(product_html)
        assert result["robots_meta"] == "index, follow"

    def test_missing_canonical_returns_none(self, spa_html):
        result = extract_metadata(spa_html)
        assert result["canonical_url"] is None

    def test_missing_description_returns_none(self, spa_html):
        result = extract_metadata(spa_html)
        assert result["meta_description"] is None or result["meta_description"] == ""

    def test_noindex_robots(self, spa_html):
        result = extract_metadata(spa_html)
        assert result["robots_meta"] == "noindex"


# ---------------------------------------------------------------------------
# extract_headings
# ---------------------------------------------------------------------------

class TestExtractHeadings:
    def test_returns_h1(self, product_html):
        headings = extract_headings(product_html)
        h1s = [h for h in headings if h["level"] == "h1"]
        assert len(h1s) == 1
        assert h1s[0]["text"] == "Blue Running Shoes"

    def test_returns_multiple_h2(self, product_html):
        headings = extract_headings(product_html)
        h2s = [h for h in headings if h["level"] == "h2"]
        assert len(h2s) >= 2

    def test_preserves_order(self, blog_html):
        headings = extract_headings(blog_html)
        levels = [h["level"] for h in headings]
        # h1 comes first
        assert levels[0] == "h1"

    def test_includes_h3(self, blog_html):
        headings = extract_headings(blog_html)
        h3s = [h for h in headings if h["level"] == "h3"]
        assert len(h3s) >= 1
        assert h3s[0]["text"] == "Advanced Breathing Techniques"

    def test_empty_page_returns_empty_list(self, spa_html):
        headings = extract_headings(spa_html)
        assert headings == []


# ---------------------------------------------------------------------------
# extract_schema_org
# ---------------------------------------------------------------------------

class TestExtractSchemaOrg:
    def test_returns_list(self, product_html):
        result = extract_schema_org(product_html)
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_parses_product_type(self, product_html):
        result = extract_schema_org(product_html)
        types = [item.get("@type") for item in result]
        assert "Product" in types

    def test_product_has_name(self, product_html):
        result = extract_schema_org(product_html)
        product = next(item for item in result if item.get("@type") == "Product")
        assert product["name"] == "Blue Running Shoes"

    def test_product_has_nested_offer(self, product_html):
        result = extract_schema_org(product_html)
        product = next(item for item in result if item.get("@type") == "Product")
        assert "offers" in product
        offers = product["offers"]
        # offers may be a dict or list; normalise to dict
        if isinstance(offers, list):
            offers = offers[0]
        assert offers.get("price") == "89.99"
        assert offers.get("priceCurrency") == "USD"

    def test_offer_availability_present(self, product_html):
        result = extract_schema_org(product_html)
        product = next(item for item in result if item.get("@type") == "Product")
        offers = product["offers"]
        if isinstance(offers, list):
            offers = offers[0]
        assert "availability" in offers

    def test_article_parsed_from_blog(self, blog_html):
        result = extract_schema_org(blog_html)
        types = [item.get("@type") for item in result]
        assert "Article" in types

    def test_returns_empty_list_for_spa(self, spa_html):
        result = extract_schema_org(spa_html)
        # WebSite is valid JSON-LD, should still parse
        assert isinstance(result, list)

    def test_no_bs4_parser_warnings(self, product_html, recwarn):
        extract_schema_org(product_html)
        bs4_warnings = [w for w in recwarn.list if "MarkupResemblesLocatorWarning" in str(w.category)]
        assert bs4_warnings == []


# ---------------------------------------------------------------------------
# extract_og_meta
# ---------------------------------------------------------------------------

class TestExtractOgMeta:
    def test_og_title(self, product_html):
        result = extract_og_meta(product_html)
        assert result["og_title"] == "Blue Running Shoes - AcmeShop"

    def test_og_description(self, product_html):
        result = extract_og_meta(product_html)
        assert result["og_description"] == "Premium running shoes for all terrains."

    def test_og_image(self, product_html):
        result = extract_og_meta(product_html)
        assert result["og_image"] == "https://example.com/images/blue-shoes.jpg"

    def test_og_url(self, product_html):
        result = extract_og_meta(product_html)
        assert result["og_url"] == "https://example.com/products/blue-running-shoes"

    def test_all_four_fields_present(self, product_html):
        result = extract_og_meta(product_html)
        assert all(k in result for k in ("og_title", "og_description", "og_image", "og_url"))

    def test_missing_og_returns_none_values(self, spa_html):
        result = extract_og_meta(spa_html)
        assert result["og_title"] is None
        assert result["og_image"] is None


# ---------------------------------------------------------------------------
# extract_visible_text
# ---------------------------------------------------------------------------

class TestExtractVisibleText:
    def test_contains_product_name(self, product_html):
        text = extract_visible_text(product_html)
        assert "Blue Running Shoes" in text

    def test_excludes_script_content(self, product_html):
        text = extract_visible_text(product_html)
        assert "should not appear in visible text" not in text
        assert "console.log" not in text

    def test_excludes_style_content(self, product_html):
        text = extract_visible_text(product_html)
        assert "font-family" not in text

    def test_excludes_nav_content(self, product_html):
        # Nav links text should not dominate — main content should be present
        text = extract_visible_text(product_html)
        assert "Products" not in text or "Running Shoes" in text  # main content present

    def test_excludes_footer_content(self, product_html):
        text = extract_visible_text(product_html)
        assert "2024 AcmeShop" not in text

    def test_max_5000_chars(self, product_html):
        text = extract_visible_text(product_html)
        assert len(text) <= 5000

    def test_returns_string(self, product_html):
        text = extract_visible_text(product_html)
        assert isinstance(text, str)


# ---------------------------------------------------------------------------
# extract_policy_links
# ---------------------------------------------------------------------------

class TestExtractPolicyLinks:
    def test_returns_returns_policy_url(self, product_html):
        result = extract_policy_links(product_html, "https://example.com")
        assert result["returns_policy_url"] is not None
        assert "returns" in result["returns_policy_url"].lower() or "return" in result["returns_policy_url"].lower()

    def test_returns_shipping_policy_url(self, product_html):
        result = extract_policy_links(product_html, "https://example.com")
        assert result["shipping_policy_url"] is not None
        assert "shipping" in result["shipping_policy_url"].lower()

    def test_returns_privacy_policy_url(self, product_html):
        result = extract_policy_links(product_html, "https://example.com")
        assert result["privacy_policy_url"] is not None
        assert "privacy" in result["privacy_policy_url"].lower()

    def test_returns_terms_url(self, product_html):
        result = extract_policy_links(product_html, "https://example.com")
        assert result["terms_url"] is not None

    def test_resolves_relative_urls(self, product_html):
        result = extract_policy_links(product_html, "https://example.com")
        for key, url in result.items():
            if url is not None:
                assert url.startswith("http"), f"{key} should be absolute URL, got {url}"

    def test_missing_policies_return_none(self, spa_html):
        result = extract_policy_links(spa_html, "https://example.com")
        assert result["returns_policy_url"] is None
        assert result["shipping_policy_url"] is None

    def test_all_keys_present(self, product_html):
        result = extract_policy_links(product_html, "https://example.com")
        assert all(k in result for k in ("returns_policy_url", "shipping_policy_url", "privacy_policy_url", "terms_url"))


# ---------------------------------------------------------------------------
# extract_product_data
# ---------------------------------------------------------------------------

class TestExtractProductData:
    def test_returns_product_name(self, product_html):
        schema = extract_schema_org(product_html)
        result = extract_product_data(schema)
        assert result is not None
        assert result["product_name"] == "Blue Running Shoes"

    def test_returns_price(self, product_html):
        schema = extract_schema_org(product_html)
        result = extract_product_data(schema)
        assert result["price"] == "89.99"

    def test_returns_currency(self, product_html):
        schema = extract_schema_org(product_html)
        result = extract_product_data(schema)
        assert result["currency"] == "USD"

    def test_returns_availability(self, product_html):
        schema = extract_schema_org(product_html)
        result = extract_product_data(schema)
        assert result["availability"] is not None
        assert "InStock" in result["availability"]

    def test_returns_offers_list(self, product_html):
        schema = extract_schema_org(product_html)
        result = extract_product_data(schema)
        assert "offers" in result
        assert isinstance(result["offers"], list)

    def test_returns_variants_key(self, product_html):
        schema = extract_schema_org(product_html)
        result = extract_product_data(schema)
        assert "variants" in result

    def test_returns_none_for_non_product(self, blog_html):
        schema = extract_schema_org(blog_html)
        result = extract_product_data(schema)
        assert result is None

    def test_returns_none_for_empty_schema(self):
        result = extract_product_data([])
        assert result is None


# ---------------------------------------------------------------------------
# extract_semantic_signals
# ---------------------------------------------------------------------------

class TestExtractSemanticSignals:
    def test_detects_aria_labels(self, product_html):
        result = extract_semantic_signals(product_html)
        assert result["has_aria_labels"] is True

    def test_counts_interactive_elements(self, product_html):
        result = extract_semantic_signals(product_html)
        # select, button, input in product page
        assert result["interactive_elements_count"] >= 3

    def test_counts_labeled_elements(self, product_html):
        result = extract_semantic_signals(product_html)
        # select, button, input all have aria-label
        assert result["labeled_elements_count"] >= 3

    def test_detects_add_to_cart(self, product_html):
        result = extract_semantic_signals(product_html)
        assert result["add_to_cart_found"] is True

    def test_no_add_to_cart_in_blog(self, blog_html):
        result = extract_semantic_signals(blog_html)
        assert result["add_to_cart_found"] is False

    def test_detects_signup_cta(self, blog_html):
        result = extract_semantic_signals(blog_html)
        assert result["signup_cta_found"] is True

    def test_no_signup_in_product(self, product_html):
        result = extract_semantic_signals(product_html)
        assert result["signup_cta_found"] is False

    def test_all_keys_present(self, product_html):
        result = extract_semantic_signals(product_html)
        assert all(k in result for k in (
            "has_aria_labels", "interactive_elements_count",
            "labeled_elements_count", "add_to_cart_found", "signup_cta_found"
        ))

    def test_spa_has_no_aria_labels(self, spa_html):
        result = extract_semantic_signals(spa_html)
        assert result["has_aria_labels"] is False
        assert result["interactive_elements_count"] == 0
