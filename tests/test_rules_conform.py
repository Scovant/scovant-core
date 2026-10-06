"""Evidence that contradicts `scovant_core.rules.evidence` is read as absent,
never raised on — for every registered rule, whoever calls it.

Two layers: `conform_page`/`conform_domain` follow the documented policy
(first part), and the registered rules survive every one-value mutation of
a full synthetic evidence document (second part), so a rule that reads a
field `evidence.py` does not document, or reads a documented field
carelessly, fails here before it fails inside a scan.
"""
from __future__ import annotations

import copy
import types
import typing
from typing import Any, Literal, Union

import pytest

import scovant_core.rules  # noqa: F401  (registers the rules)
from scovant_core.rules import evidence
from scovant_core.rules.base import RULES, MeasureCtx
from scovant_core.rules.conform import conform_domain, conform_page

# ---------------------------------------------------------------------------
# the policy
# ---------------------------------------------------------------------------

WELL_FORMED_DOMAIN = {
    "site_type": "commerce",
    "pages_scored": 3,
    "mcp": {"exists": True, "valid": True, "endpoints": ["https://example.com/mcp"],
            "interface": {"attempted": True, "ok": True, "tool_count": 1,
                          "tools": [{"name": "search", "description": "Search", "input_schema_keys": ["q"]}],
                          "response_headers": {"mcp-protocol-version": "2025-06-18"}}},
    "observed_by_host": {"anything": [1, 2]},   # undocumented: passes through untouched
}


def test_a_well_formed_document_is_unchanged_in_content():
    assert conform_domain(copy.deepcopy(WELL_FORMED_DOMAIN)) == WELL_FORMED_DOMAIN
    page = {"visible_text": "hi", "schema_org": [{"@type": "Product"}], "headings": [{"level": "h1", "text": "T"}],
            "extra_host_key": {"x": None}}
    assert conform_page(copy.deepcopy(page)) == page


def test_a_block_of_the_wrong_kind_is_dropped_only_undocumented_keys_pass_through():
    out = conform_domain({"mcp": "not-a-block", "webmcp": ["x"], "ucp": 7, "custom": "kept"})
    assert out == {"custom": "kept"}


def test_list_entries_and_mapping_entries_are_dropped_one_at_a_time():
    out = conform_domain({"mcp": {"interface": {"tools": [None, "str", {"name": "ok"}, 7],
                                                "server_info": {"name": "srv", "caps": {"nested": True}},
                                                "response_headers": {"h": "v", "bad": ["list"]}}}})
    interface = out["mcp"]["interface"]
    assert interface["tools"] == [{"name": "ok"}]
    assert interface["server_info"] == {"name": "srv"}          # the offending entry, not the mapping
    assert interface["response_headers"] == {"h": "v"}


def test_text_and_number_fields():
    out = conform_page({"visible_text": 7, "page_language": ["en"], "http_status": "200",
                        "semantic_signals": {"interactive_elements_count": None, "labeled_elements_count": 2}})
    assert out == {"semantic_signals": {"labeled_elements_count": 2}}


def test_none_is_kept_for_text_flags_blocks_and_lists_but_not_numbers():
    out = conform_page({"visible_text": None, "schema_org": None, "semantic_signals": None,
                        "content_blocks": None, "http_status": None})
    assert out == {"visible_text": None, "schema_org": None, "semantic_signals": None,
                   "content_blocks": None, "http_status": None}  # http_status is `int | None`
    assert conform_domain({"pages_scored": None, "sitemap": {"exists": None}}) == {"sitemap": {"exists": None}}


def test_flags_are_read_as_the_producer_wrote_them():
    assert conform_domain({"sitemap": {"exists": "yes", "valid": 1}}) == {"sitemap": {"exists": "yes", "valid": 1}}


def test_a_literal_outside_its_values_is_dropped():
    assert conform_domain({"sitemap": {"fetch_status": "weird", "exists": True}}) == {"sitemap": {"exists": True}}


def test_non_object_page_and_domain():
    assert conform_page("str") == {} and conform_page(None) == {}
    assert conform_domain(None) is None and conform_domain("str") is None and conform_domain([1]) is None


def test_the_same_object_is_conformed_once_and_a_new_object_afresh():
    domain = {"mcp": "bad", "site_type": "blog"}
    first = conform_domain(domain)
    assert conform_domain(domain) is first
    domain2 = dict(domain)
    assert conform_domain(domain2) is not first and conform_domain(domain2) == first


# ---------------------------------------------------------------------------
# every registered rule, every one-value mutation of a full document
# ---------------------------------------------------------------------------

PRODUCT = {"@type": "Product", "@id": "https://example.com/p#1", "name": "Widget", "productID": "W-1",
           "offers": [{"@type": "Offer", "price": "29.99", "priceCurrency": "USD",
                       "availability": "https://schema.org/InStock",
                       "shippingDetails": {"@type": "OfferShippingDetails"}}],
           "hasVariant": [{"@type": "Product", "name": "Widget Red"}]}


def _sample(annotation: Any, key: str = "") -> Any:
    """A plausible well-formed value for an evidence annotation."""
    if annotation is Any:
        return "any"
    origin = typing.get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        members = [m for m in typing.get_args(annotation) if m is not type(None)]
        return _sample(members[0], key)
    if origin is Literal:
        return typing.get_args(annotation)[0]
    if typing.is_typeddict(annotation):
        return {k: _sample(v, k) for k, v in typing.get_type_hints(annotation).items()}
    if origin is dict or annotation is dict:
        args = typing.get_args(annotation)
        return {"example": _sample(args[1], key)} if args else {"example": 1}
    if origin is list or annotation is list:
        args = typing.get_args(annotation)
        if key == "schema_org":
            return [copy.deepcopy(PRODUCT), {"@type": "WebPage"}]
        return [_sample(args[0], key), _sample(args[0], key)] if args else ["x"]
    if annotation is bool:
        return True
    if annotation is int:
        return 3
    if annotation is float:
        return 1.5
    if annotation is str:
        return {"intent": "agent", "level": "h1", "kind": "package_npm", "status": "VALID",
                "fetch_status": "ok"}.get(key, "https://example.com/x" if key.endswith("url") else "text")
    return None


def _full_page() -> dict:
    page = _sample(evidence.PageEvidence)
    page["visible_text"] = "word " * 60
    page["headings"] = [{"level": "h1", "text": "Title"}, {"level": "h3", "text": "Skipped"}]
    return page


def _full_domain() -> dict:
    domain = _sample(evidence.DomainEvidence)
    domain["site_type"] = "commerce"
    domain["pages_scored"] = 3
    domain["content_pages_scored"] = 3
    return domain


def test_the_synthetic_documents_are_well_formed():
    page, domain = _full_page(), _full_domain()
    assert conform_page(copy.deepcopy(page)) == page
    assert conform_domain(copy.deepcopy(domain)) == domain


REPLACEMENTS = [None, "str", 7, [], {}, ["x"], [None], [7], {"a": 1}]


def _paths(obj: Any, prefix: tuple = (), depth: int = 0) -> list[tuple]:
    out: list[tuple] = []
    if depth > 5:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(prefix + (k,))
            out.extend(_paths(v, prefix + (k,), depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:2]):
            out.append(prefix + (i,))
            out.extend(_paths(v, prefix + (i,), depth + 1))
    return out


def _with(obj: Any, path: tuple, value: Any) -> Any:
    out = copy.deepcopy(obj)
    cur = out
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return out


CATEGORIES = ("commerce", "blog", None)


def _run_every_rule(page: dict, domain: dict | None, where: str) -> None:
    for rule in RULES:
        for category in CATEGORIES:
            ctx = MeasureCtx(site_category=category, defaulted=frozenset())
            try:
                rule.evaluate(page, domain)
                rule.measure(page, domain, ctx)
            except Exception as exc:  # noqa: BLE001 — the point is that nothing is raised
                pytest.fail(f"{rule.code} raised {type(exc).__name__}: {exc} at {where}")


def test_every_rule_reads_the_full_well_formed_documents():
    _run_every_rule(_full_page(), _full_domain(), "well-formed")
    _run_every_rule(_full_page(), None, "no domain")
    _run_every_rule({}, {}, "empty")


def test_no_rule_raises_on_a_mutated_page():
    page, domain = _full_page(), _full_domain()
    for path in _paths(page):
        for value in REPLACEMENTS:
            _run_every_rule(_with(page, path, value), domain, f"page {path} := {value!r}")


def test_no_rule_raises_on_a_mutated_domain():
    page, domain = _full_page(), _full_domain()
    for path in _paths(domain):
        for value in REPLACEMENTS:
            _run_every_rule(page, _with(domain, path, value), f"domain {path} := {value!r}")


def test_no_rule_raises_on_published_json_ld_of_any_shape():
    # Beyond the schema: the entities themselves are the site's JSON-LD.
    page, domain = _full_page(), _full_domain()
    entities = [copy.deepcopy(PRODUCT), {"@type": "Product", "@id": ["x"], "name": {"a": 1}, "offers": "29.99",
                                         "productID": ["p"], "hasVariant": "Red"},
                {"@type": "Product", "offers": [None, "x", {"price": None}, {"price": {"amount": 1}}]},
                {"@type": ["Product", "Thing"], "offers": {"price": ["1"], "priceCurrency": 7}},
                {"@graph": 5}, {"@graph": {"@type": "Product"}}, "not-an-entity", None, 7]
    _run_every_rule({**page, "schema_org": entities}, domain, "json-ld shapes")
    _run_every_rule({**page, "schema_org": [{"@type": "Product"}] * 3}, domain, "duplicate bare products")
