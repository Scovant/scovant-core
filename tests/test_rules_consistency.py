"""Rules published in Core: structured data that disagrees with itself or
with the page (page-scoped)."""
from scovant_core.r2 import OutcomeState
from scovant_core.rules import RULES, MeasureCtx

SHOP = MeasureCtx(site_category="commerce", defaulted=frozenset())
BLOG = MeasureCtx(site_category="blog", defaulted=frozenset())
NA, NM = OutcomeState.NA, OutcomeState.NOT_MEASURED


def _rule(code):
    return next(r for r in RULES if r.code == code)


def _product(price=None, **extra):
    product = {"@type": "Product", **extra}
    if price is not None:
        product["offers"] = {"@type": "Offer", "price": price}
    return product


def test_contract():
    got = {r.code: (r.category, r.severity, r.maturity, r.scope) for r in RULES}
    assert got["PRICE_MISMATCH"] == ("consistency", "high", "required", "page")
    assert got["INCONSISTENT_STRUCTURED_DATA"] == ("consistency", "medium", "required", "page")
    assert got["DUPLICATE_CONFLICTING_ENTITIES"] == ("consistency", "medium", "required", "page")


def test_price_mismatch():
    r = _rule("PRICE_MISMATCH")
    page = {"schema_org": [_product("49.00")], "visible_text": "Now $39.00"}
    f, = r.evaluate(page, None)
    assert f.description == "Visible price ($39.00) differs from schema.org Offer.price (49.00)."
    assert f.metadata == {"visible_price": "39.00", "structured_price": "49.00"}
    assert r.evaluate({"schema_org": [_product(39)], "visible_text": "Now $39.00"}, None) == []
    assert r.evaluate({"schema_org": [_product("39.00")], "visible_text": "Now €39.00"}, None) == []
    assert r.evaluate({"schema_org": [_product()], "visible_text": "Now $39.00"}, None) == []


def test_price_mismatch_reads_only_the_first_dollar_number():
    """A thousands separator ends the visible price: "$1,299.00" reads as 1,
    which differs from 1299.00 — the rule's long-standing reading."""
    r = _rule("PRICE_MISMATCH")
    f, = r.evaluate({"schema_org": [_product("1299.00")], "visible_text": "Only $1,299.00"}, None)
    assert f.metadata == {"visible_price": "1", "structured_price": "1299.00"}


def test_price_mismatch_measure():
    r = _rule("PRICE_MISMATCH")
    comparable = {"schema_org": [_product("49.00")], "visible_text": "$39"}
    assert r.measure(comparable, None, SHOP) is None
    assert r.measure({**comparable, "visible_text": "no price"}, None, SHOP) is NA
    assert r.measure({**comparable, "schema_org": [_product("free")]}, None, SHOP) is NA
    assert r.measure({"schema_org": []}, None, SHOP) is NM
    assert r.measure(comparable, None, BLOG) is NA


def test_inconsistent_structured_data():
    r = _rule("INCONSISTENT_STRUCTURED_DATA")
    f, = r.evaluate({"schema_org": [_product("10"), _product("12")]}, None)
    assert f.description == "Multiple JSON-LD Product blocks have conflicting prices."
    assert r.evaluate({"schema_org": [_product("10"), _product("10.0")]}, None) == []
    assert r.evaluate({"schema_org": [_product("10"), _product()]}, None) == []
    assert r.measure({"schema_org": [_product(), _product()]}, None, BLOG) is None    # not gated
    assert r.measure({"schema_org": [_product()]}, None, SHOP) is NA
    assert r.measure({}, None, SHOP) is NM


def test_duplicate_conflicting_entities():
    r = _rule("DUPLICATE_CONFLICTING_ENTITIES")
    f, = r.evaluate({"schema_org": [_product(name="A"), _product(name="B")]}, None)
    assert f.title == "Duplicate conflicting Product entities"
    ids = [_product(name="A", **{"@id": "https://example.com/a"}),
           _product(name="A", **{"@id": "https://example.com/b"})]
    assert len(r.evaluate({"schema_org": ids}, None)) == 1
    assert r.evaluate({"schema_org": [_product(name="A"), _product(name="A")]}, None) == []
    assert r.measure({"schema_org": [_product(), _product()]}, None, SHOP) is None
    assert r.measure({}, None, SHOP) is NM
