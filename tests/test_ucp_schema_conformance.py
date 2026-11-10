"""The hand-written v2026 validator agrees with a real JSON Schema validator.

`jsonschema` is a dev dependency only: the parser itself never imports it.
Every `$ref` resolves from a LOCAL `referencing.Registry` built from the
vendored files and keyed by their own absolute `$id` — no retrieving resolver
exists here, so nothing can be fetched (and the offline guard would refuse it
anyway). `format` stays an annotation, as it is for a default 2020-12
validator, so the comparison is against exactly what the schemas assert.
"""
from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest

import scovant_core.parsers as parsers_pkg
from scovant_core.parsers.ucp import check_ucp_profile

jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")

VENDOR = Path(parsers_pkg.__file__).resolve().parent / "ucp_schemas" / "v2026-08-25"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ucp"


def _validator():
    registry = referencing.Registry()
    profile_id = None
    for path in sorted(VENDOR.rglob("*.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        registry = registry.with_resource(contents["$id"],
                                          referencing.Resource.from_contents(contents))
        if path.name == "profile.json" and path.parent == VENDOR:
            profile_id = contents["$id"]
    assert profile_id is not None
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
              "$ref": f"{profile_id}#/$defs/business_schema"}
    return jsonschema.Draft202012Validator(schema, registry=registry)


VALIDATOR = _validator()


def _agree(doc) -> None:
    ours = check_ucp_profile(json.dumps(doc), 200, "application/json")["v2026"]
    theirs = VALIDATOR.is_valid(doc)
    assert ours["valid"] is theirs, (json.dumps(doc)[:400], ours["validation_errors"])


def _fixture_docs():
    return sorted(p for p in FIXTURES.glob("*.json") if p.name != "legacy_expected.json")


@pytest.mark.parametrize("path", _fixture_docs(), ids=lambda p: p.stem)
def test_validator_agrees_with_jsonschema_on_fixtures(path):
    _agree(json.loads(path.read_text(encoding="utf-8")))


def test_the_positive_fixtures_are_schema_valid():
    """The doc-derived fixtures named as positives are valid per the vendored
    schema itself, not only per our validator."""
    for name in ("current_rest", "current_mcp", "current_a2a", "current_embedded",
                 "checkout_and_cart", "permalink", "overview_business",
                 "protocol_version_2026_01_23"):
        doc = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
        assert VALIDATOR.is_valid(doc), name


# ── seeded single-field mutations ─────────────────────────────────────────

_REPLACEMENTS = [
    None, True, False, 0, 1, -1, 1.5, "", "x", "REST", "rest", "mcp", "a2a", "embedded", "Rest",
    "2026-08-25", "2026-13-45", "0.1", "2026-08-25\n", "dev.ucp.shopping.checkout", "Dev.Ucp", "a",
    "https://example.com/x", [], [None], ["x"], [1], ["light"], ["blue"], {}, {"a": 1},
    {"kid": "k", "kty": "EC"}, {"kid": "k", "kty": "OKP", "crv": "Ed25519", "x": "q", "alg": "ES256"},
    {"type": "card"}, {"enum": [1, 1]}, {"enum": []}, {"const": 1}, {"required": ["a", "a"]},
    {"properties": {}}, {"anyOf": [{}]}, {"anyOf": []},
]
_NEW_KEYS = ["version", "transport", "endpoint", "schema", "spec", "config", "id", "extends",
             "keys", "signing_keys", "status", "map_order", "supported_versions",
             "available_instruments", "d", "kid", "kty", "crv", "alg", "delegate", "color_scheme",
             "Bad Key", "com.example.thing", "constraints", "anyOf", "properties", "required"]


def _paths(node, prefix=()):
    yield prefix
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _paths(value, (*prefix, key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _paths(value, (*prefix, i))


def _get(node, path):
    for part in path:
        node = node[part]
    return node


def _mutate(doc, rng: random.Random):
    doc = copy.deepcopy(doc)
    paths = [p for p in _paths(doc) if p]
    path = rng.choice(paths)
    parent = _get(doc, path[:-1])
    op = rng.choice(("replace", "delete", "add"))
    if op == "replace" or (op == "delete" and isinstance(parent, list) and len(parent) == 0):
        parent[path[-1]] = copy.deepcopy(rng.choice(_REPLACEMENTS))
    elif op == "delete":
        del parent[path[-1]]
    else:
        target = _get(doc, path)
        if isinstance(target, dict):
            target[rng.choice(_NEW_KEYS)] = copy.deepcopy(rng.choice(_REPLACEMENTS))
        elif isinstance(target, list):
            target.append(copy.deepcopy(rng.choice(_REPLACEMENTS)))
        else:
            parent[path[-1]] = copy.deepcopy(rng.choice(_REPLACEMENTS))
    return doc


def _seeds():
    rich = json.loads((FIXTURES / "overview_business.json").read_text(encoding="utf-8"))
    rest = json.loads((FIXTURES / "current_rest.json").read_text(encoding="utf-8"))
    return rest, rich


def test_validator_agrees_with_jsonschema():
    """200 seeded single-field mutations of `current_rest` (the brief's set)
    plus 800 more over the canonical overview profile, which reaches the JWK,
    payment-handler and constraint branches `current_rest` does not carry."""
    rest, rich = _seeds()
    rng = random.Random(20261109)
    for _ in range(200):
        _agree(_mutate(rest, rng))
    for _ in range(800):
        _agree(_mutate(rich, rng))


def _patched(base: str, mutate) -> dict:
    doc = json.loads((FIXTURES / f"{base}.json").read_text(encoding="utf-8"))
    mutate(doc)
    return doc


def _constraints(value):
    def mutate(doc):
        handler = doc["ucp"]["payment_handlers"]["com.example.processor_tokenizer"][0]
        handler["available_instruments"][0]["constraints"] = value
    return _patched("overview_business", mutate)


def _embedded_config(value):
    def mutate(doc):
        doc["ucp"]["services"]["dev.ucp.shopping"][0]["config"] = value
    return _patched("current_embedded", mutate)


def _ucp_field(key, value):
    def mutate(doc):
        doc["ucp"][key] = value
    return _patched("current_rest", mutate)


# Branches random single-field mutations rarely reach; each is a pair or more
# whose verdicts differ, so a validator that ignored the constraint would
# disagree with jsonschema on at least one of them.
_EDGES = [
    _constraints({"properties": {"brand": {"enum": ["visa", "visa"]}}}),
    _constraints({"properties": {"brand": {"enum": [1, 1.0]}}}),
    _constraints({"properties": {"brand": {"enum": [1, True]}}}),
    _constraints({"properties": {"brand": {"enum": [{"a": 1}, {"a": 1.0}]}}}),
    _constraints({"properties": {"brand": {"enum": [[1], [True]]}}}),
    _constraints({"properties": {"brand": {"const": None}}}),
    _constraints({"properties": {"brand": {"enum": ["a"], "const": "a"}}}),
    _constraints({"properties": {"brand": {"enum": ["a"], "x": 1}}}),
    _constraints({"properties": {"brand": {}}}),
    _constraints({"properties": {"brand": {"required": ["a"]}}}),
    _constraints({"properties": {"brand": {"required": ["a", "a"]}}}),
    _constraints({"properties": {}}),
    _constraints({"required": ["a", "b"], "anyOf": [{"required": ["a"]}, {}]}),
    _constraints({"anyOf": [{"properties": {"x": {"const": 1}}}]}),
    _constraints({"properties": {"a": {"properties": {"b": {"enum": [1, 2]}}}}}),
    _constraints({"properties": {"a": {"properties": {"b": {"enum": [2, 2]}}}}}),
    _embedded_config({"color_scheme": ["light", "dark"]}),
    _embedded_config({"color_scheme": ["blue"]}),
    _embedded_config({"color_scheme": "light"}),
    _embedded_config({"delegate": ["payment.credential"]}),
    _embedded_config({"delegate": [1]}),
    _embedded_config({"other": True}),
    _embedded_config([]),
    _ucp_field("supported_versions", {"2026-01-11": "https://business.example.com/p"}),
    _ucp_field("supported_versions", {"v1": "https://business.example.com/p"}),
    _ucp_field("supported_versions", {"2026-01-11": 1}),
    _ucp_field("supported_versions", []),
    _ucp_field("map_order", {"a": ["x"]}),
    _ucp_field("map_order", {"a": [1]}),
    _ucp_field("map_order", {"a": "x"}),
    _ucp_field("map_order", ["x"]),
    _ucp_field("status", "success"),
    _ucp_field("status", "ok"),
    _ucp_field("version", "2026-08-25\n"),
    _ucp_field("version", "\u0662\u0660\u0662\u0666-08-25"),
]


@pytest.mark.parametrize("doc", _EDGES, ids=range(len(_EDGES)))
def test_validator_agrees_on_targeted_edges(doc):
    _agree(doc)


def test_the_targeted_edges_reach_both_verdicts():
    verdicts = [VALIDATOR.is_valid(doc) for doc in _EDGES]
    assert verdicts.count(True) >= 10 and verdicts.count(False) >= 10


def test_the_mutations_reach_both_verdicts():
    rest, rich = _seeds()
    rng = random.Random(20261109)
    verdicts = [VALIDATOR.is_valid(_mutate(rest, rng)) for _ in range(200)]
    verdicts += [VALIDATOR.is_valid(_mutate(rich, rng)) for _ in range(800)]
    assert verdicts.count(True) >= 100 and verdicts.count(False) >= 100
