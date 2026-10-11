"""Bundled o200k_base tokenizer (optional `[tokens]` extra): counts are
reproducible, the encoding is built from the packaged BPE file, and nothing
is ever downloaded at runtime."""
from __future__ import annotations

import builtins
import hashlib
import importlib.resources as ir
import socket
import sys

import pytest

from scovant_core.analysis import token_cost as tc

HTML = (
    "<html><body><h1>Blue Widget</h1><p>Buy the widget today.</p>"
    '<a href="/cart">Add to cart</a><button>Checkout</button>'
    '<label>Email</label><input placeholder="you@example.com"></body></html>'
)
HEADINGS = [{"level": 1, "text": "Blue Widget"}]
TEXT = "Blue Widget Buy the widget today. Add to cart Checkout Email"


def test_bundled_bpe_file_matches_the_published_hash():
    path = ir.files("scovant_core.analysis") / "data" / "o200k_base.tiktoken"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"


def test_counts_on_a_fixed_snippet():
    pytest.importorskip("tiktoken")
    assert tc.tokenizer_available() is True
    assert tc.page_token_cost(TEXT, HEADINGS, HTML) == {"total": 26, "text": 12, "skeleton": 14}


def test_empty_inputs_cost_zero():
    pytest.importorskip("tiktoken")
    assert tc.page_token_cost("", [], "") == {"total": 0, "text": 0, "skeleton": 0}


@pytest.fixture(autouse=True)
def _reset_encoder_cache():
    """No test leaves a cached None (tiktoken blocked) behind for the next module."""
    yield
    tc._encoder.cache_clear()


def _block_tiktoken(monkeypatch):
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "tiktoken" or name.startswith("tiktoken."):
            raise ImportError("blocked")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    for m in [m for m in sys.modules if m == "tiktoken" or m.startswith("tiktoken.")]:
        monkeypatch.delitem(sys.modules, m)
    tc._encoder.cache_clear()


def test_without_tiktoken_the_cost_is_none_and_nothing_hits_the_network(monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    _block_tiktoken(monkeypatch)
    assert tc.tokenizer_available() is False
    assert tc.page_token_cost(TEXT, HEADINGS, HTML) is None


def test_encoder_never_downloads(monkeypatch):
    pytest.importorskip("tiktoken")

    def no_network(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    tc._encoder.cache_clear()
    try:
        assert tc.page_token_cost(TEXT, HEADINGS, HTML)["total"] > 0
    finally:
        tc._encoder.cache_clear()


def test_adapter_fills_token_cost_per_page_only_when_available(monkeypatch):
    from scovant_core.r2 import adapter

    page = {"url": "https://example.com/", "status": 200, "html": HTML, "bot_protection": None,
            "parsed": {"visible_text": TEXT, "headings": HEADINGS}}

    class Store:
        def try_get(self, key):
            return {"pages": [page]} if key == "pages" else None

    monkeypatch.setattr(adapter, "page_token_cost", lambda *a: {"total": 3, "text": 1, "skeleton": 2})
    ev = adapter.evidence_from_store(Store(), site_type="commerce")
    assert ev.pages[0]["token_cost"] == {"total": 3, "text": 1, "skeleton": 2}
    monkeypatch.setattr(adapter, "page_token_cost", lambda *a: None)
    ev = adapter.evidence_from_store(Store(), site_type="commerce")
    assert "token_cost" not in ev.pages[0]


def test_reason_is_tokenizer_unavailable_only_when_missing(monkeypatch):
    from scovant_core.r2 import readiness

    class Outcome:
        reason = "predicate"
        rule_id = "PAGE_TOKEN_BLOAT"

    monkeypatch.setattr(readiness, "tokenizer_available", lambda: False)
    assert readiness._reason(Outcome(), frozenset()) == "tokenizer_unavailable"
    monkeypatch.setattr(readiness, "tokenizer_available", lambda: True)
    assert readiness._reason(Outcome(), frozenset()) == "not_measured"
