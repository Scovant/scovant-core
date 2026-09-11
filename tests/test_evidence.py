import pytest

from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import GATHERERS, EvidenceStore, EvidenceUnavailable, register_gatherer
from tests.conftest import make_client


def test_gatherer_runs_once_and_is_memoised(monkeypatch):
    calls = []

    @register_gatherer("_probe_once")
    def g(client, ctx, store):
        calls.append(1)
        return {"ok": True}

    store = EvidenceStore(make_client(lambda r: None), ScanContext("https://example.com", ScanOptions()))
    assert store.get("_probe_once") == {"ok": True}
    assert store.get("_probe_once") == {"ok": True}
    assert calls == [1]
    GATHERERS.pop("_probe_once")


def test_gatherer_exception_becomes_evidence_unavailable():
    @register_gatherer("_boom")
    def g(client, ctx, store):
        raise ValueError("bad xml")

    store = EvidenceStore(make_client(lambda r: None), ScanContext("https://example.com", ScanOptions()))
    with pytest.raises(EvidenceUnavailable) as ei:
        store.get("_boom")
    assert store.errors["_boom"].kind == "ValueError" and "bad xml" in str(ei.value)
    assert store.try_get("_boom") is None
    GATHERERS.pop("_boom")


def test_unknown_gatherer_is_a_programming_error():
    store = EvidenceStore(make_client(lambda r: None), ScanContext("https://example.com", ScanOptions()))
    with pytest.raises(KeyError):
        store.get("nope")
