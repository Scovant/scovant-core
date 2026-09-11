"""Evidence store: each gatherer runs at most once per scan; failures are
recorded, never re-raised into checks (a check reads them as ERROR)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from scovant_core.context import ScanContext
from scovant_core.security.client import SecureClient

Gatherer = Callable[[SecureClient, ScanContext, "EvidenceStore"], dict]
GATHERERS: dict[str, Gatherer] = {}


def register_gatherer(name: str):
    def deco(fn: Gatherer) -> Gatherer:
        GATHERERS[name] = fn
        return fn
    return deco


@dataclass(frozen=True)
class GatherError:
    name: str
    kind: str
    message: str


class EvidenceUnavailable(Exception):
    def __init__(self, err: GatherError):
        super().__init__(f"{err.name}: {err.kind}: {err.message}")
        self.err = err


class EvidenceStore:
    def __init__(self, client: SecureClient, ctx: ScanContext):
        self.client, self.ctx = client, ctx
        self._data: dict[str, dict] = {}
        self.errors: dict[str, GatherError] = {}

    def get(self, name: str) -> dict:
        if name in self._data:
            return self._data[name]
        if name in self.errors:
            raise EvidenceUnavailable(self.errors[name])
        fn = GATHERERS[name]  # KeyError = programming error, surfaces loudly
        try:
            self._data[name] = fn(self.client, self.ctx, self)
        except Exception as exc:  # noqa: BLE001 — degrade to ERROR, never abort the scan
            self.errors[name] = GatherError(name, type(exc).__name__, str(exc)[:300])
            raise EvidenceUnavailable(self.errors[name]) from exc
        return self._data[name]

    def try_get(self, name: str) -> dict | None:
        try:
            return self.get(name)
        except EvidenceUnavailable:
            return None
