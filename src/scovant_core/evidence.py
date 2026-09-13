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

    def gathered(self, name: str) -> dict | None:
        """The evidence IF some already-executed check (or a gatherer it
        depended on) already triggered `name`'s gather — never triggers a
        NEW fetch itself. Unlike `get`/`try_get`, this distinguishes
        "genuinely not attempted this scan" (a narrowed `--include`/
        `--exclude` selection that never needed this evidence) from "was
        attempted and failed" — both return `None` here, but a caller that
        cares about the difference can still consult `self.errors`."""
        return self._data.get(name)
