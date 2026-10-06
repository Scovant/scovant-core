"""Read evidence as `scovant_core.rules.evidence` documents it.

A rule reads JSON a producer wrote — Scovant Cloud's crawler, Core's own
gatherers, or a third-party host — and page evidence carries JSON-LD a site
published. A value that contradicts the documented shape (a string where a
block is expected, a tool entry that is not an object, a text field holding
a list) must never raise inside a rule: it is read as ABSENT. That is the
one policy here, applied at the finest grain the documentation allows,
and only where the wrong shape could make a rule raise — a value that
merely reads as true or false is left alone:

- `None` is read as written in a text, flag, block, list or mapping field
  (producers write it for "nothing extracted", and a rule reads such a
  block as measured-and-empty, which a dropped key would not say); a
  number field holding `None`, and a `None` entry in a list, are dropped;
- a documented block, list or mapping whose value is some other kind of
  thing is dropped (the rule then takes its own "missing" path —
  NOT_MEASURED, N/A or no finding);
- in a list, only the entries that do not fit are dropped; in a mapping
  with documented values, only the offending entries (a `None` entry in
  either is dropped);
- a text field holding a non-string, or a number field holding a
  non-number, is dropped; a flag field is never touched;
- keys the documentation does not name pass through untouched (a host may
  carry more than Core reads);
- a well-formed document is returned unchanged in content.

`register_rule` wraps every rule's `evaluate` and `measure` with
`conform_page`/`conform_domain`, so a rule never sees evidence that
contradicts `evidence.py` whoever calls it. The conformed copy of the last
few page/domain objects is remembered by identity, so a host that hands
the same objects to every rule pays one pass per page; the one thing a
host must not do is mutate a page or domain object between rule calls —
build a new object instead (Scovant Cloud enriches `domain_data` before
the first rule runs and never afterwards).
"""
from __future__ import annotations

import functools
import threading
import types
import typing
from collections import OrderedDict
from typing import Any, Literal, Union

from scovant_core.rules import evidence

_MISSING = object()


@functools.cache
def _hints(td: type) -> dict[str, Any]:
    return typing.get_type_hints(td)


def conform(value: Any, annotation: Any) -> Any:
    """Return `value` conformed to `annotation`, or `_MISSING` when its shape
    cannot be read as the annotation at all."""
    if annotation is Any:
        return value
    origin = typing.get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        for member in typing.get_args(annotation):
            if member is type(None):
                if value is None:
                    return None
                continue
            got = conform(value, member)
            if got is not _MISSING:
                return got
        return _MISSING
    if value is None:
        return _MISSING if annotation in (int, float) else None
    if origin is Literal:
        return value if value in typing.get_args(annotation) else _MISSING
    if typing.is_typeddict(annotation):
        if not isinstance(value, dict):
            return _MISSING
        return _conform_mapping(value, _hints(annotation))
    if origin is dict or annotation is dict:
        if not isinstance(value, dict):
            return _MISSING
        args = typing.get_args(annotation)
        if not args or args[1] is Any:
            return value
        entries: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str) or v is None:
                continue
            got = conform(v, args[1])
            if got is not _MISSING:
                entries[k] = got
        return entries
    if origin is list or annotation is list:
        if not isinstance(value, list):
            return _MISSING
        args = typing.get_args(annotation)
        if not args or args[0] is Any:
            return value
        items: list[Any] = []
        for item in value:
            got = conform(item, args[0]) if item is not None else _MISSING
            if got is not _MISSING:
                items.append(got)
        return items
    if annotation is bool:
        return value  # truthiness never raises; read as the producer wrote it
    if annotation is int or annotation is float:
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else _MISSING
    if annotation is str:
        return value if isinstance(value, str) else _MISSING
    if annotation is type(None):
        return _MISSING  # a non-None value where only None is documented
    return value  # an annotation this reader does not know: pass through


def _conform_mapping(value: dict, hints: dict[str, Any]) -> dict:
    out = {}
    for k, v in value.items():
        annotation = hints.get(k) if isinstance(k, str) else None
        if annotation is None:
            out[k] = v
            continue
        got = conform(v, annotation)
        if got is not _MISSING:
            out[k] = got
    return out


# A host hands the SAME page and domain objects to every rule in turn, so
# the conformed copy is remembered for the last few objects seen (by
# identity, with the original kept alive so its id cannot be reused).
_CACHE_SIZE = 8
_cache: OrderedDict[tuple[str, int], tuple[Any, Any]] = OrderedDict()
_cache_lock = threading.Lock()


def _remembered(kind: str, obj: Any, build) -> Any:
    key = (kind, id(obj))
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None and hit[0] is obj:
            return hit[1]
    result = build(obj)
    with _cache_lock:
        _cache[key] = (obj, result)
        while len(_cache) > _CACHE_SIZE:
            _cache.popitem(last=False)
    return result


def conform_page(page: Any) -> dict:
    """The page evidence as `PageEvidence` documents it; a non-object page
    reads as an empty page."""
    if not isinstance(page, dict):
        return {}
    return _remembered("page", page, lambda p: _conform_mapping(p, _hints(evidence.PageEvidence)))


def conform_domain(domain: Any) -> dict | None:
    """The domain evidence as `DomainEvidence` documents it; None stays None
    (no domain evidence) and any other non-object reads as None."""
    if domain is None:
        return None
    if not isinstance(domain, dict):
        return None
    return _remembered("domain", domain,
                       lambda d: _conform_mapping(d, _hints(evidence.DomainEvidence)))
