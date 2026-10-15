"""Capability flags: which gated rules apply to a site.

Three tri-state flags. Evidence on the sampled pages or the domain can only
set a flag to True — a scan reads a sample, so seeing nothing is not evidence
of absence. Otherwise the published default for the site type applies;
other, unknown and unlisted types have no default (None = not established).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from scovant_core.r2.outcome import OutcomeState

FLAGS: tuple[str, ...] = ("product_catalog", "physical_goods", "transactional_checkout")

CODE_FLAG: dict[str, str] = {
    "MISSING_PRODUCT_SCHEMA": "product_catalog", "MISSING_OFFER_DATA": "product_catalog",
    "PRICE_MISSING_INVALID": "product_catalog", "MISSING_AVAILABILITY": "product_catalog",
    "VARIANT_INFO_MISSING": "product_catalog", "PRICE_MISMATCH": "product_catalog",
    "SHIPPING_INFO_UNAVAILABLE": "physical_goods", "MISSING_RETURNS_POLICY": "physical_goods",
    "UCP_CHECKOUT_MISSING": "transactional_checkout", "AGENT_PAYMENTS_ABSENT": "transactional_checkout",
}

_NON_TX = (False, False, False)
# (product_catalog, physical_goods, transactional_checkout); absent type = all None.
TYPE_DEFAULTS: dict[str, tuple[bool | None, bool | None, bool | None]] = {
    "commerce": (True, True, True),
    "booking": (False, False, True), "restaurant": (False, False, True),
    "saas": (False, False, None),
    **{t: _NON_TX for t in ("blog", "news", "docs", "documentation", "media",
                             "portfolio", "education", "real_estate")},
}
_EVIDENCE_CAP = 3
# Site types where an add-to-cart / "buy now" control is not catalog evidence:
# on a SaaS site it sells a licence or a subscription (SoftwareApplication, not
# Product), so only Product/Offer data establishes a catalog there (0.20.1).
CTA_NOT_CATALOG_TYPES: frozenset[str] = frozenset({"saas"})


@dataclass(frozen=True)
class Capability:
    value: bool | None
    source: str  # "evidence" | "type_default" | "unknown"
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Capabilities:
    product_catalog: Capability
    physical_goods: Capability
    transactional_checkout: Capability

    def to_dict(self) -> dict[str, dict]:
        return {f: {"value": c.value, "source": c.source, "evidence": list(c.evidence)}
                for f in FLAGS for c in (getattr(self, f),)}

    @classmethod
    def from_dict(cls, d: dict | None) -> Capabilities | None:
        if not isinstance(d, dict) or not all(isinstance(d.get(f), dict) for f in FLAGS):
            return None
        return cls(**{f: Capability(d[f].get("value"), d[f].get("source", "unknown"),
                                    tuple(d[f].get("evidence") or ())) for f in FLAGS})


def _offer_or_price(pd: object) -> bool:
    return isinstance(pd, dict) and bool(pd.get("price") or pd.get("offers"))


def _schema_has_shipping(schema: object) -> bool:
    def walk(node: object) -> bool:
        if isinstance(node, dict):
            if node.get("@type") == "OfferShippingDetails" or "shippingDetails" in node \
                    or "hasMerchantReturnPolicy" in node:
                return True
            return any(walk(v) for v in node.values())
        if isinstance(node, list):
            return any(walk(v) for v in node)
        return False
    return walk(schema)


def _page_evidence(pages: Sequence[dict]) -> dict[str, list[str]]:
    ev: dict[str, list[str]] = {f: [] for f in FLAGS}
    for i, page in enumerate(pages):
        if not isinstance(page, dict) or page.get("content_blocked") is True:
            continue
        ref = str(page.get("url") or f"page[{i}]")
        if _offer_or_price(page.get("product_data")):
            ev["product_catalog"].append(f"product_offer:{ref}")
        elif (page.get("semantic_signals") or {}).get("add_to_cart_found") is True:
            ev["product_catalog"].append(f"add_to_cart:{ref}")
        if _schema_has_shipping(page.get("schema_org")):
            ev["physical_goods"].append(f"shipping_schema:{ref}")
    return ev


def derive_capabilities(site_type: str | None, pages: Sequence[dict], domain: dict | None) -> Capabilities:
    ev = _page_evidence(pages or [])
    if (site_type or "") in CTA_NOT_CATALOG_TYPES:
        ev["product_catalog"] = [e for e in ev["product_catalog"] if not e.startswith("add_to_cart:")]
    dom = domain if isinstance(domain, dict) else {}
    if (dom.get("ucp") or {}).get("has_checkout") is True:
        ev["transactional_checkout"].append("ucp:has_checkout")
    if (dom.get("agent_payments") or {}).get("any_non_ucp") is True:
        ev["transactional_checkout"].append("agent_payments:any_non_ucp")
    defaults = TYPE_DEFAULTS.get(site_type or "")
    out: dict[str, Capability] = {}
    for idx, flag in enumerate(FLAGS):
        if ev[flag]:
            out[flag] = Capability(True, "evidence", tuple(ev[flag][:_EVIDENCE_CAP]))
        elif defaults is not None and defaults[idx] is not None:
            out[flag] = Capability(defaults[idx], "type_default")
        else:
            out[flag] = Capability(None, "unknown")
    return Capabilities(**out)


def gate(code: str, caps: Capabilities | None) -> tuple[OutcomeState, str] | None:
    """(N/A, reason) when `code` is gated and its flag is not True; else None.
    No capabilities (a caller that did not derive them) gates nothing."""
    flag = CODE_FLAG.get(code)
    if flag is None or caps is None:
        return None
    value = getattr(caps, flag).value
    if value is True:
        return None
    return OutcomeState.NA, (f"capability_absent:{flag}" if value is False
                             else f"capability_not_established:{flag}")
