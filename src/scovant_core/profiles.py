"""Deterministic profile resolution: which site archetype (`commerce`/`saas`/
`api`/`content`) evidence best matches, so profile-scoped checks know what to
expect. Pure — reads only what's already in the `EvidenceStore`, fetches
nothing itself."""
from __future__ import annotations

PROFILES = ("auto", "content", "commerce", "saas", "api")
_TYPES_COMMERCE = {"Product", "Offer", "AggregateOffer", "ProductGroup"}


def _types(schema_org: list[dict]) -> set[str]:
    out = set()
    for node in schema_org:
        t = node.get("@type")
        for x in (t if isinstance(t, list) else [t]):
            if isinstance(x, str):
                out.add(x)
        for g in node.get("@graph", []) if isinstance(node.get("@graph"), list) else []:
            gt = g.get("@type")
            for x in (gt if isinstance(gt, list) else [gt]):
                if isinstance(x, str):
                    out.add(x)
    return out


def resolve_profile(store) -> tuple[str, float]:
    pages = (store.try_get("pages") or {}).get("pages", [])
    parsed = [p["parsed"] for p in pages if p.get("parsed")]
    types = set().union(*(_types(p["schema_org"]) for p in parsed)) if parsed else set()
    has_product = bool(types & _TYPES_COMMERCE) or any(p["product_data"] for p in parsed)
    cart = any(p["semantic_signals"].get("add_to_cart_found") for p in parsed)
    signup = any(p["semantic_signals"].get("signup_cta_found") for p in parsed)
    links = [u for p in parsed for u in p["internal_links"]["urls"]]
    pricing = any("/pricing" in u or "/plans" in u for u in links)
    openapi = (store.try_get("openapi") or {}).get("found_url") is not None
    docsish = any("/docs" in u or "/api" in u or "/developers" in u for u in links)
    if has_product and cart:
        return "commerce", 0.95
    if has_product:
        return "commerce", 0.85
    if openapi:
        return "api", 0.9 if docsish else 0.75
    if pricing and signup:
        return "saas", 0.8
    if pricing or signup:
        return "saas", 0.6
    if docsish:
        return "api", 0.55
    return "content", 0.5


def apply_profile(ctx, store) -> None:
    if ctx.options.profile != "auto":
        ctx.resolved_profile, ctx.profile_confidence = ctx.options.profile, 1.0
        return
    ctx.resolved_profile, ctx.profile_confidence = resolve_profile(store)
