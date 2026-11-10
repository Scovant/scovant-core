"""Universal Commerce Protocol and agent-payment rules published from Scovant
Cloud: the /.well-known/ucp profile, its checkout capability and signing
keys, and agent payment protocols beyond UCP.

Since rule version 2.0 (Core 0.25.0) every rule reads the profile as a UCP
v2026-08-25 business profile — the parser's `v2026` block, validated against
the vendored official schemas (`parsers/ucp_schemas/v2026-08-25`, facts in
its FACTS.md) — and no longer the parser's older legacy keys. A profile is
*usable* when it is schema-valid AND declares the current release or an
earlier announced one; a profile declaring a later release than we vendor is
never judged (NOT_MEASURED). `measure` says when silence is a pass. UCP is
scored only for the site types that transact or sell access
(`UCP_APPLICABLE_SITE_TYPES`); the checkout and payment rules only where the
transactional_checkout capability is established — by default the types that
check out (`UCP_CHECKOUT_SITE_TYPES`), or any site whose usable profile declares
checkout or that offers another agent payment rail. `evaluate` and `measure`
share that one predicate (`_checkout_gate`), so a rule is never measured but
silent. A body over our read bound is never judged either.
"""
from __future__ import annotations

from scovant_core.parsers.ucp import UCP_USABLE_VERSION_STATES, ucp_profile_state
from scovant_core.r2 import OutcomeState
from scovant_core.rules.base import CoreRule, Finding, MeasureCtx, probe_measured, register_rule

# Site types for which a UCP profile is relevant. For every other type the
# ucp category is not scored at all (the R2 public policy's ucp profile is
# this same set).
UCP_APPLICABLE_SITE_TYPES: frozenset[str] = frozenset({"commerce", "booking", "restaurant", "saas"})
# Site types that check out: the checkout capability and agent payments apply.
UCP_CHECKOUT_SITE_TYPES: frozenset[str] = frozenset({"commerce", "booking", "restaurant"})

_UCP_REMEDIATION_BASE = (
    "The Universal Commerce Protocol (UCP) is an open Apache-2.0 standard at "
    "ucp.dev for agentic commerce. It lets AI agents autonomously discover "
    "your capabilities (Checkout, Cart, Order, Identity Linking) and transact "
    "securely on behalf of users."
)

# A minimal current business profile (UCP v2026-08-25): `ucp.version`,
# `ucp.services` and `ucp.payment_handlers` are required; transports are
# lowercase; `keys` is optional and public-only. It validates as a usable
# profile with the checkout capability (pinned by the rule tests).
_CURRENT_PROFILE_EXAMPLE = (
    "{\n"
    '  "ucp": {\n'
    '    "version": "2026-08-25",\n'
    '    "services": {\n'
    '      "dev.ucp.shopping": [\n'
    '        {"version": "2026-08-25", "transport": "rest", "endpoint": "https://example.com/ucp/v1"}\n'
    "      ]\n"
    "    },\n"
    '    "capabilities": {\n'
    '      "dev.ucp.shopping.checkout": [\n'
    '        {"version": "2026-08-25", "schema": "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json"}\n'
    "      ]\n"
    "    },\n"
    '    "payment_handlers": {}\n'
    "  },\n"
    '  "keys": [\n'
    '    {"kid": "2026-k1", "kty": "EC", "crv": "P-256", "alg": "ES256", "x": "...", "y": "..."}\n'
    "  ]\n"
    "}"
)

_USABLE_VERSION_STATES = UCP_USABLE_VERSION_STATES
# Served, but never judged: a later release, a pre-v2026 snapshot, a body over our read bound.
_NOT_JUDGED = frozenset({"future", "unread", "oversized"})
_VERSION_SHOWN = 32


def _checkout_gate(code: str, domain: dict | None, ctx: MeasureCtx | None = None) -> OutcomeState | None:
    """N/A when the checkout rules do not apply, else None — the ONE predicate
    `evaluate` and `measure` share: the transactional_checkout capability flag.
    `measure` uses the host's flags when it derived them; otherwise (and always
    in `evaluate`, which has no context) the flag is derived the same way from
    the site type and this domain evidence (`derive_capabilities`; the flag
    reads no page evidence)."""
    from scovant_core.capabilities import (  # noqa: PLC0415 (capabilities import r2)
        derive_capabilities,
        gate,
    )

    caps = getattr(ctx, "capabilities", None) if ctx is not None else None
    if caps is None:
        site_type = ctx.site_category if ctx is not None else (domain or {}).get("site_type")
        caps = derive_capabilities(site_type, [], domain)
    hit = gate(code, caps)
    return hit[0] if hit else None


def _profile(domain: dict | None) -> tuple[str, dict]:
    """`ucp_profile_state` over the domain's `ucp` block (states documented there)."""
    return ucp_profile_state((domain or {}).get("ucp"))


def _content_measured(domain: dict | None, ctx: MeasureCtx, *keys: str,
                      judged: frozenset[str] = frozenset({"usable"})) -> OutcomeState | None:
    """Measured when the profile is in one of the `judged` states; N/A when
    there is no profile to judge; NOT_MEASURED when our probe failed or the
    content could not be read (a future release, a pre-v2026 snapshot)."""
    verdict = probe_measured(domain, ctx, *keys)
    if verdict:
        return verdict
    state, _ = _profile(domain)
    if state in judged:
        return None
    if state in _NOT_JUDGED:
        return OutcomeState.NOT_MEASURED
    return OutcomeState.NA


@register_rule
class UcpProfileAbsent(CoreRule):
    code = "UCP_PROFILE_ABSENT"
    since = "0.10.0"
    maturity = "required"
    rule_version = "2.0"
    scope = "domain"
    category = "ucp"
    # medium: an applicable site with no /.well-known/ucp profile has zero
    # UCP support, and the category must reflect that.
    severity = "medium"
    title = "Universal Commerce Protocol profile absent"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        site_type: str = domain.get("site_type", "")
        if site_type not in UCP_APPLICABLE_SITE_TYPES:
            return []
        state, _ = _profile(domain)
        if state not in ("absent", "html"):
            return []
        served_html = state == "html"
        return [
            Finding(
                title="Universal Commerce Protocol profile absent",
                description=(
                    ("/.well-known/ucp answered with an HTML page, not a profile. "
                     if served_html else "No /.well-known/ucp profile found on this domain. ")
                    + "AI agents that follow the UCP standard cannot autonomously "
                    "discover this site's commerce capabilities."
                ),
                example=(
                    "# /.well-known/ucp — a minimal UCP v2026-08-25 business profile\n"
                    + _CURRENT_PROFILE_EXAMPLE
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Publish a JSON business profile at /.well-known/ucp (over "
                    "HTTPS, no redirects). It requires ucp.version (the release "
                    "date, currently \"2026-08-25\"), ucp.services (each binding "
                    "names a lowercase transport — rest, mcp, a2a or embedded — "
                    "and, except for embedded, an endpoint) and "
                    "ucp.payment_handlers (present even when empty). Declare "
                    "dev.ucp.shopping.checkout under ucp.capabilities so agents "
                    "can transact; a top-level `keys` JWK Set of PUBLIC signing "
                    "keys is optional. See ucp.dev/specification/overview for the "
                    "full schema and github.com/Universal-Commerce-Protocol/samples "
                    "for working implementations. If a catch-all route serves "
                    "your HTML app at this path, make it return 404 until a "
                    "profile is published."
                ),
                metadata={"site_type": site_type, "served_html": served_html},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if ctx.site_category not in UCP_APPLICABLE_SITE_TYPES:
            return OutcomeState.NA
        return probe_measured(domain, ctx, "ucp")


@register_rule
class UcpProfileInvalid(CoreRule):
    code = "UCP_PROFILE_INVALID"
    since = "0.10.0"
    maturity = "required"
    rule_version = "2.0"
    scope = "domain"
    category = "ucp"
    severity = "medium"
    title = "Universal Commerce Protocol profile invalid"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        state, v = _profile(domain)
        if state != "unusable":
            return []
        shown = [e for e in (v.get("validation_errors") or []) if isinstance(e, str)][:5]
        if not shown and v.get("version_state") == "INVALID":
            declared = v.get("profile_version")
            shown = [f"declares version {str(declared)[:_VERSION_SHOWN]}, which is not a released UCP version"
                     if isinstance(declared, str) else "declares no ucp.version"]
        return [
            Finding(
                title="Universal Commerce Protocol profile invalid",
                description=(
                    "/.well-known/ucp returned 200 but the profile is not a "
                    "usable UCP v2026-08-25 business profile. First errors: "
                    f"{'; '.join(shown) or 'none reported'}."
                ),
                example=(
                    "# Required: ucp.version (YYYY-MM-DD), ucp.services, ucp.payment_handlers\n"
                    + _CURRENT_PROFILE_EXAMPLE
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Your profile is served but does not validate against the "
                    "official UCP v2026-08-25 business-profile schema, or declares "
                    "a version that is not a released one. Required: ucp.version "
                    "as a release date (\"2026-08-25\" or an earlier announced "
                    "release), ucp.services and ucp.payment_handlers (both "
                    "present even when empty). Every service binding needs "
                    "version and a lowercase transport (rest, mcp, a2a or "
                    "embedded); rest, mcp and a2a also need an endpoint. A "
                    "capability entry needs version and schema. Optional `keys` "
                    "must hold only public JWKs (kid and kty; crv/x/y for EC, "
                    "crv/x for OKP; no private members such as d). Check the "
                    "profile against the schemas at ucp.dev and the conformance "
                    "suite at github.com/Universal-Commerce-Protocol/conformance."
                ),
                metadata={"validation_errors": list(v.get("validation_errors") or []),
                          "version_state": v.get("version_state")},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _content_measured(domain, ctx, "ucp", judged=frozenset({"usable", "unusable"}))


@register_rule
class UcpCheckoutMissing(CoreRule):
    code = "UCP_CHECKOUT_MISSING"
    since = "0.10.0"
    maturity = "required"
    rule_version = "2.0"
    scope = "domain"
    category = "ucp"
    severity = "low"
    title = "Universal Commerce Protocol: Checkout capability missing"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        site_type: str = domain.get("site_type", "")
        if _checkout_gate(self.code, domain) is not None:
            return []
        state, v = _profile(domain)
        if state != "usable" or v.get("has_checkout"):
            return []
        return [
            Finding(
                title="Universal Commerce Protocol: Checkout capability missing",
                description=(
                    "Site publishes a valid UCP profile but does not declare the "
                    "dev.ucp.shopping.checkout capability — AI agents cannot "
                    "initiate transactions via the protocol."
                ),
                example=(
                    "# Declare the checkout capability under ucp.capabilities\n"
                    '"capabilities": {\n'
                    '  "dev.ucp.shopping.checkout": [\n'
                    '    {"version": "2026-08-25", "schema": "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json"}\n'
                    "  ]\n"
                    "}"
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Your profile is valid but is missing the Checkout capability. "
                    "Add an entry under ucp.capabilities with the key "
                    "'dev.ucp.shopping.checkout' (version and schema), served by "
                    "a binding of your dev.ucp.shopping service. See "
                    "ucp.dev/specification/checkout for the full capability "
                    "definition and request/response schemas. Sites with "
                    "declared Checkout are the ones agentic-commerce platforms "
                    "will route purchase intents to."
                ),
                metadata={
                    "site_type": site_type,
                    "declared_capabilities": list(v.get("capabilities_standard") or [])
                    + list(v.get("capabilities_custom") or []),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if (g := _checkout_gate(self.code, domain, ctx)) is not None:
            return g
        return _content_measured(domain, ctx, "ucp")


@register_rule
class UcpSigningKeysInvalid(CoreRule):
    code = "UCP_SIGNING_KEYS_INVALID"
    since = "0.10.0"
    maturity = "required"
    rule_version = "2.0"
    scope = "domain"
    category = "ucp"
    severity = "medium"
    title = "Universal Commerce Protocol: signing keys invalid"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        state, v = _profile(domain)
        # `keys` is optional: only keys that are published and malformed are
        # a finding. A malformed key also fails the schema, so
        # UCP_PROFILE_INVALID reports the profile; this rule names the keys.
        if state not in ("usable", "unusable") or v.get("version_state") not in _USABLE_VERSION_STATES:
            return []
        if v.get("keys_state") != "INVALID":
            return []
        key_errors = [e for e in (v.get("validation_errors") or [])
                      if isinstance(e, str) and e.startswith("keys")]
        return [
            Finding(
                title="Universal Commerce Protocol: signing keys invalid",
                description=(
                    "Site publishes a UCP profile whose `keys` are not a valid "
                    "set of public JWKs (a JWK needs kid and kty, crv/x/y for EC "
                    "and crv/x for OKP, and must carry no private member). AI "
                    "agents cannot verify signatures against this profile."
                ),
                example=(
                    "# `keys` (optional) is a top-level JWK Set of PUBLIC keys\n"
                    '"keys": [\n'
                    '  {"kid": "2026-k1", "kty": "EC", "crv": "P-256", "alg": "ES256", "x": "f83...", "y": "x_F..."}\n'
                    "]"
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "`keys` is optional; when you publish it, every entry must be "
                    "a public JWK (RFC 7517) with 'kid' and 'kty' — plus 'crv', "
                    "'x' and 'y' for EC keys, 'crv' and 'x' for OKP keys — and "
                    "none of the private members (d, p, q, dp, dq, qi, oth, k). "
                    "Generate the keys server-side and publish only the public "
                    "half; if a private member was ever published, rotate that "
                    "key. The older `signing_keys` field is not part of the "
                    "v2026-08-25 schema and is ignored. UCP's use of signing keys "
                    "is described at ucp.dev/specification/overview."
                ),
                metadata={"key_errors": key_errors},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        verdict = _content_measured(domain, ctx, "ucp", judged=frozenset({"usable", "unusable"}))
        if verdict:
            return verdict
        _, v = _profile(domain)
        return None if v.get("version_state") in _USABLE_VERSION_STATES else OutcomeState.NA


@register_rule
class AgentPaymentsAbsent(CoreRule):
    code = "AGENT_PAYMENTS_ABSENT"
    since = "0.10.0"
    maturity = "required"
    rule_version = "2.0"
    scope = "domain"
    category = "ucp"
    # info: agent payment protocol adoption is near zero — absence informs,
    # it does not punish.
    severity = "info"
    title = "No agent payment protocol beyond UCP"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        if _checkout_gate(self.code, domain) is not None:
            return []
        # Non-overlap invariant: without a usable UCP profile, UCP_PROFILE_ABSENT
        # or UCP_PROFILE_INVALID already reports it — stay silent.
        if _profile(domain)[0] != "usable":
            return []
        payments = domain.get("agent_payments") or {}
        if payments.get("any_non_ucp"):
            return []
        return [
            Finding(
                title="No agent payment protocol beyond UCP",
                description=(
                    "The site publishes a UCP profile but supports no other agent "
                    "payment protocol (x402, L402, ACP). Agents standardized on "
                    "those rails cannot transact here."
                ),
                example=(
                    "# 402 Payment Required — L402-style challenge on a paid endpoint\n"
                    "HTTP/1.1 402 Payment Required\n"
                    'WWW-Authenticate: L402 macaroon="...", invoice="lnbc..."'
                ),
                remediation_hint=(
                    "Consider supporting an HTTP-402-style agent payment protocol "
                    "in addition to UCP: x402 (github.com/coinbase/x402) or L402 "
                    "(docs.lightning.engineering) are the most adopted as of 2026."
                ),
                metadata={"probed": list(payments.get("protocols", {}).keys())},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        if (g := _checkout_gate(self.code, domain, ctx)) is not None:
            return g
        return _content_measured(domain, ctx, "agent_payments", "ucp")
