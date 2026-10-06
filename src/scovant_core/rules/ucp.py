"""Universal Commerce Protocol and agent-payment rules published from Scovant
Cloud: the /.well-known/ucp profile, its checkout capability and signing
keys, and agent payment protocols beyond UCP.

The findings' text and metadata are the ones Scovant Cloud has always
reported for these codes; `measure` says when silence is a pass. UCP is
scored only for the site types that transact or sell access
(`UCP_APPLICABLE_SITE_TYPES`); the checkout and payment rules only for the
types that check out (`UCP_CHECKOUT_SITE_TYPES`).
"""
from __future__ import annotations

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
    "your capabilities (Checkout, Order, Identity Linking, Payment Token "
    "Exchange) and transact securely on behalf of users."
)


def _published(domain: dict | None, ctx: MeasureCtx, *, types: frozenset[str] | None,
               need_valid: bool) -> OutcomeState | None:
    """Measured when the site published a profile (a valid one, if asked)."""
    if types is not None and ctx.site_category not in types:
        return OutcomeState.NA
    verdict = probe_measured(domain, ctx, "ucp")
    if verdict:
        return verdict
    assert domain is not None
    ucp = (domain.get("ucp") or {})
    if not ucp.get("exists") or (need_valid and not ucp.get("valid")):
        return OutcomeState.NA
    return None


@register_rule
class UcpProfileAbsent(CoreRule):
    code = "UCP_PROFILE_ABSENT"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
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
        ucp = domain.get("ucp") or {}
        if ucp.get("exists"):
            return []
        return [
            Finding(
                title="Universal Commerce Protocol profile absent",
                description=(
                    "No /.well-known/ucp profile found on this domain. AI agents "
                    "that follow the UCP standard cannot autonomously discover "
                    "this site's commerce capabilities."
                ),
                example=(
                    "# /.well-known/ucp.json — publish a Universal Commerce Protocol profile\n"
                    "{\n"
                    '  "ucp_version": "0.1",\n'
                    '  "merchant": {"name": "Acme", "url": "https://example.com"},\n'
                    '  "checkout": {"endpoint": "https://example.com/ucp/checkout"},\n'
                    '  "signing_keys": [\n'
                    '    {"kid": "2026-k1", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "sig"}\n'
                    "  ]\n"
                    "}"
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Publish a JSON profile at /.well-known/ucp declaring the "
                    "capabilities you support. A minimal profile lists your "
                    "Checkout service, the supported transport (REST, MCP, A2A, "
                    "or embedded), and your signing keys. See ucp.dev/specification/"
                    "overview for the full schema and "
                    "github.com/Universal-Commerce-Protocol/samples for working "
                    "implementations. UCP support signals to agentic-commerce "
                    "platforms that your site is ready for autonomous purchase "
                    "flows — adoption today is small, so being early is a "
                    "differentiator."
                ),
                metadata={"site_type": site_type},
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
    rule_version = "1.0"
    scope = "domain"
    category = "ucp"
    severity = "medium"
    title = "Universal Commerce Protocol profile invalid"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        ucp = domain.get("ucp") or {}
        if not ucp.get("exists") or ucp.get("valid"):
            return []
        errors = [e for e in (ucp.get("validation_errors") or []) if isinstance(e, str)][:5]
        return [
            Finding(
                title="Universal Commerce Protocol profile invalid",
                description=(
                    "/.well-known/ucp returned 200 but the profile failed schema "
                    f"validation. First errors: {'; '.join(errors) or 'none reported'}."
                ),
                example=(
                    "# Fill in the required top-level fields\n"
                    "{\n"
                    '  "ucp_version": "0.1",\n'
                    '  "merchant": {"name": "Acme", "url": "https://example.com"},\n'
                    '  "checkout": {"endpoint": "https://example.com/ucp/checkout"}\n'
                    "}"
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Your profile is served but does not conform to the schema. "
                    "Required top-level keys are ucp.version, ucp.services, "
                    "ucp.capabilities, and signing_keys. Each service entry must "
                    "include version, spec, transport, and (for non-A2A) endpoint "
                    "and schema URLs. Each capability entry must include version, "
                    "spec, and schema. Run the official conformance suite at "
                    "github.com/Universal-Commerce-Protocol/conformance against "
                    "your profile to confirm the fix."
                ),
                metadata={"validation_errors": ucp.get("validation_errors", [])},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _published(domain, ctx, types=None, need_valid=False)


@register_rule
class UcpCheckoutMissing(CoreRule):
    code = "UCP_CHECKOUT_MISSING"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "ucp"
    severity = "low"
    title = "Universal Commerce Protocol: Checkout capability missing"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        site_type: str = domain.get("site_type", "")
        if site_type not in UCP_CHECKOUT_SITE_TYPES:
            return []
        ucp = domain.get("ucp") or {}
        if not ucp.get("exists") or not ucp.get("valid"):
            return []
        if ucp.get("has_checkout"):
            return []
        return [
            Finding(
                title="Universal Commerce Protocol: Checkout capability missing",
                description=(
                    "Site publishes a valid UCP profile but does not declare the "
                    "dev.ucp.commerce.checkout capability — AI agents cannot "
                    "initiate transactions via the protocol."
                ),
                example=(
                    "# Declare a checkout capability so agents know they can transact\n"
                    '"checkout": {\n'
                    '  "endpoint": "https://example.com/ucp/checkout",\n'
                    '  "methods": ["card", "wallet"]\n'
                    "}"
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Your profile is valid but is missing the Checkout capability. "
                    "Add an entry under ucp.capabilities with key "
                    "'dev.ucp.commerce.checkout' that points to your checkout "
                    "session creation, cart management, and tax calculation "
                    "endpoints. See ucp.dev/specification/checkout for the full "
                    "capability definition and request/response schemas. Sites "
                    "with declared Checkout are the ones agentic-commerce "
                    "platforms will route purchase intents to."
                ),
                metadata={
                    "site_type": site_type,
                    "declared_capabilities": ucp.get("capabilities", []),
                },
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _published(domain, ctx, types=UCP_CHECKOUT_SITE_TYPES, need_valid=True)


@register_rule
class UcpSigningKeysInvalid(CoreRule):
    code = "UCP_SIGNING_KEYS_INVALID"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "ucp"
    severity = "medium"
    title = "Universal Commerce Protocol: signing keys invalid"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        ucp = domain.get("ucp") or {}
        # Only fires when profile is structurally valid — a broken profile is
        # reported via UCP_PROFILE_INVALID instead, to avoid cascading noise.
        if not ucp.get("exists") or not ucp.get("valid"):
            return []
        if ucp.get("signing_keys_valid"):
            return []
        return [
            Finding(
                title="Universal Commerce Protocol: signing keys invalid",
                description=(
                    "Site publishes a valid UCP profile but the signing_keys "
                    "array is empty or its entries are not valid JWKs (kid / kty "
                    "/ use=sig). AI agents cannot verify PSP or Credential "
                    "Provider exchanges against this profile."
                ),
                example=(
                    "# Each signing key needs kid, kty and use=\"sig\"\n"
                    '"signing_keys": [\n'
                    '  {"kid": "2026-k1", "kty": "EC", "crv": "P-256", "x": "f83...", "y": "x_F...", "use": "sig"}\n'
                    "]"
                ),
                remediation_hint=(
                    f"{_UCP_REMEDIATION_BASE} "
                    "Each entry in signing_keys must be a JWK with three string "
                    "fields: 'kid' (key identifier), 'kty' (key type — EC, RSA, "
                    "or oct), and 'use' set to 'sig'. Generate the keys server-"
                    "side (do not commit private keys), publish only the public "
                    "half. Rotate by appending a new entry with a fresh 'kid' "
                    "and removing the old one after rollout. The full JWK spec "
                    "is at RFC 7517 § 4; UCP's use of signing keys is described "
                    "at ucp.dev/specification/security."
                ),
                metadata={},
            )
        ]

    def measure(self, page: dict, domain: dict | None, ctx: MeasureCtx) -> OutcomeState | None:
        return _published(domain, ctx, types=None, need_valid=True)


@register_rule
class AgentPaymentsAbsent(CoreRule):
    code = "AGENT_PAYMENTS_ABSENT"
    since = "0.10.0"
    maturity = "required"
    rule_version = "1.0"
    scope = "domain"
    category = "ucp"
    # info: agent payment protocol adoption is near zero — absence informs,
    # it does not punish.
    severity = "info"
    title = "No agent payment protocol beyond UCP"

    def evaluate(self, page: dict, domain: dict | None) -> list[Finding]:
        if not domain:
            return []
        if domain.get("site_type", "") not in UCP_CHECKOUT_SITE_TYPES:
            return []
        # Non-overlap invariant: if UCP itself is absent, UCP_PROFILE_ABSENT
        # already reports "no agent commerce at all" — stay silent.
        if not (domain.get("ucp") or {}).get("exists"):
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
        if ctx.site_category not in UCP_CHECKOUT_SITE_TYPES:
            return OutcomeState.NA
        verdict = probe_measured(domain, ctx, "agent_payments", "ucp")
        if verdict:
            return verdict
        assert domain is not None
        return None if (domain.get("ucp") or {}).get("exists") else OutcomeState.NA
