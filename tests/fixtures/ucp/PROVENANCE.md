# UCP profile fixtures — provenance

Positive fixtures are copied from the example business profiles in the
Universal Commerce Protocol documentation at release `v2026-08-25` (repository
`Universal-Commerce-Protocol/ucp`, commit
`1c225995e9db9808c23fc6440fc70f38b27d914a`, the same tree as the vendored
schemas — see `src/scovant_core/parsers/ucp_schemas/v2026-08-25/SOURCE.md`;
Apache License 2.0). Paths are relative to `docs/specification/` in that
repository; the line is the line of the example's `ucp:example` annotation.

Every documentation example is reduced the way the upstream validator reduces
it: `{{ ucp_version }}` replaced by `2026-08-25`. Hosts outside the
documentation namespaces (`example.com` and its subdomains) are rewritten to
one of them; that is the only other change, and it is named per fixture.
`ucp.dev` URLs are kept verbatim: they are the protocol's own spec and schema
namespace, never fetched (the parser never dereferences a URL).

Each positive fixture is also validated by `jsonschema` against the vendored
schema in `tests/test_ucp_schema_conformance.py`.

| file | origin | v2026 state |
|---|---|---|
| current_rest.json | `shopping/checkout/rest.md`, `### Discovery`, line 29 — verbatim | usable |
| current_mcp.json | `shopping/checkout/mcp.md`, `### Discovery`, line 29 — the payment handler's vendor host (not a reserved documentation name) → `vendor.example.com` | usable |
| current_a2a.json | `shopping/checkout/a2a.md`, `## Transport Discovery`, line 28 (a `$.ucp.services` fragment) — wrapped with `"payment_handlers": {}`; the agent-card host (not a reserved documentation name) → `business.example.com` | usable |
| current_embedded.json | `shopping/checkout/embedded.md`, `#### Service-Level Discovery`, line 93 (a `$.services` fragment) — kept only the `embedded` binding, wrapped in `ucp` with `version` and `"payment_handlers": {}` | usable |
| checkout_and_cart.json | `shopping/cart/rest.md`, `### Discovery`, line 28 — verbatim | usable |
| permalink.json | `permalink.md`, `## Discovery`, line 58 (a `$.ucp.capabilities` fragment) — wrapped with `"services": {}` and `"payment_handlers": {}`; the permalink endpoint host `merchant.example` → `merchant.example.com` | usable |
| overview_business.json | `overview/index.md`, `#### Business Profile`, line 512 — verbatim (all four transports, an OKP and an EC public key) | usable |
| protocol_version_2026_01_23.json | `overview/index.md`, `#### Protocol Version`, line 3494 — verbatim (declares `2026-01-23`, an earlier announced release) | usable |
| uppercase_rest.json | derived from current_rest.json: `transport` `rest` → `REST` | unusable |
| legacy_commerce_checkout.json | derived from current_rest.json: capability key `dev.ucp.shopping.checkout` → `dev.ucp.commerce.checkout` | usable |
| version_0_1.json | derived from current_rest.json: `ucp.version` → `0.1` | unusable |
| missing_endpoint.json | derived from current_rest.json: the rest binding's `endpoint` removed | unusable |
| missing_schema.json | derived from current_rest.json: the checkout capability's `schema` removed | unusable |
| future_version.json | derived from current_rest.json: every `2026-08-25` → `2027-03-01` | future |
| custom_capability.json | derived from current_rest.json: added capability `com.example.loyalty` | usable |
| json_array_root.json | derived from current_rest.json: the profile wrapped in a JSON array | unusable |
| private_ip_schema_url.json | derived from current_rest.json: the service and capability `schema` URLs → a private address (10.0.0.5), which must never be fetched | usable |
| private_jwk.json | derived from current_rest.json: added `keys` with one OKP key carrying the private member `d` (synthetic, low-entropy placeholder values) | unusable |
| legacy_signing_keys.json | derived from current_rest.json: added the pre-release `signing_keys` field (synthetic key without material) | usable |
| html_catchall.html | synthetic — an SPA shell, as a catch-all route serves for an unknown path | html |
| legacy_expected.json | generated — the legacy keys `check_ucp_profile` returned for every fixture above before the `v2026` block existed | — |

The `oversized` case is generated inside the test (a padded current_rest.json).

`v2026 state` is the verdict `ucp_profile_state` gives each fixture served with
HTTP 200 (`usable`, `unusable`, `future`, `html`); `test_ucp_v2026_parser.py`
pins the column to the parser and downstream checks read it, so a
parser that turns a negative fixture usable (or the reverse) fails both.
