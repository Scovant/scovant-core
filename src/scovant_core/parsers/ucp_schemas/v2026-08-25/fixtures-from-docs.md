# Profile examples in the UCP v2026-08-25 documentation

Source for fixtures: the `docs/` tree of the upstream repository at the commit
named in `SOURCE.md`. Every JSON example in those docs carries an annotation
`<!-- ucp:example schema=... [def=...] [extract=...] [target=...] -->` that the
upstream build validates against the schemas. Before use as a fixture an example
must be reduced the way the upstream validator reduces it: replace
`{{ ucp_version }}` with `2026-08-25`, strip `//` line comments, and drop or
replace `...` elision markers (an example containing an elision is a fragment,
not a complete document).

Paths are relative to `docs/specification/` unless they start with `docs/`.
"Line" is the line of the annotation comment.

## Complete business profiles (`def=business_schema`, no `target`)

These validate as whole documents against `profile.json#/$defs/business_schema`.

| File | Heading | Line |
| :--- | :------ | ---: |
| `overview/index.md` | `#### Business Profile` (canonical example: rest + mcp + a2a + embedded services, checkout/fulfillment/discount/identity-linking capabilities, one payment handler, an OKP and an EC key) | 512 |
| `overview/index.md` | `#### map_order` | 914 |
| `overview/index.md` | `#### Example` (under negotiation) | 3445 |
| `overview/index.md` | `#### Protocol Version` (minimal: `version` + `supported_versions`, empty `services` and `payment_handlers`) | 3494 |
| `docs/documentation/core-concepts.md` | `### Profile Structure` | 269 |
| `common/identity-linking/index.md` | `### Profile Example` | 475 |
| `common/identity-linking/index.md` | `#### B2C retailer` | 1117 |
| `common/identity-linking/index.md` | `#### B2B wholesaler` | 1155 |
| `payment/extensions/ap2-mandates.md` | `### Business Profile Advertisement` | 68 |
| `common/location/rest.md` | `### Discovery` | 28 |
| `common/location/mcp.md` | `### Discovery` | 27 |
| `shopping/checkout/rest.md` | `### Discovery` | 29 |
| `shopping/checkout/mcp.md` | `### Discovery` (`op=read direction=response`) | 29 |
| `shopping/cart/rest.md` | `### Discovery` | 28 |
| `shopping/cart/mcp.md` | `### Discovery` | 29 |
| `shopping/catalog/rest.md` | `### Discovery` | 29 |
| `shopping/catalog/mcp.md` | `### Discovery` | 29 |
| `shopping/order/rest.md` | `### Discovery` | 28 |
| `shopping/order/mcp.md` | `### Discovery` | 29 |

## Business-profile fragments (`def=business_schema` with `target`/`extract`)

Only the part named by `target` is shown; wrap it in a minimal valid profile
(`ucp.version`, empty `services` and `payment_handlers`) before use.

| File | Heading | Line | Part |
| :--- | :------ | ---: | :--- |
| `permalink.md` | `## Discovery` | 58 | `$.ucp.capabilities` (`dev.ucp.shopping.permalink`) |
| `overview/index.md` | `#### Extensions` | 281 | `$.ucp.capabilities` |
| `overview/index.md` | `##### Multi-Parent Extensions` | 299 | `$.ucp.capabilities` |
| `docs/documentation/core-concepts.md` | `### Extensions` | 163 | `$.ucp.capabilities` |
| `shopping/extensions/fulfillment.md` | `### Business Profile` | 755 | `$.ucp.capabilities` |
| `shopping/extensions/discount.md` | `## Discovery` | 41 | `$.ucp.capabilities` |
| `shopping/extensions/buyer-consent.md` | `## Discovery` | 62 | `$.ucp.capabilities` |
| `common/extensions/loyalty.md` | `## Discovery` | 104 | `$.ucp.capabilities` (includes `dev.ucp.shopping.cart`) |
| `payment/extensions/authentication.md` | `## Discovery and Negotiation` | 50 | `$.ucp.capabilities` |
| `shopping/checkout/a2a.md` | `## Transport Discovery` | 28 | `$.ucp.services` (a2a) |
| `shopping/checkout/embedded.md` | `#### Service-Level Discovery` | 93 | `$.ucp.services` (embedded) |
| `shopping/cart/embedded.md` | `### Discovery` | 53 | `$.ucp.services` (embedded) |
| `payment/guide.md` | `### Handler Declaration` | 171 | `$.ucp.payment_handlers` |
| `payment/examples/processor-tokenizer-payment-handler.md` | `#### Example Business Handler Declaration` | 110 | `$.ucp.payment_handlers` |
| `payment/examples/processor-tokenizer-payment-handler.md` | `#### Step 1: Discover Handler` | 198 | `$.ucp.payment_handlers` |
| `payment/examples/platform-tokenizer-payment-handler.md` | `#### Example Business Handler Declaration` | 195 | `$.ucp.payment_handlers` |
| `payment/examples/platform-tokenizer-payment-handler.md` | `#### Example Platform Handler Declaration` | 330 | `$.ucp.payment_handlers` |
| `payment/examples/encrypted-credential-payment-handler.md` | `#### Example Business Handler Declaration` | 144 | `$.ucp.payment_handlers` |
| `payment/examples/encrypted-credential-payment-handler.md` | `#### Example Platform Handler Declaration` | 257 | `$.ucp.payment_handlers` |

## Single keys (`target=$.keys[0]`)

| File | Heading | Line | Key |
| :--- | :------ | ---: | :-- |
| `signatures.md` | `### Key Format (JWK)` | 175 | EC P-256 / ES256 |
| `signatures.md` | `### Key Format (JWK)` | 190 | OKP Ed25519 / EdDSA |

## Platform profiles (`def=platform_schema`) — not served at `/.well-known/ucp`

Useful only as negative controls for the business validator (a platform
profile is a different variant).

| File | Heading | Line |
| :--- | :------ | ---: |
| `overview/index.md` | `#### Platform Profile` | 685 |
| `overview/index.md` | `#### Example` (under negotiation) | 3459 |
| `shopping/extensions/fulfillment.md` | `### Platform Profile` | 706, 729 |
| `shopping/order/index.md` | `### Webhook URL Configuration` | 711 |

## Conformance suite

The upstream conformance repository (`main` at
`79a0f40fb4b4e477e7a0988f86ccc5ed5b030b1b`) is a pytest suite run against live
servers and ships **no** static business-profile fixtures. Two points from it
are evidence only: its profile reader (`framework/discovery.py`, `UcpProfile`)
tolerates `capabilities` given as a list of `{name, ...}` objects as well as the
keyed map, and its default protocol version is `2026-04-08`
(`framework/constants.py`, `DEFAULT_UCP_VERSION`). `shopping-agent-test.json`
at its root is a platform profile, not a business profile.
