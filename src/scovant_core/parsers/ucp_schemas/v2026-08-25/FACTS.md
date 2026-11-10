# UCP v2026-08-25 — facts for the profile parser

Every statement below is quoted from the vendored schemas in this directory
(file + JSON pointer) or, where the schemas are silent, from the documentation
at the same release (`docs/` in the upstream repository at commit
`1c225995e9db9808c23fc6440fc70f38b27d914a`, cited as file + heading). See
`SOURCE.md` for provenance. Where these facts disagree with any earlier
assumption in this package, these facts win; every such disagreement is listed
under "Contradictions with the previous parser assumptions" at the end.

A business profile (the document at `/.well-known/ucp`) is validated against
`profile.json#/$defs/business_schema`, not the root of `profile.json`. The
documentation marks every business-profile example with
`<!-- ucp:example schema=profile def=business_schema -->`.

`$ref` resolution: every vendored file carries an absolute `$id` under `https://ucp.dev/schemas/`
(e.g. `profile.json` → `https://ucp.dev/schemas/profile.json`, `ucp.json` →
`https://ucp.dev/schemas/ucp.json`), and their relative `$ref`s resolve against
those ids. A validator **MUST** resolve every `$ref` from a local registry built
from these vendored files (keyed by each file's `$id`) and **MUST NOT** use a
retrieving resolver: nothing is ever fetched from `ucp.dev`.

## (a) Version

- Field: `ucp.version`. Required: `ucp.json#/$defs/base/required` = `["version"]`;
  the profile root requires `ucp`: `profile.json#/$defs/base/required` = `["ucp"]`.
- Format: `ucp.json#/$defs/version` —
  `"type": "string"`, `"pattern": "^\\d{4}-\\d{2}-\\d{2}$"`,
  `"description": "Version identifier in YYYY-MM-DD format."`
  The pattern checks shape only: `2026-13-45` matches it.
- Every service, capability and payment-handler entry also carries a `version`
  of the same format: `ucp.json#/$defs/entity/required` = `["version"]`,
  `ucp.json#/$defs/entity/properties/version/$ref` = `#/$defs/version`.
- This release: `2026-08-25` (tag `v2026-08-25`; `mkdocs.yml` `extra.ucp_version: "2026-08-25"`).
- Earlier releases named in the docs: `docs/versioning.md` names **no** release
  values (it only defines the `release/YYYY-MM-DD` / `vYYYY-MM-DD` scheme).
  `docs/documentation/announcements.md` names three earlier protocol releases:
  - "April 8, 2026: Protocol Release v2026-04-08"
  - "January 23, 2026: Protocol Release v2026-01-23"
  - "January 11, 2026: Protocol Release v2026-01-11"
- Older versions a business still supports are declared in
  `ucp.supported_versions`: `ucp.json#/$defs/business_schema/allOf/1/properties/supported_versions`
  — an object whose keys match `#/$defs/version` and whose values are
  `"type": "string", "format": "uri"`. Docs, `overview/index.md` § "Protocol
  Version": "When `supported_versions` is omitted, only `version` is
  supported." and "Version-specific profiles are leaf documents — they describe
  exactly one protocol version and **MUST NOT** contain a `supported_versions`
  field."
- Entry versions (docs only, not expressible in the schema),
  `overview/index.md` § "Component Versioning and Release Snapshots": "A
  Business or Platform that selects `ucp.version` `D` **MUST** declare version
  `D` on every `dev.ucp.*` service, capability, and extension entry in its
  profile. A Platform that encounters a `dev.ucp.*` entry whose `version`
  differs from the profile's `ucp.version` **MUST** reject that entry — treated
  as not present and never activated — and **MAY** continue with the remaining
  entries." Payment-handler versions are not constrained to `D` (same section).

## (b) Transport enum

- `service.json#/$defs/base/allOf/1/properties/transport`:
  `"type": "string"`, `"enum": ["rest", "mcp", "a2a", "embedded"]`.
- Exact case: **lowercase**. JSON Schema `enum` compares exactly, so `"REST"`,
  `"MCP"` and `"A2A"` are invalid values.
- `transport` is required on every service entry:
  `service.json#/$defs/base/allOf/1/required` = `["transport"]`.

## (c) Capabilities

- Declaration shape: an **object keyed by reverse-domain name**, each value an
  **array** of capability entries.
  `ucp.json#/$defs/base/properties/capabilities`: `"type": "object"`,
  `"propertyNames": { "$ref": "common/types/reverse_domain_name.json" }`,
  `"additionalProperties": { "type": "array", "items": { "$ref": "capability.json#/$defs/base" } }`.
  The business variant narrows the items to `capability.json#/$defs/business_schema`
  (`ucp.json#/$defs/business_schema/allOf/1/properties/capabilities`).
- `ucp.capabilities` is **optional**: it is not in
  `ucp.json#/$defs/business_schema/allOf/1/required` (= `["services", "payment_handlers"]`).
  Docs, `overview/index.md` § "Profile Structure": "`ucp.capabilities` is
  optional and **MAY** be omitted, though useful commerce profiles normally
  advertise at least one capability."
- A business capability entry requires `version` (entity) and `schema`:
  `capability.json#/$defs/business_schema/allOf/1/required` = `["schema"]`.
  `spec` is required only for platforms (`capability.json#/$defs/platform_schema/allOf/1/required` = `["spec", "schema"]`).
- Extensions carry `extends` (a reverse-domain name or a non-empty array of them):
  `capability.json#/$defs/base/allOf/1/properties/extends`.
- Name format: `common/types/reverse_domain_name.json` —
  `"pattern": "^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9_])?)+$"`
  (lowercase, at least two dot-separated segments). The same pattern governs
  the keys of `services` and `payment_handlers`.
- Standard shopping capability names (from the upstream shopping schemas, which
  are not vendored because the profile does not reference them, and the docs):
  - `dev.ucp.shopping.checkout` — `source/schemas/shopping/checkout.json#/name`;
    also `common/types/reverse_domain_name.json#/examples/0`; docs
    `overview/index.md` § "Business Profile" example.
  - `dev.ucp.shopping.cart` — `source/schemas/shopping/cart.json#/name`; docs
    `shopping/cart/index.md`: "**Capability Name:** `dev.ucp.shopping.cart`".
  - `dev.ucp.shopping.permalink` — `source/schemas/shopping/permalink.json#/name`;
    docs `permalink.md`: "**Capability Name:** `dev.ucp.shopping.permalink`".
  The shopping service itself is keyed `dev.ucp.shopping` (docs
  `overview/index.md` § "Services": "A service is identified by its
  reverse-domain registry key (e.g., `dev.ucp.shopping`)").

## (d) Signing keys

- Field name: top-level **`keys`** (a sibling of `ucp`, not inside it):
  `profile.json#/$defs/base/properties/keys` — `"type": "array"`,
  `"items": { "$ref": "#/$defs/jwk_public_key" }`; description: "Canonical UCP
  profile field for publishing signing keys, as a JWK Set per RFC 7517. When a
  profile publishes signing keys, they MUST appear here".
- `keys` is **optional**: it is not in `profile.json#/$defs/base/required`
  (= `["ucp"]`). Docs, `overview/index.md` § "Profile Structure": "Profiles
  **MAY** include public JSON Web Keys".
- `signing_keys` appears nowhere in the vendored schemas or in the docs at this release.
- JWK requirements, `profile.json#/$defs/jwk_public_key`:
  - `"required": ["kid", "kty"]`; `kid`, `kty`, `crv`, `x`, `y`, `alg`, `use` are strings when present.
  - `/allOf/0`: `kty == "EC"` → `required: ["crv", "x", "y"]`.
  - `/allOf/1`: `kty == "OKP"` → `required: ["crv", "x"]`.
  - `/allOf/2..4`: `crv` `P-256` ⇒ `alg` (if present) `ES256`; `P-384` ⇒ `ES384`; `Ed25519` ⇒ `EdDSA`.
  - `/not/anyOf`: none of the private members `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k` may be present.
  - `"additionalProperties": true`.
  - `use` is **not** required. Its description: "JWK public key use. UCP examples use sig for signatures."
  - Open vocabulary (`/description`): "verifiers MUST tolerate key types,
    curves, and algorithms they do not recognize ... An unsupported key affects
    only the signature that references it (algorithm_unsupported) and MUST NOT
    cause whole-profile rejection."

## (e) Required fields per transport binding (business profile)

Every service entry: `version` (`ucp.json#/$defs/entity/required`) and
`transport` (`service.json#/$defs/base/allOf/1/required`). `ucp.services` and
`ucp.payment_handlers` are required in the business profile
(`ucp.json#/$defs/business_schema/allOf/1/required`); docs, § "Profile
Structure": "The `services` and `payment_handlers` registries **MUST** be
present even when empty." Each service value is an array; each array entry is
one transport binding (`service.json` `description`).

Per transport, `service.json#/$defs/business_schema/allOf/1/anyOf`:

| transport | additionally required | note |
| :-------- | :-------------------- | :--- |
| `rest` | `endpoint` | `anyOf/0` |
| `mcp` | `endpoint` | `anyOf/1` |
| `a2a` | `endpoint` | `anyOf/2`; docs § "Endpoint Resolution": "`endpoint` for A2A transport refers to the Agent Card URL for the agent" |
| `embedded` | nothing | `anyOf/3`; `config`, when present, must match `transports/embedded_config.json` |

`spec` and `schema` are **not** required for a business service entry. (For
platform profiles, `service.json#/$defs/platform_schema` requires `spec` on
every entry and `schema` for `rest`, `mcp` and `embedded`.) `endpoint` is
`"format": "uri"` (`service.json#/$defs/base/allOf/1/properties/endpoint`);
docs § "Endpoint Resolution": "`endpoint` **MUST** be a valid URL with scheme
(https)".

Payment handlers: each entry requires `id` (`payment_handler.json#/$defs/base/allOf/1/required`)
and `version` (entity); `available_instruments`, when present, has `"minItems": 1`.

## (f) Media type

- The schemas specify no media type.
- The docs specify none for the profile document. `overview/index.md` §
  "Hosting" requires HTTPS, no 3xx redirects, and `Cache-Control` with
  `public` and `max-age` ≥ 60 (no `private`/`no-store`/`no-cache`), and says a
  validator (`ETag` or `Last-Modified`) **SHOULD** be present.
- The only `Content-Type` requirement is for the REST transport's API calls,
  § "REST Transport (Core)": "Requests and responses **MUST** use `application/json`."
  A media-type check on `/.well-known/ucp` is therefore a recommendation
  derived from JSON content, not a requirement the specification states.
- Size, § "Fetching", item 8: "documented profiles are under 5 KiB; since the
  schema sets no size limit, this bound is a deployment guard, and verifiers
  **SHOULD** set it no lower than 128 KiB so it does not reject conformant profiles."

## Contradictions with the previous parser assumptions

1. **Checkout capability name.** The previous parser matched the prefix
   `dev.ucp.commerce.checkout`. The name is `dev.ucp.shopping.checkout` (c).
2. **Keys field.** The previous parser required `signing_keys` (a list). The
   field is `keys` and it is optional (d); `signing_keys` is not a UCP field.
   A profile without `keys` is valid.
3. **Key `use`.** The previous parser required `use == "sig"` on every key. `use`
   is optional; the schema requires `kid` and `kty`, plus `crv`/`x`/`y` for EC
   and `crv`/`x` for OKP, and forbids private members (d). An unrecognised
   `kty` must not invalidate the whole profile (d).
4. **Transport case.** The previous parser compared `REST`, `MCP`, `A2A`. The
   enum is lowercase `rest`, `mcp`, `a2a`, `embedded` (b).
5. **Per-binding requirements.** The previous parser required `spec` on every
   service entry, `endpoint` on everything except `A2A`, and `schema` on
   REST/MCP/embedded. For a business profile: `endpoint` is required for
   `rest`, `mcp` **and** `a2a`; nothing extra for `embedded`; `spec` and
   `schema` are not required (e).
6. **Capabilities.** The previous parser treated a missing `ucp.capabilities`
   as an error and required `spec` and `schema` on each entry. `capabilities`
   is optional and a business entry requires `version` and `schema` only (c).
7. **Payment handlers.** The previous parser did not check
   `ucp.payment_handlers`. It is required in a business profile, even when empty (e).
8. **Version format.** The previous parser accepted any string as
   `ucp.version`. It must match `^\d{4}-\d{2}-\d{2}$` (a).
9. **Body size cap.** A 64 KB cap on the stored body is below the docs'
   recommended floor of 128 KiB for a verifier's read bound (f). Documented
   profiles are under 5 KiB, so a 64 KB cap is unlikely to bite, but it is
   below the stated floor.
10. **Media type.** No media type is mandated for the profile document (f);
    a `Content-Type` finding can only be a warning, not a validity failure.
11. **Missing keys as a key-state.** A `MISSING` key state must not be read as
    invalid: the specification makes `keys` optional (d).
