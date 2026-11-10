# Source of the vendored UCP schemas

These files are copied **unchanged** (byte for byte) from the Universal Commerce
Protocol specification repository. Nothing here is fetched at scan time.

| Field | Value |
| :---- | :---- |
| Repository | https://github.com/Universal-Commerce-Protocol/ucp |
| Release tag | `v2026-08-25` |
| Commit | `1c225995e9db9808c23fc6440fc70f38b27d914a` |
| Tag published | 2026-08-25T13:53:03Z |
| Tarball | https://api.github.com/repos/Universal-Commerce-Protocol/ucp/tarball/v2026-08-25 |
| Tarball sha256 | `aa05b8802bb8a9befc4a481cbe8b691f1c1575ce81bb7959958873f576955ad7` |
| Path in the repository | `source/schemas/` (the release publishes no assets; the schemas live in the tree) |
| Retrieved | 2026-11-09 |
| Licence | Apache License 2.0 (the repository's `LICENSE`, sha256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`; no `NOTICE` file) |

## Selection

Only the schemas needed to validate a business profile served at
`/.well-known/ucp`: `profile.json` and every file its `$ref`s reach, followed
transitively. Shopping, order, cart and other payload schemas are not reachable
from the profile and are not vendored. The paths below are relative to this
directory and equal the paths under `source/schemas/` in the repository.

## Resolving `$ref`s

Every vendored file carries an absolute `$id` under `https://ucp.dev/schemas/`
(e.g. `profile.json` → `https://ucp.dev/schemas/profile.json`, `ucp.json` →
`https://ucp.dev/schemas/ucp.json`), and their relative `$ref`s resolve against
those ids. A validator **MUST** resolve every `$ref` from a local registry built
from these vendored files (keyed by each file's `$id`) and **MUST NOT** use a
retrieving resolver: nothing is ever fetched from `ucp.dev`.

## Files

| File | sha256 |
| :--- | :----- |
| `capability.json` | `2bbed66b5adbc3d77d3b5e0c9e87687da3d8bf159755ba95d89e88cd3420ef39` |
| `common/types/available_payment_instrument.json` | `d32ca30a463a647a53c806d8ee236be739741f015db9ba0ab13f4b67003f6507` |
| `common/types/constraint_expression.json` | `8c0fcbfabc3f8038c89a86b7f6b9fa32c2754eba727328c6d90062584855ade2` |
| `common/types/request_constraints.json` | `987eaa192930a0ea8d1c7b6a7cc947153e1d9da32b46d61aa49eaf782c166edf` |
| `common/types/reverse_domain_name.json` | `a5d616402d47c602196e6e455053ee3683bc9a6e90192330297bb13abd3326eb` |
| `payment_handler.json` | `5ea09bb44a6dd5a7696150e220eae2b3b4a8eacda176793fb816a9f8240a50a6` |
| `profile.json` | `720a4e676bd4aaa5cbdcef2f89a4d0b776c4f0e141f1911da7514227ecb5c239` |
| `service.json` | `4f8453ee67d82d53f05b06fb7ea03dec0e0600faea1098b3184b71cdf0fc2423` |
| `transports/embedded_config.json` | `00381600d1d5b6ce832499c00712f6192b12674b3c2c833420c0e9d3f8f196a2` |
| `ucp.json` | `05329a3ae4546f97efcf381c3b0cb279d21063e351bcf4edd00950dc14d67c9c` |

`tests/test_ucp_schema_vendor.py` fails if a file is added, removed or edited
without this table changing with it.
