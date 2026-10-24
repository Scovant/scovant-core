# Evidence envelope

`scovant_core.envelope.EvidenceEnvelope` (schema: [`evidence-envelope.schema.json`](evidence-envelope.schema.json),
`envelope_version` 1.0) is one record of experimental evidence. It never moves a
score by itself.

## Fields

| Field | Meaning |
|---|---|
| `envelope_version` | Contract version; any field change mints a new one. |
| `id` | UUID of this record. |
| `scan_id` | The scan it belongs to, or null. |
| `source` | `CORE`, `CLOUD` or `IMPORT`. |
| `verification_mode` | `DECLARED` (published by the site), `PASSIVE_OBSERVED` (read without side effects), `ACTIVE_SAFE` (requests that cannot change state), `SYNTHETIC_AUTHORIZED` (authorized writes against a sandbox). |
| `status` | `PASS`, `WARN`, `FAIL`, `NA`, `ERROR`, `INCONCLUSIVE`, `NOT_MEASURED`. |
| `maturity` | `EXPERIMENTAL`, `BETA`, `STABLE`. |
| `scored` | Whether a scored rule consumes this record. |
| `rule_id`, `check_id` | The rule or check it relates to. |
| `capability` | The capability measured, e.g. `access.diagnostics`. |
| `principal`, `intent` | Who acted and what they meant to do. |
| `environment` | `PUBLIC`, `PRODUCTION_READ_ONLY`, `SANDBOX`. |
| `observed_at` | When it was observed (timezone required). |
| `collector_version`, `ruleset_version`, `policy_id` | What produced it, under which rules and policy. |
| `evidence`, `limitations` | The observation and what it cannot show. |
| `fix_owner` | Who would fix a WARN/FAIL: `frontend`, `backend`, `identity`, `mcp`, `edge_cdn`, `devops`, `content`, `commerce`, `security`. |

## Invariants

1. `scored: true` requires `rule_id`.
2. `SYNTHETIC_AUTHORIZED` requires `environment: SANDBOX`.
3. `WARN` and `FAIL` require `fix_owner`.

## Existing verification-mode names

`VERIFICATION_MODE_MAPPING` maps names used by existing checks and findings:
`DECLARED` → `DECLARED`, `PASSIVE_OBSERVED` → `PASSIVE_OBSERVED`,
`STATIC_DECLARED` → `DECLARED`, `ACTIVE_AUTHORIZED` → `ACTIVE_SAFE`
(`SYNTHETIC_AUTHORIZED` when the environment is `SANDBOX`; see
`map_verification_mode`).

## Promotion into a scored rule

Experimental evidence may start to affect a score only after: a stable public
specification; deterministic fixtures; a false-positive review; coverage at or
above the set threshold; for execution-dependent signals, a benchmark on at
least two independent providers or runtimes; a published changelog entry; a new
model id; a shadow period; and an explicit approval.
