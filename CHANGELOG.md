# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog; versions follow semver. `ruleset_version` changes are called
out explicitly because scores are only comparable within one ruleset version.

## [0.3.1] - 2026-09-15

The scored set, weights and `RULESET_VERSION` (2026.10) are unchanged. Two
detector fixes below can change individual verdicts (CORE-OPERABILITY-008
application-shell WARN; CORE-OPERABILITY-010 on 200-served access-denied
pages), so `ruleset_digest` changes and a re-scan of an affected site may
differ.

### Fixed
- Public CI: five mypy errors; coverage was measured on a non-editable install; cli-smoke no longer asserts a literal score (it checks status/scope/grade and a score floor via `tests/_smoke_assert.py`); Action smoke was missing `trusted-target`.
- CORE-OPERABILITY-008 distinguishes an application shell (WARN) from a real soft-404 (FAIL).

### Added
- `scripts/ci_parity.sh` + contract tests (CI parity, action ⇄ smoke workflow).
- `fixtures/http-semantics/` — 12 named positive/negative cases for OPERABILITY-008/-009/-010, including an Akamai sensor-only case (a bot-sensor script alone is never treated as a challenge; the denial verdict is decided from response text, the sensor only corroborates it).
- `promotion_criteria` on every experimental check, rendered in `docs/checks.md`.
- Methodology: experimental process, "How Scovant Core validates new checks", community-contribution trust statement.
- Ruleset-freeze rule and a scored-set pin test.

### Changed
- `constraints/constraints-0.3.1.txt` bumps `uvicorn` 0.52.4 → 0.53.0.
- Bot-protection detection gains an Akamai denial detector: a denial page's own text is now enough to classify it, even without a recognizable Akamai sensor marker. This changes verdicts for some Akamai-fronted denial pages from unclassified to correctly detected — expect new true positives, not regressions.

## [0.3.0] - 2026-09-14

`ruleset_version` 2026.09 → **2026.10**: three required checks were added, so
scores are NOT comparable with 0.2.x. `ruleset_digest` changed.

### Added
- Required HTTP-semantics checks (category Operability): CORE-OPERABILITY-008
  "Unknown paths return 404" (one probe of a path that cannot exist — a 200
  HTML answer is a soft-404), -009 "Rate limiting is signalled" (any observed
  429 must carry Retry-After; N/A when no 429 was seen — Core never provokes
  one), -010 "Challenge pages are not served as 200".
- Experimental (unscored) checks: CORE-ACCESS-011 "llms.txt utility" and
  CORE-OPERABILITY-011 "Discovery linkage".
- AgentReady mapping: AR-READ-02 is now EXACT (measured by -004, -008, -009).
- CITATION.cff, SUPPORT.md, CODEOWNERS, issue and pull-request templates.

### Changed
- Methodology: "HTTP 200 is not success" paragraph; seven experimental checks.

## [0.2.1] - 2026-09-14

`ruleset_version` unchanged (`2026.09`); `ruleset_digest` unchanged — scores fully
comparable with 0.2.0 and 0.1.x. Descriptive additions only.

### Added
- AgentReady v1.0 mapping (https://agentready.org/, MIT): every check declares the
  requirements it measures (`standards`), every report carries
  `metrics.standards.agentready_v1` (per-tier measured/pass/warn/fail — descriptive,
  never scored) and a one-line summary; `docs/standards/agentready.md` is generated
  from the mapping. AgentReady defines requirements, not weights; no third-party
  score is reproduced.

### Changed
- Positioning: "Scovant Core measures passive, machine-facing signals. Scovant Cloud
  verifies how real agents actually behave, across providers, browser runtimes,
  security layers and time."

## [0.2.0] - 2026-09-14

`ruleset_version` unchanged (`2026.09`); `ruleset_digest` unchanged — scores
fully comparable with 0.1.x. This release adds description and hardening,
not verdicts.

### Breaking
- GitHub Action: `allow-private-networks: true` now refuses to run unless
  `trusted-target: true` is also set, and never runs for pull requests from
  forks or with an unknown head repository (exit 2). Add
  `trusted-target: 'true'` to existing private-network workflows that take
  the URL from a trusted source.

### Added
- `metrics.protocol_adoption` — descriptive adoption of MCP, WebMCP, UCP,
  llms.txt, OpenAPI, OAuth metadata, Content-Signal and security.txt
  (`present | absent | invalid | not_checked`); rendered as "Capabilities
  detected" in every report. Never scored: absence of an optional protocol
  is not a defect, presence is not a bonus.
- Profile identity: `provenance.profile_detector_version`; a low-confidence
  auto-detected profile (< 0.70) is stated on the report; `--contribute`
  sends `profile_confidence` and `profile_detector_version`.
- Reproducibility: `constraints/constraints-0.2.0.txt` (exact pins, shipped
  as a release asset); `provenance.dependencies` and
  `provenance.environment_digest` record what actually ran.
- IP-pinned HTTP transport: hostnames are resolved once, every address is
  validated, and the connection goes to the validated address with `Host`
  and TLS verification against the original hostname — closes the DNS
  rebinding window between guard and connect. `provenance.network_mode`
  is `pinned` for live scans.
- GitHub Action: `trusted-target` input; `allow-private-networks: true`
  now refuses to run without it and never runs for pull requests from
  forks (exit 2).

### Changed
- Documentation: methodology states the optional-protocol rule explicitly;
  security.md describes the pinned transport.

## [0.1.1] - 2026-09-13

`ruleset_version` unchanged (`2026.09`); `ruleset_digest` changed — scores stay
comparable with 0.1.0, grades are stricter.

### Changed
- Scan scope and score status: a scan with `--include`/`--exclude`/`--experimental`
  is `CUSTOM` and reports a **Subset Diagnostic Score** (no grade, "Canonical Core
  Score: NOT CALCULATED"); a full scan under 85 % coverage or with any errored
  check is `PARTIAL`/`DEGRADED` (score, no grade); a canonical scan is `OK`.
  Provenance records `scan_scope`, `included_checks`, `excluded_checks`,
  `error_count` and both coverage floors. New `--require-canonical` flag; the
  GitHub Action gains `require-canonical` and outputs `coverage`, `score_status`,
  `scan_scope`, `error_count`.
- Crawler registry is purpose-aware (`search` / `user_fetch` / `training` /
  `content_use_control`, `identity_type`, `official_source`, `last_reviewed`,
  `REGISTRY_VERSION`); `CORE-ACCESS-003`/`-004` (1.1) derive their identity lists
  from it, and `-003` reports user-triggered fetch agents separately;
  `metrics.ai_crawler_policy` publishes the four dimensions.
- `--contribute` sends only canonical scans (`scan_scope`, `score_status`,
  `error_count` added to the payload); Scovant marks every client contribution
  `unverified_client`.
- URLs with credentials are rejected (exit 2); query values are shown as
  `[REDACTED]` in every report, summary and output.
- The npm launcher refuses an engine whose version differs from the launcher's
  (exit 9) unless `SCOVANT_ALLOW_VERSION_MISMATCH=1`.

## [0.1.0] - 2026-09-12

### Added
- Package skeleton, security layer (SSRF guard), parsers for robots.txt,
  Content-Signal, llms.txt, MCP discovery, UCP profile, HTML
  metadata/structured data, and the AI crawler registry.
- 45 deterministic checks (`ruleset_version` `2026.09`) across 5 categories
  — 5 of the 45 are `experimental` (marked below): evaluated and reported
  on every scan, but excluded from the Static Signal Score until
  calibrated against real-world traffic and promoted:
  - Access & Discovery (10) — `CORE-ACCESS-001` HTTPS reachability,
    `CORE-ACCESS-002` robots.txt availability and syntax,
    `CORE-ACCESS-003` AI search crawler policy,
    `CORE-ACCESS-004` training vs. search crawler separation,
    `CORE-ACCESS-005` sitemap availability,
    `CORE-ACCESS-006` sitemap freshness,
    `CORE-ACCESS-007` canonical URL integrity,
    `CORE-ACCESS-008` indexability,
    `CORE-ACCESS-009` llms.txt presence and integrity,
    `CORE-ACCESS-010` Content-Signal declaration
  - Machine Understanding (12) — `CORE-MACHINE-001` JSON-LD parseability,
    `CORE-MACHINE-002` Organization entity,
    `CORE-MACHINE-003` WebSite/WebPage entity,
    `CORE-MACHINE-004` Product structured data,
    `CORE-MACHINE-005` Offer price/currency/availability,
    `CORE-MACHINE-006` product identifier count,
    `CORE-MACHINE-007` breadcrumbs,
    `CORE-MACHINE-008` metadata quality,
    `CORE-MACHINE-009` heading structure,
    `CORE-MACHINE-010` language declaration,
    `CORE-MACHINE-011` image alt coverage,
    `CORE-MACHINE-012` visible vs. structured price (experimental)
  - Agent Interfaces (9) — `CORE-INTERFACE-001` MCP discovery presence,
    `CORE-INTERFACE-002` MCP server declaration quality,
    `CORE-INTERFACE-003` WebMCP static presence,
    `CORE-INTERFACE-004` WebMCP tool declaration quality (experimental),
    `CORE-INTERFACE-005` OpenAPI discovery,
    `CORE-INTERFACE-006` OAuth authorization-server metadata,
    `CORE-INTERFACE-007` OAuth protected-resource metadata,
    `CORE-INTERFACE-008` UCP profile validity (experimental),
    `CORE-INTERFACE-009` agent discovery surface presence — A2A cards,
    AI-plugin manifests, agents.json, Agent Skills (experimental)
  - Trust & Commerce (7) — `CORE-TRUST-001` contact/support
    discoverability, `CORE-TRUST-002` shipping policy discoverability,
    `CORE-TRUST-003` returns/refund policy discoverability,
    `CORE-TRUST-004` privacy policy discoverability,
    `CORE-TRUST-005` terms/conditions discoverability,
    `CORE-TRUST-006` security.txt discoverability,
    `CORE-TRUST-007` pricing discoverability
  - Operability & Efficiency (7) — `CORE-OPERABILITY-001`
    server-rendered core content, `CORE-OPERABILITY-002` redirect chain
    complexity, `CORE-OPERABILITY-003` cache validators,
    `CORE-OPERABILITY-004` broken machine-consumable endpoints,
    `CORE-OPERABILITY-005` agent parse cost, `CORE-OPERABILITY-006`
    form/control labels, `CORE-OPERABILITY-007` machine reference
    integrity (experimental; its gatherer runs only under `--experimental`
    — the only gatherer whose requests leave the target's own origin)
- `scovant scan` CLI (`scovant`/`scovant check`) with `--profile`,
  `--format text|json`, `--min-score`, `--fail-on`, `--timeout`,
  `--max-pages`, `--user-agent`, `--include`/`--exclude`, `--experimental`,
  `--token-chars-ratio` (characters-per-token estimate for
  `CORE-OPERABILITY-005`'s page-cost evidence, default 4), `--quiet`,
  `--no-color`, `--verbose`, and a stable exit-code contract (0 ok, 1
  threshold, 2 invalid input, 3 network, 4 security block, 5 internal
  error).
- Human-readable text report and a versioned JSON report
  (`schema_version` `1.0`), both driven off one `Report` model.
- Network safety model: scheme allow-list, DNS/literal-IP SSRF guard
  re-checked on every redirect hop, a driven (not automatic) redirect loop
  capped at 5 hops, per-kind response size caps, connect/request/total-budget
  timeouts — see `docs/security.md`.
- Deterministic profile resolution (`content`/`commerce`/`saas`/`api`) —
  see `docs/profiles.md`.
- Golden-report regression tests for four canonical fixture sites —
  `commerce-good` (100, A), `commerce-bad` (35, F), `api-good` (89, B),
  `saas-mixed` (80, B) — plus unit tests for every parser, gatherer, and
  check.
- Evidence-honesty rules applied uniformly across the checks:
  - A reference the scanner could not fetch (`status: null`) is reported as
    `unresolved`, never as a broken link — whatever declared it. When
    nothing could be read at all, the check is `ERROR`, not `PASS`.
  - A declared MCP endpoint is recorded but never judged: it speaks
    JSON-RPC over POST and Core never performs the handshake, so whatever it
    answers to a GET is `inconclusive`.
  - A 200 response carrying an HTML page where a machine document was
    requested (a catch-all router / soft-404 template) is treated as the
    document being ABSENT — for `robots.txt`, sitemaps, `llms.txt` and
    OpenAPI specs alike — and recorded as `served_as_html`. OpenAPI
    discovery keeps probing the remaining candidates instead of locking
    onto such a response.
  - An unresolvable hostname is a network failure (CLI exit 3), not a
    security block (exit 4): nothing was blocked, the name does not exist.
  - A report whose entry URL never answered carries `final_url: null`.
- Sitemap and MCP server-card probes follow redirects through the guarded
  client, so a document declared behind a 301 is found rather than reported
  as absent.
- The text report prints `(evaluated/applicable)` check counts beside each
  category score, and an `Experimental (not scored)` block listing any
  experimental check that evaluated to something other than `N/A` (or a
  one-line notice when none did); `docs/methodology.md` documents the
  per-category check/weight distribution.
- Documented, capped request budget per scan beyond the entry-page fetch
  and always-on discovery documents: policy pages ≤5, `security.txt` ≤2,
  OAuth metadata 2, UCP profile 1, agent discovery surfaces ≤10 (≤11 when
  the OpenAPI document was found at a path other than `/openapi.json` —
  three of the thirteen conventional paths, the OpenAPI root document and
  the two OAuth discovery documents, are shared documents another gatherer
  already fetched this scan, so a DEFINITIVE earlier answer (a real 200 +
  real JSON, a genuine 404/410, or a soft-200 HTML catch-all) is recorded
  from that read instead of being probed a second time; an inconclusive
  earlier read is never guessed into an answer and is probed directly),
  machine reference integrity ≤20 (`--experimental` only — the only
  gatherer gated on the flag, zero requests without it) — see
  `docs/security.md`.
- The machine reference integrity probe (`analysis/integrity_probe.py`) is
  routed through the same guarded `SecureClient` every other gatherer
  uses for its package-registry lookups (SSRF guard, size cap, and a
  refusal of any redirect that would leave the requested registry host —
  no cross-host hop is followed even when the hop itself is a safe public
  address); DNS lookups for domain references remain their own, separate,
  HTTP-free resolution. It only ever runs under `--experimental` and is
  bounded by the ≤20-lookup budget above.
- `--format markdown` — the same `Report` rendered as GitHub-flavored
  Markdown (score table, per-category breakdown, findings grouped by
  status with collapsible evidence) for pasting into a PR or issue.
- `--format html` — the same `Report` rendered as one self-contained HTML
  document (inline CSS, no external resources, no JavaScript) suitable to
  open directly in a browser or attach as a CI artifact. Both new
  renderers are plain Python over the existing `Report` model
  (`html.escape` for HTML) — no template-engine dependency added.
- `--allow-private-networks` — an explicit, off-by-default opt-in that
  lifts the SSRF address block for the scan's target host only (every
  other protection — scheme allow-list, redirect re-check, size caps,
  request budget — stays in force); the CLI and the GitHub Action's
  `allow-private-networks` input both map to the same
  `SecurityPolicy.allow_private_networks` flag, and every report format
  prints a one-line notice when it was used. See `docs/security.md` §
  Private-network targets (opt-in) — the match is on the exact hostname
  string you typed (`localhost` does not cover `127.0.0.1`).
- Composite GitHub Action (`action.yml` at the package root, so
  `uses: Scovant/scovant-core@v1` runs it): installs itself from the
  checked-out ref (`pip install "$GITHUB_ACTION_PATH"`, no PyPI
  round-trip, no version skew between the pinned tag and the code that
  runs), scans one URL, writes a Markdown Step Summary, uploads the full
  report as a workflow artifact, and fails the step per its
  `min-core-score`/`fail-on` gate. Inputs: `url`, `profile`,
  `min-core-score`, `fail-on`, `experimental`, `timeout`, `report-format`,
  `allow-private-networks`. Outputs: `score`, `grade`, `pass_count`,
  `warn_count`, `fail_count`, `report_path`. One URL, one run, no state,
  no comparison across runs — see the README's "Free boundary" note for
  where Scovant Monitor picks up.
- `scovant mcp` — a stdio MCP server behind the optional `[mcp]` extra
  (`mcp>=1.28,<2`), exposing five read-only tools (`scan_site`,
  `get_core_score`, `list_checks`, `explain_check`, `get_finding`) so an
  agent host can run a passive scan as a tool call instead of a shell
  command. Single-flight (one scan at a time) and keeps only the last 8
  reports in memory for `get_finding` to read back; never opens a browser,
  never performs an MCP `initialize`/`tools/call` against the *scanned*
  site, never authenticates.
- One shared `document_status()` rule backs every one of the nine checks
  that classify a single well-known document fetch (robots.txt, sitemaps,
  llms.txt, MCP/OpenAPI/OAuth/UCP/`security.txt` discovery) — see
  `docs/methodology.md` § The status model for the exact ERROR/N/A/PASS
  boundary it enforces.
- Discovery-surface probe budget: ≤13 candidate requests per scan, ≤10
  when all three shared documents (OpenAPI at `/openapi.json`, both OAuth
  well-knowns) gave a definitive earlier answer — an inconclusive earlier
  read (5xx/401/403/error/a different path) is re-probed directly instead
  of being guessed. See the request-budget bullet above.
- Documentation: `docs/methodology.md`, `docs/checks.md` (generated),
  `docs/core-vs-cloud.md`, `docs/security.md`, `docs/profiles.md`,
  `docs/releasing.md`.
- Published, generated JSON schema for the report (`docs/report.schema.json`,
  JSON Schema draft 2020-12) — `scovant_core.schema.report_schema()` derives
  it from the `Report` pydantic model, `python -m scovant_core.schema`
  writes it, and a test pins the committed file to the generator and
  validates every golden fixture and every MCP tool's `inputSchema` against
  it. Adding a report field never bumps `schema_version`; removing or
  retyping one does — see `docs/methodology.md` § Report schema.
- `--contribute` — opt-in, off by default: after a scan completes, sends
  one HTTPS POST to a single fixed URL with an aggregate-only measurement
  (`domain`, `timestamp`, `core_version`, `ruleset_version`,
  `ruleset_digest`, `profile`, `experimental`, `check_statuses`, `score`)
  for the community index at scovant.com/research. No page content, no
  evidence, no IP address is ever sent. Never blocks or changes the exit
  code; refused (exit 2) together with `--allow-private-networks`. See the
  README's "Community contributions" section and `docs/security.md` §
  Outbound requests.
- `@scovant/core` — a thin npm launcher (`npm/`) that runs the Python
  engine rather than reimplementing any of it: it resolves a runner in
  order (`uvx`, then `pipx`, then `python3 -m scovant_core`), each pinned
  to the exact npm package version, and exits 9 when none is usable. The
  package's own `src/scovant_core/__main__.py` was added so the third
  fallback (`python3 -m scovant_core`) actually works. Published to npm
  from a tag-triggered `publish_npm` job that runs only after the PyPI
  `release` job succeeds, behind its own reviewer-gated environment; it
  does not use `--provenance` — npm cannot attest provenance from a
  private source repository — and that limitation is documented in the
  runbook and the npm README. The `python3 -m scovant_core` fallback is the
  one path that cannot pin the version, so the launcher compares the
  version that interpreter reports with its own and warns on stderr,
  naming both, before running it — it never substitutes an engine version
  silently. A probe killed by its own timeout is reported as a timeout
  (with `SCOVANT_NPM_PROBE_TIMEOUT_MS` to raise the budget), never as a
  missing tool, and the published tarball carries the Apache-2.0 licence
  text.
- `docs/example-report.md` — a full example report rendered from the
  `commerce-good` golden fixture via `python -m scovant_core.docs
  --example`, generated rather than hand-written, and pinned by a test
  so it can never drift from the renderer or the fixture.

### Changed
- A verdict drawn from a document the fetch layer cut off at its per-kind
  byte cap now declares that partial read wherever it happens, not only on
  the four robots.txt-derived checks (`CORE-ACCESS-002`, `-003`, `-004`,
  `-010`) that used to be the whole contract. The truncation flag travels
  from the fetch layer through every body-reading gatherer to the checks:
  such a finding records `"truncated": true` in its evidence, caps its
  confidence at `medium`, and says so in its summary — on every branch,
  including a `FAIL`, since a partial read can invert a verdict in either
  direction. 41 of the 45 checks participate; the remaining four
  (`CORE-ACCESS-001`, `CORE-OPERABILITY-002`, `-003`, `-004`) are audited
  exemptions whose verdict is drawn from status codes, response headers, or
  the redirect chain — data a byte cap cannot affect. Truncation does not
  change a verdict: the same site scans to the same statuses and the same
  score whether a document was read in full or cut off, which a parity test
  asserts directly, and the set of checks carrying the flag is pinned so the
  coverage cannot shrink unnoticed. (The one status change on this release
  is separate and deliberate — see the JSON-probe entry below.) Three
  further tests make the contract structural rather than a convention — one
  enumerates the gatherers, one enumerates the checks, and one walks every
  individual verdict branch of every participating check, so a check that
  declares on one branch and stays silent on another fails rather than
  passing on the strength of its other branches.
  `docs/methodology.md` and `docs/security.md` describe the wider
  contract; reports produced before it are identified by
  `provenance.core_version` / `core_version`.
- The shared JSON probe used to answer "truncated" and "not valid JSON"
  identically, so an oversized document was reported as ABSENT. It now
  distinguishes the two, and `CORE-INTERFACE-001` (MCP discovery presence)
  reports `ERROR` for an MCP server card it could not read in full instead
  of claiming the card is not there. **This is the one status change in this
  release, and it can move a report's outcome.** An `ERROR` counts toward a
  category's applicable weight, so a site whose only unreadable document is
  an oversized server card can now fall below the evidence-coverage floor
  and be reported as `INSUFFICIENT_EVIDENCE` rather than scored. That is the
  intended trade: a document we could not read is not a document that is
  absent, and reporting "no MCP discovery file is published" about a file we
  never finished reading is the over-claim this release exists to remove.
  It cannot fire on a genuinely absent document — a real 404 still yields a
  confirmed absence, which a test pins alongside the `ERROR` case.
- `CORE-OPERABILITY-005` states a token estimate taken from a truncated
  page as a floor ("at least N tokens"), so a partial read can no longer
  read as a measurement that came in under the threshold. The cost band
  follows the sentence: on a partial read the finding's evidence reports
  `level: null` with `level_at_least` naming the band, instead of asserting
  a below-threshold classification the floor cannot support.

### Fixed
- Every report format (Markdown, HTML, and text) now accounts for every
  check it counts: the header/summary line counts all 45 checks, but
  experimental `N/A` findings appeared in no section of the body, so the
  arithmetic did not reconcile (37 PASS + 8 N/A with only 5 N/A listed).
  They are now listed as bare ids — in the "Experimental (not scored)"
  section for Markdown and HTML, and on the same compact "N/A: ..." line
  for text. Statuses, scoring and applicability are unchanged — this is a
  rendering fix.
- `cli.py`'s `_PROFILES` is now imported from `scovant_core.profiles`
  instead of a second, hand-duplicated tuple.
