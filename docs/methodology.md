# Methodology

This document explains what Scovant Core measures, how its rating is
computed, and — just as importantly — what it does not tell you.

**Core's one rating is Technical Readiness** (`readiness.technical`), the
open R2 model documented in [`r2.md`](r2.md). It is the number every report
leads with and the one `--min-score` and `--require-canonical` gate on. The
checks described below are diagnostics: each reports its own verdict and
evidence, and none of them carries a weight (see "Before 0.19.0" for the
five-domain score they used to feed).

## What Core measures

Scovant Core is a passive, static scanner. Every check evaluates evidence
the site already exposes on request: HTTP responses, `robots.txt`,
sitemaps, `llms.txt`, structured data (JSON-LD, Open Graph, meta tags),
declared agent-interface discovery files (MCP, WebMCP, OpenAPI), and basic
page structure. All of it is fetched by an ordinary, honestly-identified
HTTP client (`ScovantCore/<version>`) making a small, capped number of
requests. See `docs/checks.md` for the full check catalog.

Every scan produces one `Report` model; four equivalent output formats are
rendered from it — `text` (human-readable terminal output, the default),
`json` (versioned, machine-readable, for CI pipelines and the MCP server),
`markdown` (GitHub-flavored, for pasting into a PR or issue), and `html`
(one self-contained document, no external resources, no JavaScript). All
four carry the same rating, findings, and evidence — only the presentation
differs. See the README's "JSON, Markdown and HTML output" section for
examples.

**HTTP 200 is not success.** Core probes one path that cannot exist and
expects a real 404 (CORE-OPERABILITY-008), requires a `Retry-After` on any
429 it happens to observe (-009), and treats a bot-challenge page served
with HTTP 200 as a defect (-010) — the three clauses of AgentReady v1.0's
`AR-READ-02`.

## What Core does not measure

Core never opens a browser, never executes JavaScript, never authenticates,
never submits a form, and never observes how a real AI agent — or a bot
firewall's treatment of one — actually behaves against the site. Declaring
a policy and enforcing it consistently are two different things; Core can
only see the former. Concretely, out of scope for Core:

- Observed WAF/bot-firewall access (a declared robots.txt allow-rule says
  nothing about whether the request is actually admitted)
- Real agent task completion (browsing, filling a form, completing a
  purchase)
- MCP tool execution (Core only checks that a discovery file or server
  card is published; it never performs the `initialize` handshake and
  never calls a tool)
- WebMCP state parity (whether an in-browser tool registration is
  correct at runtime)
- Multi-model reliability (how different LLM agents actually behave on the
  site)
- Regression stability over time (Core reports one point-in-time scan)

> A high Technical Readiness rating does not prove that autonomous agents can complete real
> workflows on the site.

Scovant Cloud is the paid product that measures the items above by running
real browser-based agents against the live site. See `docs/core-vs-cloud.md`.

## The status model

Every check returns exactly one status:

| Status | Meaning |
|---|---|
| `PASS` | Evidence satisfies the documented deterministic criterion. |
| `WARN` | The feature exists but is incomplete, ambiguous, stale, or weak. |
| `FAIL` | The feature is expected/applicable and deterministic evidence shows a meaningful issue. |
| `N/A` | The check does not apply to the resolved profile, or the thing being checked is genuinely absent by a real, meaningful response (an optional feature that simply isn't present is not itself a defect). |
| `ERROR` | Core could not safely or reliably evaluate the check (a fetch failed, a response could not be parsed). |

**`N/A` vs. `ERROR`:** a document or page that *should* have been readable
but could not be — a fetch failure, a 5xx, an unparseable body — is
`ERROR`: a data-quality gap, reported as such and counted in the report's
`error_count`. Technical Readiness treats the same gap the same way — a
rule whose input could not be read is `NOT_MEASURED` and lowers coverage,
so a site that is genuinely unreachable ends `INSUFFICIENT_EVIDENCE` rather
than being rated on whatever few rules happened to still evaluate (see
[`r2.md`](r2.md)). `N/A` means there
was nothing to evaluate in the first place — the check does not apply to
this profile, or the thing being checked is optional and a real response
confirmed its absence. `ERROR` must never silently become `FAIL`, and
absence must never be scored as a defect when the check documents it as
optional. Several optional agent-facing protocols (MCP, WebMCP, UCP,
llms.txt, OpenAPI, OAuth discovery, Content-Signal, security.txt) are
additionally surfaced as a separate `present`/`absent`/`invalid`/`not_checked`
"Capabilities detected" summary derived from these same findings — it is
purely descriptive, reported alongside the rating, and never itself enters it.

**The document-status rule:** every check that fetches a single well-known
document (robots.txt, a sitemap, llms.txt, an MCP/OpenAPI/OAuth/UCP/
security.txt discovery file) classifies that fetch through one shared rule.
A fetch that never got an HTTP response at all (DNS, connect, timeout) is
`ERROR`. A real `404`/`410` is `N/A` — genuinely absent, not a defect. A
`200` response whose body is actually an HTML catch-all page (a soft-404
template, not the requested document) is also `N/A`, since that document
was never really published. Any other non-`200` status — a 5xx, a 401/403
auth wall, an unexpected redirect target — is `ERROR`: the document could
not be read, which is a data-quality gap, not a confirmed absence. A clean
`200` proceeds to the check's own PASS/WARN/FAIL logic. A few checks whose
own product semantics treat confirmed absence as a meaningful, non-`N/A`
finding (e.g. a missing sitemap on a commerce site) apply only this rule's
`ERROR` verdict and keep their own absence handling.

## Confidence

Each result also carries a confidence level — `high`, `medium`, or `low` —
independent of severity. Confidence reflects how directly the evidence
supports the verdict (e.g. a check that degraded to `ERROR` carries low
confidence); severity reflects how much a `FAIL`/`WARN` should matter.
Core prefers deterministic evidence and avoids LLM-based classification in
this version.

## Truncated documents

Every fetch is capped at a per-document-kind byte limit (1 MiB for
robots.txt — see `docs/security.md`). A document larger than its cap is
parsed from the bytes that were read, so anything it declares past the cap
is invisible to the scan. That is degraded evidence, not a site defect, and
Core never publishes it as a full read:

- the finding's evidence carries `"truncated": true`,
- its confidence is capped at `medium`,
- its summary says the body "was read only in part, so anything past the
  cap is not reflected in this verdict" — or, for a check that draws its
  verdict from one named document, the named form, e.g. "The robots.txt body
  exceeded the fetch size cap and was read only in part, so anything past
  the cap is not reflected in this verdict" — on every verdict, including a
  `FAIL`, since a truncated read can invert a verdict in either direction.
  A verdict drawn from several documents at once (or from one signal folded
  across a document and its children) uses the unnamed form: naming one of
  them would claim a specific document had been cut when a different one had.

**What the flag's absence means.** The key is written only when a body
really was cut off; an always-present `"truncated": false` would carry no
information. Every check that draws a verdict from a document body
participates, on every branch of that verdict — including a branch that
reports the document's content as absent, which is precisely the verdict a
partial read can invert: on those findings, an absent key means the
document the verdict was drawn from was read in full. A verdict established
without reading a body writes no flag either way — a real 404 or a probe
that found nothing to read, a check that reads only status codes, headers
or redirect chains, or a claim about which pages were sampled rather than
about what they contain. Where such a verdict does depend on a document one
step upstream (an oversized sitemap can shrink the set of pages sampled),
the disclosure is carried by the check that reads that document. Some
checks are restricted to a subset of site profiles and simply do not run
for a given site; that is a profile decision, not a truncation signal.

Reports produced before this contract existed are identified by
`provenance.core_version` / `core_version` in the report payload; the flag
carries its stated meaning from the version that introduced it onward.

## Technical Readiness

Technical Readiness is computed by the open R2 model over the evidence Core
gathers — its rules, categories, weights, coverage floor, statuses and
grades are documented in [`r2.md`](r2.md) and identified in every report by
`readiness.technical.model_id`. The checks below do not feed it: a check and
a readiness rule may read the same signal (the curated
[`crosswalk.md`](crosswalk.md) says which), but each check's verdict stands
on its own.

## Check catalog

Ruleset 2026.10 ships 68 checks: 50 readiness checks (7 of them
`experimental`; see `docs/checks.md`) and 18 security checks (10
experimental) that are never rated — see `docs/security.md`. The
readiness checks fall into five themes:

| Theme | Checks |
|---|---:|
| Access & Discovery | 11 |
| Machine Understanding | 12 |
| Agent Interfaces | 9 |
| Trust & Commerce | 7 |
| Operability & Efficiency | 11 |

Several Machine Understanding and Trust & Commerce checks are
profile-restricted (e.g. Product/Offer/identifier checks apply only to the
`commerce` profile), so a given scan's applicable set within a theme is
usually smaller than the table above. Read each finding with its evidence
in the JSON report, not as a broad measurement of its whole theme.

## Experimental checks: measure first, promote later

A check ships experimental when its signal is real but its *calibration* is
not yet defensible — an emerging protocol whose shape is still moving, or a
heuristic whose false-positive rate has not been measured on a real corpus.
Experimental findings are reported in their own block, apart from the
established checks; `--experimental` also runs the experimental-only
gatherers and ranks those findings with the rest (the scan's scope is then
`CUSTOM`). No check moves Technical Readiness, experimental or not.
Presenting a signal we cannot yet defend as established would be worse than
not measuring it.

Every experimental check publishes four fields in
[`checks.md`](checks.md), on a `**Status:**` line under its description:

| Field | Meaning |
|---|---|
| status | `experimental` — reported in its own block; `--experimental` ranks it with the rest. |
| scored | Always `no` (since 0.19.0 no check carries a score). |
| reason | Why the check exists at all — the signal it claims to measure. |
| promotion criteria | What it would take to promote this check out of experimental — written per check, in `CoreCheck.promotion_criteria`. |

What running a check as experimental buys is the same for all of them: a distribution
of the signal across real sites, and the false positives that distribution
exposes.

The per-check promotion criteria are specific, but all of them are instances
of the same five general requirements:

1. **Sufficient corpus.** Enough canonical scans of sites where the check
   actually applies to know the signal's real distribution, not an anecdote.
2. **False-positive review.** Each heuristic reviewed against sites it flags,
   so a known false-positive class is fixed or documented before it can
   mislead anyone.
3. **Documented causal relationship.** A stated, defensible link between the
   signal and agent behaviour — not "this looks like it should matter".
4. **Stable semantics.** The thing being measured no longer changes shape
   underneath the check (for emerging protocols: a settled, versioned
   specification).
5. **Versioned change.** Promotion lands in its own calibrated change that
   moves the check out of experimental and bumps `RULESET_VERSION`, because
   reports before and after are not comparable.

A check that cannot meet these is not promoted. Staying experimental
indefinitely, or being removed, are both acceptable outcomes; quietly
promoting it is not.

## Security signals are reported, not scored

The `CORE-SECURITY-*` checks (category "Agentic Security & Trust") sit
outside Technical Readiness entirely — by construction, not by convention.
No readiness rule reads a security finding, and excluding them
(`--exclude security`) changes nothing about Technical Readiness, its
per-rule outcomes, or any readiness finding's own verdict — this is what
`tests/test_security_is_score_neutral.py` proves on every fixture, on every
commit. A SECURITY check that ERRORs (a security-only probe that could not
be read at all) is neutral in the same way: it never degrades Technical
Readiness, its coverage, or its grade. The report still counts it, as
`error_count` (total) and `security_error_count` (the security slice of it). Full
boundary, label semantics, and standards mapping: `docs/security.md`.

Every SECURITY finding carries two axes a readiness finding does not:

- **`family_id`** — which identity/attack surface it belongs to (`SEC-WEB-*`
  web-security-header checks, `SEC-TXT-*` security.txt, `MACHINE-DATA-*`
  data exposure in machine-facing surfaces, `PROMPT-SURFACE-*` prompt-
  injection-shaped content) — what a reader groups findings by, independent
  of check-id ordering.
- **`verification_mode`** — how the evidence was obtained. Scovant's
  security design defines four canonical modes; Scovant Core, being passive-only, emits
  exactly two of them:

  | Mode | Meaning | Core emits it? |
  |---|---|---|
  | `DECLARED` | Derived from configuration/metadata only (e.g. a `security.txt` file exists; a tool description declares an override). | yes |
  | `PASSIVE_OBSERVED` | Observed from normal requests without mutating state (e.g. an HSTS header on the entry response). | yes |
  | `ACTIVE_SAFE` | Safe, bounded active probing against a real agent/tool. | no — requires authenticated/live testing, out of Core's passive boundary |
  | `SYNTHETIC_AUTHORIZED` | Synthetic test data run under explicit customer authorization. | no — requires a `VERIFIED_SECURITY` execution mode Core does not implement |

## How Scovant Core validates new checks

Every check — experimental or established — goes through the same seven steps:

1. **Proposed check.** A stated claim about what evidence means, with the
   limitation of a passive scanner written down first.
2. **Controlled positive fixtures.** Fixtures where the condition is
   unambiguously present, so a PASS/FAIL verdict has a known right answer.
3. **Controlled negative fixtures.** Fixtures that look like the condition
   but are not it — the ones that catch a check firing on the wrong
   evidence.
4. **Real-site corpus.** The check is run across real sites to see what the
   signal's distribution actually is, rather than what the fixtures suggest.
5. **False-positive review.** Flagged sites are inspected by hand; each
   false-positive class is either fixed or written into the check's
   `limitations`.
6. **Experimental period.** The check ships visible, in its own report
   block, gathering evidence against the promotion criteria above.
7. **Promotion.** A dedicated, calibrated change moves the check out of
   experimental and bumps `RULESET_VERSION`.

[`fixtures/http-semantics/`](../fixtures/http-semantics) is the worked
example of steps 2 and 3: alongside the positive cases (a real soft-404, a
bot challenge, a maintenance page, a `429` with and without `Retry-After`)
it carries the near-misses that must *not* be flagged as the same thing — an
SPA shell that is not a soft-404, a genuine `404`, a normal login page, a
cookie-consent interstitial, and a sensor-only page that carries a
fingerprinting script but no refusal text.

## Contributed measurements

Scovant Core can optionally contribute a scan result to the community index
(`--contribute`, off by default; see the README for the exact payload).
Those results are treated as unverified discovery signals only.
Client-provided scores are never incorporated directly into authoritative Scovant research datasets
— a contributed domain is independently re-evaluated by Scovant-controlled
infrastructure before inclusion. A
contribution tells us *where to look*; it is never itself the measurement
that gets published.

## Scan scope

Every report carries `provenance.scan_scope`, a property of the
**selection** alone:

| Scope | Meaning |
|---|---|
| `CANONICAL` | The default check selection (no `--include`/`--exclude`/`--experimental`). |
| `CUSTOM` | `--include`/`--exclude`/`--experimental` narrowed or widened the run; reports say "Scope: CUSTOM (subset of checks)". |

Evidence quality is not a scope: it is Technical Readiness's own `status`
(`OK`, `DEGRADED`, `INSUFFICIENT_EVIDENCE` — see [`r2.md`](r2.md)). A full
selection whose checks errored is still `CANONICAL`; read its Technical
status to see how far the evidence can be trusted. `--require-canonical`
requires Technical Readiness status `OK`. `--contribute` sends only a
`CANONICAL` report whose Technical Readiness status is `OK` — otherwise the
CLI prints `contributed: skipped (…)` with the reason instead of posting.

## Profiles

Some checks only apply to a specific site archetype. Core resolves one of
`content`, `commerce`, `saas`, or `api` for every scan (`auto` is the
resolution mode, not a profile itself) — see `docs/profiles.md` for the
exact deterministic resolution rules. A check outside the resolved profile
returns `N/A`, not `FAIL`.

## Determinism

Given the same fetched evidence, the same check versions, and the same R2
model, a scan produces byte-identical output (`report.provenance` aside,
which records genuinely environment-dependent facts like the Python
interpreter). There is no LLM in the rating path. The package's golden
tests (`tests/test_golden.py`) pin this for every fixture site.

## Versioning

A report carries these independent version fields:

- `core_version` — the installed `scovant-core` package version (semver).
- `ruleset_version` — the calendar-stamped version of the check set itself
  (e.g. `2026.10`), combined with a content digest (`ruleset_digest()`,
  hashing every check id and its own version) so any change to what is
  checked is detectable even within the same calendar version string.
  Before 0.19.0 the digest also hashed the five-domain scoring constants;
  dropping them changed it once (`7f440d6205c3` → `e7426fb13abe`) with
  `ruleset_version` unchanged.
- `readiness.technical.model_id` — the Technical Readiness model (rules and
  policy); any change to how the rating is computed mints a new id.
- `schema_version` — the JSON report schema version.

Ratings are only meaningfully comparable across two scans when their
`model_id` matches, and check verdicts when their `ruleset_version` (and
digest) match. A report whose model or ruleset changed between two scans of
the same site should be read as "the measurement changed," not "the site
changed."

## Report schema

The JSON report (`--format json`) has a published, machine-readable schema
at [`docs/report.schema.json`](report.schema.json) (JSON Schema draft
2020-12). It is generated, never hand-written — `python -m
scovant_core.schema` renders it straight from the pydantic `Report` model
(`scovant_core.schema.report_schema()`), and `tests/test_schema.py` fails CI
if the committed file and the generator ever disagree.

Run it as `python -m scovant_core.schema --stdout` to print the schema; that
works from an installed package. The bare form rewrites the repository's
committed `docs/report.schema.json` and therefore needs a git checkout of
`scovant-core` — from an installed wheel there is no `docs/` directory to
write to, and the command says so instead of failing obscurely.

Bump policy: adding a key to the report is not a breaking change and does
not bump `schema_version`. A minor bump marks a deprecation: 1.2 marked the
five-domain `score` deprecated (`score.deprecated`, `score.replaced_by`),
and 2.0 removed it. Removing or retyping an existing field is breaking and
bumps the major version — the schema deliberately allows additional
properties at the top level so additive changes never require a consumer
update.

## Before 0.19.0

Until 0.18.x Core also computed a five-domain score from the checks
themselves (the "Static Signal Score": a per-check local weight, five
weighted categories, its own coverage floors and a `PARTIAL` scope for an
errored full scan). 0.18.0 made Technical Readiness the headline and
deprecated it (report schema 1.2, `--legacy-score`); 0.19.0 removed it
(report schema 2.0) together with every per-check weight. Older reports
are identified by `schema_version` and `core_version`.

## Limitations

Core samples a bounded number of pages (`--max-pages`, default 5) and a
capped set of declared references per site; it never crawls a full site.
Every check's own limitations are documented per-check in `docs/checks.md`.
Core is a signal, not a guarantee — see the disclaimer above.
