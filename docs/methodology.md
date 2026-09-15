# Methodology

This document explains what the Scovant Core Static Signal Score (`Core
Score`) measures, how it is computed, and — just as importantly — what it
does not tell you.

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
four carry the same score, findings, and evidence — only the presentation
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

> A high Core Score does not prove that autonomous agents can complete real
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
`ERROR`. It is excluded from the numeric score but still counts toward the
category's *applicable* weight, so a site that is genuinely unreachable
drops the scan's evidence coverage below the floor rather than being
scored on whatever few checks happened to still evaluate. `N/A` means there
was nothing to evaluate in the first place — the check does not apply to
this profile, or the thing being checked is optional and a real response
confirmed its absence. `ERROR` must never silently become `FAIL`, and
absence must never be scored as a defect when the check documents it as
optional. Several optional agent-facing protocols (MCP, WebMCP, UCP,
llms.txt, OpenAPI, OAuth discovery, Content-Signal, security.txt) are
additionally surfaced as a separate `present`/`absent`/`invalid`/`not_checked`
"Capabilities detected" summary derived from these same findings — it is
purely descriptive, reported alongside the score, and never itself enters it.

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

## Scoring formula

Each check has a local integer weight. Per category, the raw ratio is:

```text
sum(check_weight × status_value) / sum(applicable, evaluated weight)
```

where `status_value` is `PASS=1.0`, `WARN=0.5`, `FAIL=0.0`; `N/A` and
`ERROR` results are excluded from both sums, and so is any `experimental`
check regardless of its status — an experimental check's evidence is still
computed and reported (see `docs/checks.md` for which five checks currently
carry that flag), it is simply never added into a category's weight sums
until it has been calibrated and promoted to non-experimental. This ratio
is kept **unrounded**
through the rest of the computation — only the category score shown in a
report is rounded (to 0.1) for display, because rounding each category
before weighting can flip the overall score's grade band on inputs that sit
near a rounding boundary.

The overall score is the weighted sum of the unrounded category ratios
against the category weights below, **renormalized over only the
categories that actually produced a ratio** — a category whose every check
came back `N/A`/`ERROR` for this scan (zero evaluated weight) drops out of
both the numerator and the weight total entirely, rather than being
averaged in as a 0. The result is rounded to the nearest whole number with
half-up rounding (never Python's banker's rounding, so a `.5` always rounds
up):

| Category | Weight |
|---|---:|
| Access & Discovery | 25 |
| Machine Understanding | 25 |
| Agent Interfaces | 20 |
| Trust & Commerce | 15 |
| Operability & Efficiency | 15 |
| **Total** | **100** |

Minimum evidence coverage: 60%. Below this coverage, no score is emitted (`INSUFFICIENT_EVIDENCE`) instead of scoring on whatever few checks happened to evaluate.

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

## v0.1 category coverage

Ruleset 2026.10 ships 50 checks in total (7 of them `experimental` —
evaluated and reported, but excluded from the score until calibrated and
promoted; see `docs/checks.md`), distributed like this — *checks / summed
local weight* per category, counting experimental checks in both columns:

| Category | Checks / local weight | Category weight |
|---|---|---:|
| Access & Discovery | 11 / 26 | 25 |
| Machine Understanding | 12 / 26 | 25 |
| Agent Interfaces | 9 / 20 | 20 |
| Trust & Commerce | 7 / 15 | 15 |
| Operability & Efficiency | 11 / 23 | 15 |

Every category now carries enough checks that a single verdict rarely
decides the whole category on its own — Trust & Commerce and Operability &
Efficiency, the thinnest in v0.1's first draft (one check each), now carry
seven or more apiece. Several Machine Understanding and Trust & Commerce checks are
profile-restricted (e.g. Product/Offer/identifier checks apply only to the
`commerce` profile), so a given scan's *applicable* set within a category is
usually smaller than its full local-weight total above — the `(n/N)`
coverage the CLI prints beside each category is what tells you how many of
*that scan's* applicable checks actually ran, which is always a better read
than the static table above.

Read a category score together with the `(n/N)` coverage the CLI prints
beside it (`n` checks evaluated of `N` applicable, excluding experimental
checks and any check the resolved profile doesn't apply to) and with the
per-check detail in the JSON report — not as a broad measurement of that
whole theme. The category weights themselves are held stable so scores
stay comparable within a ruleset version.

## Coverage floor

There are two coverage floors, not one:

- **Evidence floor (60%).** A score is only emitted when at least 60% of the
  total applicable check weight was actually evaluated (not `N/A`, not
  `ERROR`). Below that floor, `Score.status` is `INSUFFICIENT_EVIDENCE` and
  `Score.value`/`Score.grade` are both `null` — Core will not present a
  number computed from mostly missing evidence as if it meant something.
  Coverage itself is still reported so a caller can see how far short of
  the floor the scan fell.
- **Canonical floor (85%).** A full-selection scan (no `--include`,
  `--exclude`, or `--experimental`) that clears the 60% evidence floor but
  falls short of 85% coverage, or that hit any `ERROR` check, still gets a
  `value`/`coverage` but no `grade`: `Score.status` is `DEGRADED`. Only a
  full scan at ≥85% coverage with zero errored checks reaches `status: OK`
  and a letter grade.

## Experimental checks: measure first, score later

A check ships experimental when its signal is real but its *calibration* is
not yet defensible — an emerging protocol whose shape is still moving, or a
heuristic whose false-positive rate has not been measured on a real corpus.
Experimental checks run and are reported (`--experimental`), but they are
excluded from the score entirely: they cannot move a value, a grade, or the
coverage denominator. Scoring a signal we cannot yet defend would be worse
than not measuring it.

Every experimental check publishes four fields in
[`checks.md`](checks.md), on a `**Status:**` line under its description:

| Field | Meaning |
|---|---|
| status | `experimental` — visible in reports, gated behind `--experimental`. |
| scored | Always `no` while experimental. |
| reason | Why the check exists at all — the signal it claims to measure. |
| promotion criteria | What it would take to make this check scored — written per check, in `CoreCheck.promotion_criteria`. |

What running a check unscored buys is the same for all of them: a distribution
of the signal across real sites, and the false positives that distribution
exposes.

The per-check promotion criteria are specific, but all of them are instances
of the same five general requirements:

1. **Sufficient corpus.** Enough canonical scans of sites where the check
   actually applies to know the signal's real distribution, not an anecdote.
2. **False-positive review.** Each heuristic reviewed against sites it flags,
   so a known false-positive class is fixed or documented before it can cost
   anyone points.
3. **Documented causal relationship.** A stated, defensible link between the
   signal and agent behaviour — not "this looks like it should matter".
4. **Stable semantics.** The thing being measured no longer changes shape
   underneath the check (for emerging protocols: a settled, versioned
   specification).
5. **Versioned scoring impact.** Promotion lands in its own calibrated change
   that assigns the weight and bumps `RULESET_VERSION`, because scores before
   and after are not comparable.

A check that cannot meet these is not promoted. Staying experimental
indefinitely, or being removed, are both acceptable outcomes; quietly
scoring it is not.

## How Scovant Core validates new checks

Every check — experimental or scored — goes through the same seven steps:

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
6. **Experimental (unscored) period.** The check ships visible but excluded
   from the score, gathering evidence against the promotion criteria above.
7. **Promotion to a scored rule.** A dedicated, calibrated change assigns the
   weight and bumps `RULESET_VERSION`.

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

## Scan scope and score status

Every report carries `Score.scope` (a property of the **selection**) and
`Score.status` (a property of the **resulting score**):

| Scope | Meaning | Status | Grade |
|---|---|---|---|
| `CANONICAL` | Full check selection (no `--include`/`--exclude`/`--experimental`), coverage ≥ 85%, zero `ERROR`ed checks | `OK` | Yes |
| `PARTIAL` | Full check selection, but coverage < 85% or any check `ERROR`ed (and coverage still ≥ 60%) | `DEGRADED` | No |
| `PARTIAL` or `CUSTOM` | Coverage < 60% (evidence floor) | `INSUFFICIENT_EVIDENCE` | No |
| `CUSTOM` | `--include`/`--exclude`/`--experimental` narrowed or widened the run (and coverage ≥ 60%) | `NOT_CANONICAL` | No |

A `CUSTOM` scan reports a **Subset Diagnostic Score** rather than the
Scovant Core Static Signal Score, and the CLI prints "Canonical Core Score:
NOT CALCULATED" instead of a value — a subset score is useful for local
debugging of a specific check, but it is not comparable across sites or
over time the way a canonical score is. Use `--require-canonical` to make a
CI job fail fast when a scan is accidentally scoped down. `--contribute`
refuses to send anything but a `CANONICAL`-scope report — the CLI prints
`contributed: skipped (scan is CUSTOM; only canonical scans are accepted)`
instead of posting.

## Profiles

Some checks only apply to a specific site archetype. Core resolves one of
`content`, `commerce`, `saas`, or `api` for every scan (`auto` is the
resolution mode, not a profile itself) — see `docs/profiles.md` for the
exact deterministic resolution rules. A check outside the resolved profile
returns `N/A`, not `FAIL`.

## Determinism

Given the same fetched evidence, the same check version, and the same
scoring constants, a scan produces byte-identical output (`report.provenance`
aside, which records genuinely environment-dependent facts like the Python
interpreter). There is no LLM in the scoring path. The package's golden
tests (`tests/test_golden.py`) pin this for four canonical fixture sites.

## Versioning

A report carries three independent version fields:

- `core_version` — the installed `scovant-core` package version (semver).
- `ruleset_version` — the calendar-stamped version of the check set itself
  (e.g. `2026.09`), combined with a content digest (`ruleset_digest()`,
  hashing every check id, its own version, and the scoring constants) so
  any change to what is measured or how it is weighted is detectable even
  within the same calendar version string.
- `schema_version` — the JSON report schema version.

Scores are only meaningfully comparable across two scans when their
`ruleset_version` (and digest) match. A report whose ruleset changed
between two scans of the same site should be read as "the measurement
changed," not "the site changed."

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
not bump `schema_version`. Removing or retyping an existing field is
breaking and bumps it — the schema deliberately allows additional
properties at the top level so additive changes never require a consumer
update.

## Limitations

Core samples a bounded number of pages (`--max-pages`, default 5) and a
capped set of declared references per site; it never crawls a full site.
Every check's own limitations are documented per-check in `docs/checks.md`.
Core is a signal, not a guarantee — see the disclaimer above.
