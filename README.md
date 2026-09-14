# Scovant Core

## Definition

Scovant Core is an open-source passive scanner for machine-facing website signals used by AI agents. It checks crawler policy, structured data, agent discovery surfaces, protocol metadata, commerce signals and basic operability.

Scovant Core measures what a site declares. Scovant Cloud measures what real agents actually experience.

> A high Core Score does not prove that autonomous agents can complete real workflows on the site.

## 30-second install

```bash
uvx --from scovant-core scovant scan https://example.com   # no install, needs uv
pipx run --spec scovant-core scovant scan https://example.com
pip install scovant-core                                    # Python >= 3.12
npx @scovant/core scan https://example.com                  # Node launcher, needs uv/pipx/python3
```

### Reproducible install

Same Core version does not guarantee the same dependency graph months
later. Each release ships exact pins:

    pip install "scovant-core==0.3.0" -c https://raw.githubusercontent.com/Scovant/scovant-core/v0.3.0/constraints/constraints-0.3.0.txt

Every report records what actually ran (`provenance.dependencies`,
`provenance.environment_digest`).

## Example output

Running `scovant scan https://example.com --experimental` against a
well-instrumented commerce site produces text output shaped like this (real
output, rendered — never from a live scan — from the `commerce-good` test
fixture; a site with nothing to report on the SCORED checks, so "Top
findings" is empty; any FAIL/WARN among those would be listed there). The
`(n/N)` beside each category is how many of that category's applicable
checks were actually evaluated — see `docs/methodology.md` for how the
categories' depth varies. The "Experimental (not scored)" block lists every
experimental check that evaluated to something other than `N/A` on this
scan (including a WARN, as below — experimental findings are still shown,
just never scored), plus a compact "N/A: ..." line naming the experimental
checks that had nothing to evaluate — so every check the header counts is
named somewhere, never merely counted. These never affect the Static Signal
Score; pass `--experimental` to also run the experimental checks gated
behind that flag (omit it and they're skipped entirely, not evaluated as
N/A).

```text
SCOVANT CORE
──────────────────────────────────────────────

Target: https://example.com/
Profile: commerce (auto → commerce, confidence 0.85)
Core version: 0.3.0

Static Signal Score       100 / 100   A
Scope: CANONICAL · Status: OK · Coverage: 100% · Errors: 0

Capabilities detected (descriptive, not scored)
  mcp: present
  webmcp: absent
  ucp: present
  llms_txt: present
  openapi: not_checked
  oauth: not_checked
  content_signal: present
  security_txt: present

AgentReady v1.0 (descriptive, not scored): MUST 3/3 measured — 3 pass · SHOULD 5/12 measured — 5 pass · MAY none measured (0/3)
  Mapping: docs/standards/agentready.md

Access & Discovery        100   (10/10)
Machine Understanding     100   (11/11)
Agent Interfaces          100   (2/2)
Trust & Commerce          100   (7/7)
Operability & Efficiency  100   (7/7)

50 checks
40 PASS
1 WARN
0 FAIL
9 N/A
0 ERROR

Top findings

(none)

Experimental (not scored)
──────────────────────────────────────────────
PASS  CORE-ACCESS-011
      llms.txt links useful same-origin pages and carries no misplaced policy or template text.

PASS  CORE-INTERFACE-008
      A UCP profile is published and valid.

PASS  CORE-MACHINE-012
      The structured price matches a visible price on the page.

WARN  CORE-OPERABILITY-011
      3 of 3 machine surface(s) are not linked from anything an agent reads: llms_txt, mcp, ucp.

N/A: CORE-INTERFACE-004, CORE-INTERFACE-009, CORE-OPERABILITY-007

Not tested by Scovant Core
──────────────────────────────────────────────
Observed WAF access       NOT TESTED
Real agent tasks          NOT TESTED
MCP tool execution        NOT TESTED
WebMCP state parity       NOT TESTED
Multi-model reliability   NOT TESTED
Regression stability      NOT TESTED

Verify with real agents:
https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss
```

## What Core checks

50 deterministic checks across 5 categories (7 of the 50 are experimental —
they run and report but never affect the score; see below):

- **Access & Discovery** (11) — HTTPS reachability, robots.txt, AI crawler
  policy, training-vs-search crawler separation, sitemap availability and
  freshness, canonical URLs, indexability, llms.txt, Content-Signal, and
  (experimental) llms.txt utility (useful links, no misplaced policy text,
  not a template)
- **Machine Understanding** (12) — JSON-LD parseability, Organization and
  WebSite/WebPage entities, Product/Offer structured data, product
  identifier count, breadcrumbs, metadata quality, heading structure,
  language declaration, image alt coverage, and (experimental) visible-vs-
  structured price consistency
- **Agent Interfaces** (9) — MCP discovery and server-declaration quality,
  WebMCP static presence and (experimental) tool-declaration quality,
  OpenAPI discovery, OAuth authorization-server and protected-resource
  metadata, and (experimental) UCP profile validity and agent discovery
  surface presence (A2A cards, AI-plugin manifests, agents.json, Agent
  Skills)
- **Trust & Commerce** (7) — contact/support, shipping, returns/refund,
  privacy, terms, `security.txt`, and pricing discoverability
- **Operability & Efficiency** (11) — server-rendered core content,
  redirect-chain complexity, cache validators, broken machine-consumable
  endpoints, agent parse cost, form/control labels, unknown paths return a
  real 404, rate-limiting (429) is signalled with `Retry-After`, bot-
  challenge pages are not served as HTTP 200, and (experimental,
  `--experimental` only) machine-reference integrity and discovery linkage

### Experimental checks

Seven checks ship `experimental`: they evaluate and appear in every report,
but their weight is excluded from the Static Signal Score until they have
been calibrated against real-world traffic and promoted.

| ID | Title |
|---|---|
| `CORE-ACCESS-011` | llms.txt utility |
| `CORE-INTERFACE-004` | WebMCP tool declaration quality |
| `CORE-INTERFACE-008` | UCP profile validity |
| `CORE-INTERFACE-009` | Agent discovery surface presence |
| `CORE-MACHINE-012` | Visible vs. structured price |
| `CORE-OPERABILITY-007` | Machine reference integrity |
| `CORE-OPERABILITY-011` | Discovery linkage |

`CORE-OPERABILITY-007` is additionally gated on the `--experimental` flag
itself — it is the only check whose gatherer (`reference_integrity`) makes
any network request at all beyond the ordinary scan, so a plain `scovant
scan` never resolves an external package registry or DNS name for it. The
other six evaluate on every scan; they simply never move the score.

See [`docs/checks.md`](docs/checks.md) for the full catalog — every check's
id, weight, applicable profile, and why it matters — generated straight
from the check registry so it can never drift from what the package
actually runs.

## What Core does NOT test

Core is a static, unauthenticated scanner. It never opens a browser and
never observes real traffic, so it cannot tell you:

- Observed WAF/bot-firewall access
- Real agent task completion
- MCP tool execution
- WebMCP state parity (runtime, not just static presence)
- Multi-model reliability
- Regression stability over time

## Standards

Scovant Core maps its checks to **AgentReady v1.0** (<https://agentready.org/>, MIT), the open
baseline standard for agent-facing website signals. AgentReady defines requirements, not weights;
Core reports which requirements its checks measure (`metrics.standards.agentready_v1` in every
report) and never reproduces any third-party score. Mapping: `docs/standards/agentready.md`.

## Core vs Cloud

Scovant Core measures passive, machine-facing signals. Scovant Cloud verifies how real agents actually behave, across providers, browser runtimes, security layers and time.

See [`docs/core-vs-cloud.md`](docs/core-vs-cloud.md) for the full capability
matrix and concrete "Core can determine / cannot determine / Cloud can
test" examples, and [scovant.com/open-source](https://scovant.com/open-source)
for the same comparison as a live, always-current page.

## GitHub Action

```yaml
- uses: Scovant/scovant-core@v0
  id: scan
  with:
    url: https://staging.example.com
    min-core-score: '70'
    fail-on: fail
    allow-private-networks: 'true'
    trusted-target: 'true'
```

`@v0` is the moving major tag while the package is pre-1.0 — see
[`docs/releasing.md`](docs/releasing.md); pin `@v0.3.0` instead for an
exact, never-moving version. `allow-private-networks` is what makes this
example work against a private CI runner scanning its own not-yet-public
staging host — see "Free boundary" below.

The action installs itself from the checked-out ref (`pip install
"$GITHUB_ACTION_PATH"` — no PyPI dependency, no version skew between the
tag you pinned and the code that runs), scans one URL, writes a Markdown
summary to the job's Step Summary, uploads the full report (HTML by
default) as a workflow artifact named `scovant-core-report`, and fails the
step when the gate you configured trips.

### Inputs

| Input | Description | Default |
|---|---|---|
| `url` | Entry URL to scan | *(required)* |
| `profile` | `auto`\|`content`\|`commerce`\|`saas`\|`api` | `auto` |
| `min-core-score` | Fail the step below this score (empty = no gate) | `''` |
| `fail-on` | `never`\|`fail`\|`warn` | `never` |
| `experimental` | Score experimental checks too | `false` |
| `timeout` | Total scan budget in seconds | `60` |
| `report-format` | `html`\|`markdown` — the uploaded artifact | `html` |
| `allow-private-networks` | Allow private/loopback targets (your own staging) | `false` |
| `trusted-target` | Required (`true`) when `allow-private-networks` is `true`; never honoured for pull requests from forks | `false` |
| `require-canonical` | Fail the step unless the scan is CANONICAL with score status OK | `false` |

### Outputs

| Output | Description |
|---|---|
| `score` | Static Signal Score (0-100, empty if unmeasured) |
| `grade` | Letter grade (empty if unmeasured) |
| `pass_count` | Number of PASS findings |
| `warn_count` | Number of WARN findings |
| `fail_count` | Number of FAIL findings |
| `report_path` | Path to the uploaded report file on the runner |
| `coverage` | Evidence coverage ratio (0.0-1.0) |
| `score_status` | `OK`\|`DEGRADED`\|`NOT_CANONICAL`\|`INSUFFICIENT_EVIDENCE` |
| `scan_scope` | `CANONICAL`\|`CUSTOM`\|`PARTIAL` |
| `error_count` | Number of checks that errored |

### Scanning private networks

> **WARNING:** Never derive the target URL from untrusted PR input when
> `allow-private-networks: true`. On a self-hosted runner that combination
> turns the scanner into an internal-network probe.

`allow-private-networks: true` is honoured only together with
`trusted-target: true`, and never for pull requests from forks — the
action exits 2 otherwise. A pull request whose head repository is unknown
(for example, a deleted fork) is treated as a fork. Take the URL from a
repository variable, not from the event:

    with:
      url: ${{ vars.STAGING_URL }}
      allow-private-networks: 'true'
      trusted-target: 'true'

### Free boundary

One URL, one run, no state, no comparison across runs, no schedule, no
outgoing notification. For history, regression detection, real-agent
simulation, and CI-triggered re-scans across your whole site, see
[Scovant Monitor](https://scovant.com/pricing?utm_source=scovant-core&utm_medium=github&utm_campaign=oss).

## JSON, Markdown and HTML output

```bash
scovant scan https://example.com --format json
```

produces a versioned JSON report (`schema_version`, `core_version`,
`ruleset_version`, per-category scores, every finding with its own
evidence) suitable for CI pipelines, matching the published
[`docs/report.schema.json`](docs/report.schema.json). Combine with
`--min-score`/`--fail-on` for a CI-friendly exit code, or `--output
report.json` to write it to a file.

```bash
scovant scan https://example.com --format markdown --output report.md
```

renders the same report as GitHub-flavored Markdown — score, per-category
table, findings grouped by status with collapsible evidence — ready to
paste into a pull request or issue.

```bash
scovant scan https://example.com --format html --output report.html
```

renders the same report as one self-contained HTML document (inline CSS,
no external resources, no JavaScript) — open it directly in a browser or
attach it as a CI artifact.

## MCP

```bash
pip install "scovant-core[mcp]"
scovant mcp
```

starts a stdio MCP server so an agent host (Claude Desktop, Cursor, or any
MCP client) can run Scovant Core's passive scan as a tool call instead of a
shell command. Claude Desktop (`claude_desktop_config.json`) and Cursor
(`.cursor/mcp.json` or Settings → MCP) both take the same config:

```json
{
  "mcpServers": {
    "scovant-core": {
      "command": "scovant",
      "args": ["mcp"]
    }
  }
}
```

| Tool | Description |
| --- | --- |
| `scan_site` | Run all 50 checks against one public URL, return the JSON report |
| `get_core_score` | Run the scan, return only the Static Signal Score summary |
| `list_checks` | List every check with category, weight, profiles, experimental flag |
| `explain_check` | Explain one check: why it matters, limitations, Cloud extension, references |
| `get_finding` | Return one finding from a scan this server already ran (no re-scan) |

Every tool is passive/static only — the same evidence gathering `scovant
scan` does (public documents: robots.txt, sitemaps, llms.txt, JSON-LD,
MCP/OAuth/UCP discovery files), never a browser, never an MCP `tools/call`,
never authentication. The server runs one scan at a time and keeps only the
last 8 reports in memory for `get_finding` to read back.

## Methodology

Full scoring methodology, the status/confidence model, the coverage floor,
and rule versioning: [`docs/methodology.md`](docs/methodology.md).

## Security

Scovant Core fetches arbitrary public URLs; see
[`docs/security.md`](docs/security.md) for the network safety model
(scheme allow-list, SSRF guard, redirect/size/timeout limits). Scanning your
own private/staging infrastructure needs an explicit opt-in — see
[`docs/security.md` § Private-network targets (opt-in)](docs/security.md#private-network-targets-opt-in).
To report a vulnerability, see [`SECURITY.md`](SECURITY.md) or email
`security@scovant.com`.

### Community contributions (opt-in)

`--contribute` is off by default. When you pass it, Core sends ONE HTTPS
POST, after the scan finishes, to a single fixed Scovant endpoint — a
measurement of the PUBLIC site you just scanned, for the aggregate,
opt-in community index at
[scovant.com/research](https://scovant.com/research):

```bash
scovant scan https://example.com --contribute
```

What is sent (exactly these fields, nothing else):

- `domain` — the scanned site's hostname (no path, no query string)
- `timestamp` — when the scan completed
- `core_version`, `ruleset_version`, `ruleset_digest` — which Core build and
  checklist produced the result
- `profile` — the resolved site profile (`content`/`commerce`/`saas`/`api`)
- `experimental` — whether experimental checks were included
- `check_statuses` — each check id's status (`PASS`/`WARN`/`FAIL`/`N/A`/`ERROR`)
- `score` — the overall value, grade, coverage and status

What is never sent: no page HTML, no evidence, no URLs beyond the domain
itself, no IP address, no filesystem paths, no CLI flags beyond what's
listed above. The request carries no cookies and never follows a redirect.

`--contribute` is refused (exit 2) together with `--allow-private-networks`
— only a target Core itself already confirmed public gets contributed. A
contribution never changes the CLI's exit code and never fails the scan;
one line on stderr (`contributed: <domain> (accepted|deduplicated|failed:
<reason>)`) reports the outcome. See
[`docs/security.md` § Outbound requests](docs/security.md#outbound-requests)
for the full network contract.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). For how releases are made,
verified, and pinned, see [`docs/releasing.md`](docs/releasing.md).

## License

Apache-2.0. See `LICENSE`.
