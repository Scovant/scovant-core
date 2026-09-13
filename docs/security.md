# Security model

Scovant Core fetches arbitrary, user-supplied public URLs, so its network
layer (`security/client.py`, `security/policy.py`, `security/url_safety.py`)
is treated as a release gate, not an afterthought. This document describes
what it actually does; see `SECURITY.md` for how to report a vulnerability.

## Scheme allow-list

Only `http` and `https` are accepted. Every other scheme
(`file:`, `ftp:`, `gopher:`, `data:`, `javascript:`, `unix:`, ...) is
rejected before any network call is made.

## Blocked address ranges

Before connecting, and again on every redirect hop, the target host is
checked against the private/reserved ranges below. A literal IP is checked
directly; a hostname is resolved via DNS and **every** returned A/AAAA
record is checked — a hostname that resolves to even one blocked address is
refused.

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
169.254.0.0/16
0.0.0.0/8
100.64.0.0/10       (carrier-grade NAT)
::1/128
fc00::/7
fe80::/10
```

plus any address Python's `ipaddress` module classifies as private,
loopback, link-local, reserved, multicast, or unspecified — a superset that
also covers cloud-metadata-style addresses without hand-maintaining a
separate list.

## Private-network targets (opt-in)

By default the block above applies unconditionally — Core refuses to scan
your own staging environment or an intranet service just as it refuses
anyone else's. `--allow-private-networks` on the CLI (or
`ScanOptions(allow_private_networks=True)` when calling the library
directly; the GitHub Action's `allow-private-networks` input maps to the
same flag) is the documented way to lift that specific block when the
target genuinely is private and genuinely is yours.

**What it lifts:** the private/loopback/link-local address check, and ONLY
for the hostname you named as the scan target. `engine.scan` resolves the
entry URL's hostname once, lower-cases it, and passes it as the sole member
of `SecurityPolicy.private_hosts`; `SecureClient`'s per-request guard
(structural pre-check and the resolved-address event-hook alike) skips the
address block for a request only when that request's own host is in
`private_hosts` — every other host stays fully guarded, checked exactly as
it would be with the flag off. Concretely: a redirect hop that lands on a
*different* host (private or not), and any link the scan discovers mid-run
on another host (a sitemap URL, a policy page, a well-known document, ...),
is still blocked if it resolves to a private/loopback/link-local address —
including the classic cloud-metadata address (`169.254.169.254`) reached via
a redirect from an allowed target. See `tests/test_private_networks.py` for
the verified behaviour.

**What stays on, unconditionally:** the scheme allow-list (`ftp://`,
`file://`, etc. are still rejected before any network call), the address
block for every host other than the one you named, the redirect hop cap and
body-never-read-until-final behaviour, the per-`kind` response size caps,
and the connect/request/total-scan-budget timeouts.

**Who should use it:** yourself, against infrastructure you control — a
staging host, an internal service, a CI-only loopback fixture server. Never
set it against a URL you do not control; doing so knowingly forfeits one
layer of SSRF protection for that scan.

**Reporting:** whenever the flag was used, `report.provenance.allow_private_networks`
is `true` and the text/Markdown/HTML reports print a one-line notice near
the top, so a shared report never silently implies the address block ran
when it didn't.

## Redirect policy

The client drives its own redirect loop rather than relying on the HTTP
library's automatic following, so every hop can be validated:

- Maximum 5 redirect hops; the 6th response is rejected outright.
- Each hop's destination is validated against the scheme allow-list and the
  blocked-range check above before it is followed.
- An intermediate (non-final) redirect response's **body is never read** —
  only its status and `Location` header — so an oversized redirect page
  cannot be downloaded for nothing.
- Cookies are cleared between every hop and after every fetch; nothing is
  forwarded across hops or across separate fetches in the same scan.

## Response size limits

The shared `SecureClient` (`security/client.py`) is the entry point used for
the main entry-page fetch and the primary declared documents; it enforces
the per-`kind` byte caps below while streaming (a response that exceeds its
cap is truncated, not downloaded in full first) and the total scan-budget
deadline described under Timeouts:

| Kind | Limit |
|---|---:|
| HTML | 5 MB |
| robots.txt | 1 MB |
| Sitemap index | 5 MB |
| Individual sitemap | 10 MB |
| JSON (OpenAPI, MCP discovery, ...) | 10 MB |
| Other text | 1 MB |

A handful of secondary, best-effort discovery probes (the sitemap
candidate-path probe, and the MCP server-card probe) issue their GETs
directly against the underlying HTTP client on a tighter, fixed path
instead: a 512 KB response-body cap and a 5-second per-request timeout,
regardless of `kind`. These probes exist to answer a single yes/no
("does this candidate path return something parseable") over a handful of
fixed, low-risk paths, so the smaller, non-configurable cap is intentional
rather than an inconsistency.

## Timeouts

```text
connect timeout        5 seconds  (per request)
request timeout        15 seconds (per request)
total scan budget      60 seconds (per scan, across all requests)
```

The total-budget deadline is checked before every new fetch and, for a
streamed response, again while reading each chunk — a slow response cannot
consume the whole scan's remaining budget just because it hasn't yet timed
out on a per-chunk basis.

## Request budget

Beyond the entry-page fetch and the always-on discovery documents
(robots.txt, sitemap, `llms.txt`), several checks' gatherers issue their own
small, hard-capped batch of GETs. Per scan, worst case:

| Gatherer | Requests | Notes |
|---|---:|---|
| Policy pages (shipping/returns/privacy/terms/pricing) | ≤5 | `MAX_FETCHES` in `gatherers/policy_pages.py`; stops as soon as a candidate link for each kind is found and fetched. |
| `security.txt` | ≤2 | `/.well-known/security.txt` then `/security.txt`. |
| OAuth metadata | 2 | authorization-server metadata, then protected-resource metadata — both fixed well-known paths. |
| UCP profile | 1 | one fixed well-known path. |
| Agent discovery surfaces (A2A, AI-plugin, agents.json, Agent Skills, OpenAPI, OAuth well-known, `llms-full.txt`) | ≤13; ≤10 when all three shared documents (OpenAPI at `/openapi.json`, both OAuth well-knowns) gave a definitive earlier answer | one GET per conventional path in a fixed 13-entry probe table; existence-only, capped at 512 KB and a 5-second timeout each. Three of those 13 paths — the OpenAPI root document and the two OAuth discovery documents — are shared documents this scan already fetched for another purpose (the OpenAPI and OAuth-metadata gatherers above); when that earlier read gave a DEFINITIVE answer (a real 200 + real JSON, or a genuine 404/410, or a soft-200 HTML catch-all), this gatherer records it as-is instead of re-fetching it, so all three drop out of the count. An inconclusive earlier read (a 5xx, 401/403, a crashed gatherer, or any other non-definitive outcome) is never guessed into an answer; that path is re-probed directly instead, which is why the worst case stays at ≤13 rather than a flat ≤10. |
| Machine reference integrity (`--experimental` only) | ≤20 | allow-listed npm/PyPI metadata GETs plus DNS lookups while resolving references named in `llms.txt`/MCP tool descriptions; a hard `LOOKUP_BUDGET` — anything beyond it is recorded `UNCHECKED`, never guessed. This is the only gatherer gated on `--experimental` (without the flag it issues zero requests) and the only one whose requests leave the target's own origin. |

Every gatherer above, including machine reference integrity, is routed
through the same guarded `SecureClient` — SSRF guard applied per hop and
per-kind response size caps, described elsewhere in this document. This
does **not** mean no gatherer ever follows a cross-host redirect: the
shared client's redirect loop follows any hop that passes the SSRF guard,
INCLUDING a hop that lands on a different public host — the guard checks
"is this address safe to reach", not "is this still the host I asked for".
The machine reference integrity probe is the one place that additionally
narrows this: its registry lookups are wrapped in a fetcher that refuses
any redirect landing on a host OTHER than the one requested (a stricter
rule layered on top of the shared client, not a property of the shared
client itself) — restricted to a fixed allow-list of package-registry
hosts (npm, PyPI) and bounded by the ≤20-lookup budget above. A refused
redirect is recorded `UNCHECKED` rather than resolved against whatever
answered on the other end. DNS lookups for domain references remain a
separate, DNS-only resolution with no HTTP request at all. It runs only
under `--experimental`, and it only ever resolves references it extracted
from already-fetched, allow-listed content (not arbitrary user input).
None of this changes the total-scan-budget deadline (60 seconds, below) —
it is one more thing that budget is checked against.

## Concurrency

No concurrency limit is enforced in this version; requests are sequential.
A future per-domain concurrency cap is reserved in `SecurityPolicy`
(`per_domain_concurrency`) but is not yet read by anything — there is
nothing to enforce it against while every fetch in a scan already happens
one at a time.

## Outbound requests

Every request described above is Core scanning the target you gave it.
There is exactly one exception, and it only happens if you ask for it.

`--contribute` sends ONE HTTPS POST, after the scan finishes, to a single
fixed URL (`https://scovant.com/api/public/core/contribute`) — never to
any other host, and never unless the flag is present on the command line.
The request uses its own dedicated client: `follow_redirects=False`, no
environment proxy configuration (`trust_env=False`), no cookies, a 10
second timeout, and the same `User-Agent` Core uses for the scan itself. A
failed request (timeout, connection error, non-2xx response) never raises
and never changes the CLI's exit code — it prints one line to stderr
(`contributed: <domain> (accepted|deduplicated|failed: <reason>)`) and
that's the end of it.

The request body carries exactly these fields and nothing else — no page
HTML, no evidence, no fetched document contents, no filesystem paths, no
IP address:

- `domain` — the scanned site's hostname only (no path, no query string)
- `timestamp` — when the scan completed
- `core_version`, `ruleset_version`, `ruleset_digest`
- `profile` — the resolved site profile
- `experimental` — whether experimental checks were included
- `check_statuses` — each check id's status (`PASS`/`WARN`/`FAIL`/`N/A`/`ERROR`)
- `score` — `{value, grade, coverage, status}`

`--contribute` is refused (exit 2) when combined with
`--allow-private-networks` — the same SSRF guard described above already
determined the target is public before the flag is even considered, and a
target you've explicitly marked private is never eligible for the
community index regardless. See the README's
["Community contributions"](../README.md#community-contributions) section
for what the data is used for.

## MCP server

`scovant mcp` (the `[mcp]` extra) is a stdio MCP server, not a network
service — it speaks the Model Context Protocol over stdin/stdout to
whichever single client process started it (Claude Desktop, Cursor, or
another MCP host), and binds no port. It inherits every guarantee above
unchanged: each `scan_site`/`get_core_score` tool call runs the same
passive, read-only scan `scovant scan` does, through the same SSRF-guarded
`SecureClient`, against the same total-scan-budget deadline. It adds no new
network surface and no new fetcher — it never opens a connection Core's
scan engine wouldn't otherwise open.

Two properties specific to the server process itself: only one scan runs
at a time (a second concurrent tool call is rejected outright rather than
queued or run in parallel — this is a single-client stdio process, not a
concurrent service), and completed reports are kept only in an in-memory
ring buffer (the 8 most recent) for `get_finding` to read back — nothing is
written to disk, and the ring is empty again the moment the process exits.

## What Core never does

- Store or forward cookies across requests.
- Authenticate to the target site.
- Submit a form or otherwise write to the target site.
- Make a purchase or perform any other destructive/transactional action.
- Persist a secret it happens to observe in a fetched response.

Core is a passive, read-only scanner: every request is a plain `GET`.

## The DNS-rebinding gap is closed

Earlier versions validated a hostname's resolved address twice: once at the
SSRF guard's own lookup (an `httpx` request-event hook, closest to the
connect) and once implicitly by the underlying TCP connect performing its
own resolution a few milliseconds later — two separate DNS lookups an
attacker controlling DNS for the target host could, in principle, answer
differently, a classic DNS-rebinding race.

The default transport (`PinnedTransport`, `security/pinned_transport.py`)
closes this: it resolves each host exactly once, validates every returned
address with the same predicate the guard hook uses
(`url_safety.assert_public_address`), and connects to the address it
validated — never a second, independent resolution. `Host` and the TLS
SNI/certificate verification stay pinned to the original hostname (not the
IP), and each redirect hop is re-pinned from scratch through the same
one-resolution-per-host path, so a rebinding answer can change what a
*later* hop connects to but never what an *already-validated* hop connects
to. The per-request `_guard_hook` in `SecureClient` stays attached as a
second, independent check — belt-and-braces, and the only check that
applies when a caller injects its own transport (tests, fixture sites).

## Security test coverage

The network layer's automated security suite (`pytest -m security`) covers
every mandatory case below — an offline regression suite run against
`httpx.MockTransport`/a local fixture server, never real network I/O. Each
row names the actual test function that proves the case; a release fails if
any of them fails.

| Mandatory case                | Proven by                                                          |
| ------------------------------ | ------------------------------------------------------------------- |
| `localhost`                    | `test_blocked_targets_raise_security_error` (`tests/test_client_security.py`) |
| `127.0.0.1`                     | `test_blocked_targets_raise_security_error` (`tests/test_client_security.py`) |
| `169.254.169.254`               | `test_blocked_targets_raise_security_error` (`tests/test_client_security.py`) |
| `10.0.0.1`                      | `test_blocked_targets_raise_security_error` (`tests/test_client_security.py`) |
| `192.168.1.1`                   | `test_blocked_targets_raise_security_error` (`tests/test_client_security.py`) |
| IPv6 loopback                   | `test_blocked_targets_raise_security_error` (`tests/test_client_security.py`, `http://[::1]/` case) |
| redirect to localhost           | `test_redirect_to_localhost_is_blocked` (`tests/test_security_suite.py`) |
| redirect to metadata IP         | `test_redirect_to_cloud_metadata_address_is_blocked_and_never_requested` (`tests/test_security_suite.py`), also `test_redirect_to_private_is_blocked` (`tests/test_client_security.py`) |
| DNS rebinding simulation        | `test_ssrf_blocked_via_rebinding_dns_is_classified_as_security` (`tests/test_client_security.py`) |
| oversized documents             | `test_oversized_robots_txt_is_truncated_and_parsed_as_present_not_crash` and `test_an_oversized_llms_txt_is_declared_as_a_partial_read_end_to_end` (`tests/test_security_suite.py`, the latter over a real HTTP server), also `test_oversized_body_is_truncated_and_flagged` (`tests/test_client_security.py`); that every body-reading GATHERER carries and derives the truncation flag is the completeness suite in `tests/test_truncation_contract.py`, and that every CHECK that draws a verdict from a document body actually declares the partial read (not merely computes it) is the completeness suite in `tests/test_truncation_check_completeness.py`, an audited exemption list for the genuine non-participants; `test_every_robots_derived_verdict_declares_the_truncated_read`, `test_a_truncated_robots_fail_verdict_is_not_silent` and `test_a_fully_read_robots_txt_omits_the_truncated_flag_on_every_such_check` (`tests/test_security_suite.py`) prove the robots.txt-specific case end to end |
| oversized XML                   | `test_oversized_sitemap_xml_is_truncated_and_reported_invalid_no_crash` (`tests/test_security_suite.py`) |
| redirect loops                  | `test_redirect_loop_is_a_network_error` (`tests/test_client_security.py`) |
| malformed gzip                  | `test_malformed_gzip_body_is_a_network_error_not_a_crash` (`tests/test_security_suite.py`) |
| zip bomb equivalent             | `test_gzip_decompression_bomb_is_capped_not_decompressed_without_limit` (`tests/test_security_suite.py`) |
| slow response                   | `test_slow_response_trips_the_scan_time_budget_as_a_timeout` (`tests/test_security_suite.py`) |

## Supply chain

Three GitHub Actions workflows in this repository run continuously against
the published tree — not against a scan target, against Core's own code and
dependencies:

- **Dependabot** (`.github/dependabot.yml`) opens a pull request weekly for
  outdated `pip` dependencies and a separate one for outdated GitHub Actions
  pins, each grouping every update of its kind into a single PR rather than
  one PR per package.
- **CodeQL** (`.github/workflows/codeql.yml`) runs static analysis over the
  Python source on every push to `main`, every pull request, and weekly on a
  schedule; findings land in this repository's Security tab as code
  scanning alerts.
- **`pip-audit`** (`.github/workflows/audit.yml`) installs the package with
  its `[mcp]` extra into a fresh environment weekly, freezes the resolved
  dependency set (`pip freeze --exclude-editable`, with the local
  `scovant-core` entry itself excluded — it isn't a PyPI-hosted dependency
  and auditing it as one only produces a "not found on PyPI" error, not a
  vulnerability finding), and runs `pip-audit --strict` against that
  requirements list, plus an on-demand `workflow_dispatch` trigger. The audit
  tool itself is installed into a *separate* virtualenv, so the frozen list
  is this package's real dependency closure and not the tool's own tree —
  otherwise an advisory in something only `pip-audit` depends on would fail
  the workflow with a security-shaped alarm about software this package does
  not ship. There is no ignore list — a real, unfixed advisory in any of the
  actual runtime dependencies fails the workflow rather than being silenced;
  see `docs/releasing.md` for how a release handles one.

Because this repository is a snapshot mirror (see `docs/releasing.md`),
Dependabot and CodeQL pull requests opened here are never merged here — they
are ported into Scovant's private monorepo by hand, following the same
"port a community PR" path any external contribution takes, and reach this
repository again only in the next sync commit.

## Reporting a vulnerability

Email `security@scovant.com` or use GitHub's private vulnerability
reporting on this repository. Please include a reproduction. See
`SECURITY.md` for the full reporting policy and response timeline.
