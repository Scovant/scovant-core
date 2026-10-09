# Scovant Core — https://example.com/

## Score

**Scovant Core Static Signal Score:** 80 / 100 · grade B · coverage 100%
**Scope:** CANONICAL · **Status:** OK · **Errors:** 0
Profile: api? (confidence LOW, 0.55) — canonical comparison should specify --profile.
**Profile:** api (requested auto, confidence 55%)

**Capabilities detected** (descriptive, not scored): mcp: absent · webmcp: absent · ucp: not_checked · llms_txt: absent · openapi: absent · oauth: present · content_signal: absent · security_txt: absent
**Standards:** AgentReady v1.0 (descriptive, not scored): MUST 3/3 measured — 1 pass, 1 warn, 1 fail · SHOULD 5/12 measured — 1 pass, 4 warn · MAY none measured (0/3) — Mapping: docs/standards/agentready.md

## Categories

| Category | Weight | Score | Evaluated / applicable |
|---|---:|---:|---:|
| Access & Discovery | 25 | 92 | 19 / 19 |
| Machine Understanding | 25 | 81 | 8 / 8 |
| Agent Interfaces | 20 | 83 | 6 / 6 |
| Trust & Commerce | 15 | 67 | 6 / 6 |
| Operability & Efficiency | 15 | 69 | 16 / 16 |

68 checks: 25 PASS, 10 WARN, 2 FAIL, 31 N/A, 0 ERROR

## Top findings

- **CORE-OPERABILITY-004** — 1 of 2 machine-consumable reference(s) do not resolve.
- **CORE-ACCESS-005** — No sitemap was found.
- **CORE-OPERABILITY-001** — The entry page's static HTML carries only 155 chars of visible text (< 200).
- **CORE-INTERFACE-005** — No OpenAPI document discovered at the conventional paths.
- **CORE-MACHINE-002** — No Organization entity was found on the sampled pages.
- **CORE-TRUST-004** — The privacy policy page link is broken (HTTP 404).
- **CORE-TRUST-005** — No terms/conditions page was found linked from the entry page.
- **CORE-MACHINE-003** — No WebSite or WebPage entity was found on the sampled pages.
- **[security]** **CORE-SECURITY-003** — Neither Content-Security-Policy nor X-Frame-Options is sent.
- **[security]** **CORE-SECURITY-002** — No Strict-Transport-Security header.
- **[security]** **CORE-SECURITY-005** — Missing: referrer-policy, x-content-type-options.

## Findings

### FAIL (2)

- **CORE-OPERABILITY-004** — Broken machine-consumable endpoints (high): 1 of 2 machine-consumable reference(s) do not resolve.
  - Remediation: Fix or remove the broken references (sitemap, llms.txt, OpenAPI spec, policy links) so agents don't hit dead links.

  <details><summary>evidence</summary>

  ```json
  {
    "broken": [
      {
        "source": "policy_link",
        "status": 404,
        "url": "https://example.com/privacy"
      }
    ],
    "broken_count": 1,
    "inconclusive": [],
    "refs_checked": 2,
    "refs_resolved": 2,
    "unresolved": []
  }
  ```

  </details>

- **CORE-SECURITY-003** — Content-Security-Policy / framing policy (medium): Neither Content-Security-Policy nor X-Frame-Options is sent.
  - Remediation: Send a Content-Security-Policy with frame-ancestors, or at least X-Frame-Options: DENY.

  <details><summary>evidence</summary>

  ```json
  {
    "csp_present": false,
    "csp_report_only": false,
    "frame_ancestors": false,
    "x_frame_options": null
  }
  ```

  </details>

### WARN (10)

- **CORE-ACCESS-005** — Sitemap availability (medium): No sitemap was found.
  - Remediation: Publish /sitemap.xml and declare it in robots.txt.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_count": 0,
    "exists": false,
    "kind": null,
    "parse_error": null,
    "probe_error": null,
    "probe_status": 404,
    "served_as_html": false,
    "url": null,
    "valid": false
  }
  ```

  </details>

- **CORE-INTERFACE-005** — OpenAPI discovery (medium): No OpenAPI document discovered at the conventional paths.
  - Remediation: Publish an OpenAPI document at a conventional path (e.g. /openapi.json), or link to it from the entry page.

  <details><summary>evidence</summary>

  ```json
  {
    "candidates_checked": 5,
    "found_url": null,
    "openapi_version": null,
    "parseable": false
  }
  ```

  </details>

- **CORE-MACHINE-002** — Organization entity (medium): No Organization entity was found on the sampled pages.
  - Remediation: Add JSON-LD with "@type": "Organization" declaring at least name and url.

  <details><summary>evidence</summary>

  ```json
  {
    "found": false,
    "pages_parsed": 1,
    "unread": 1
  }
  ```

  </details>

- **CORE-MACHINE-003** — WebSite/WebPage entity (low): No WebSite or WebPage entity was found on the sampled pages.
  - Remediation: Add JSON-LD with "@type": "WebSite" or "WebPage".

  <details><summary>evidence</summary>

  ```json
  {
    "found": false,
    "pages_parsed": 1,
    "unread": 1
  }
  ```

  </details>

- **CORE-OPERABILITY-001** — Server-rendered core content (medium): The entry page's static HTML carries only 155 chars of visible text (< 200).
  - Remediation: Server-render (or statically pre-render) the core content so an agent's plain HTTP fetch sees it.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "spa_shell_marker": false,
    "visible_text_chars": 155
  }
  ```

  </details>

- **CORE-OPERABILITY-003** — Cache validators (info): The entry response carries no cache validator (ETag, Last-Modified, or Cache-Control).
  - Remediation: Add an ETag or Last-Modified header so agents can issue conditional GETs.

  <details><summary>evidence</summary>

  ```json
  {
    "cache_control": null,
    "etag": null,
    "last_modified": null
  }
  ```

  </details>

- **CORE-SECURITY-002** — HSTS presence (low): No Strict-Transport-Security header.
  - Remediation: Send Strict-Transport-Security: max-age=31536000 (add includeSubDomains once every subdomain is https).

  <details><summary>evidence</summary>

  ```json
  {
    "header": null,
    "max_age": null
  }
  ```

  </details>

- **CORE-SECURITY-005** — Referrer / MIME hygiene headers (low): Missing: referrer-policy, x-content-type-options.
  - Remediation: Send Referrer-Policy: strict-origin-when-cross-origin and X-Content-Type-Options: nosniff.

  <details><summary>evidence</summary>

  ```json
  {
    "missing": [
      "referrer-policy",
      "x-content-type-options"
    ],
    "referrer_policy": null,
    "x_content_type_options": null
  }
  ```

  </details>

- **CORE-TRUST-004** — Privacy policy discoverability (high): The privacy policy page link is broken (HTTP 404).
  - Remediation: Publish a privacy policy page and link it from the entry page's nav or footer.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": false,
    "status": 404,
    "text_chars": 0,
    "url": "https://example.com/privacy"
  }
  ```

  </details>

- **CORE-TRUST-005** — Terms/conditions discoverability (medium): No terms/conditions page was found linked from the entry page.
  - Remediation: Publish a terms/conditions page and link it from the entry page's nav or footer.
### PASS (19)

- **CORE-ACCESS-001** — HTTPS reachability (info): HTTPS entry URL answered 200.

  <details><summary>evidence</summary>

  ```json
  {
    "final_url": "https://example.com/",
    "input_url": "https://example.com/",
    "redirect_chain": [],
    "redirect_count": 0,
    "status": 200
  }
  ```

  </details>

- **CORE-ACCESS-002** — robots.txt availability and syntax (info): robots.txt answered 200 with a well-formed policy.

  <details><summary>evidence</summary>

  ```json
  {
    "error": null,
    "resource": "https://example.com/robots.txt",
    "served_as_html": false,
    "sha256": "b87966e58d2e52aaf3d52e0e5308a67505c7b1015c2fa7f772d1ecc327c4082f",
    "sitemap_count": 1,
    "status": 200,
    "unknown_directives": []
  }
  ```

  </details>

- **CORE-ACCESS-003** — AI search crawler policy (info): robots.txt declares all major search and answer-engine crawlers as allowed.

  <details><summary>evidence</summary>

  ```json
  {
    "declared_policy": {
      "Applebot": true,
      "Bingbot": true,
      "Claude-SearchBot": true,
      "Googlebot": true,
      "OAI-SearchBot": true,
      "PerplexityBot": true
    },
    "http_status": 200,
    "resource": "https://example.com/robots.txt",
    "robots_present": true,
    "user_fetch_policy": {
      "ChatGPT-User": true,
      "Claude-User": true,
      "DuckAssistBot": true,
      "Perplexity-User": true
    }
  }
  ```

  </details>

- **CORE-ACCESS-004** — Training vs. search crawler separation (info): No training restriction is declared; search and retrieval remain allowed.

  <details><summary>evidence</summary>

  ```json
  {
    "explicit_separation": false,
    "http_status": 200,
    "resource": "https://example.com/robots.txt",
    "search_blocked": [],
    "training_blocked": []
  }
  ```

  </details>

- **CORE-ACCESS-007** — Canonical URL integrity (info): The canonical URL matches the entry URL.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_url": "https://example.com/",
    "entry_url": "https://example.com/"
  }
  ```

  </details>

- **CORE-ACCESS-008** — Indexability (info): The entry page does not declare noindex.

  <details><summary>evidence</summary>

  ```json
  {
    "robots_meta": null,
    "x_robots_tag": null
  }
  ```

  </details>

- **CORE-INTERFACE-006** — OAuth authorization-server metadata (info): OAuth authorization-server metadata is published and complete.

  <details><summary>evidence</summary>

  ```json
  {
    "has_endpoints": true,
    "http_status": 200,
    "issuer": "https://example.com",
    "parseable": true,
    "resource": "https://example.com/.well-known/oauth-authorization-server",
    "served_as_html": false
  }
  ```

  </details>

- **CORE-INTERFACE-007** — OAuth protected-resource metadata (info): OAuth protected-resource metadata is published and complete.

  <details><summary>evidence</summary>

  ```json
  {
    "authorization_servers": [
      "https://example.com"
    ],
    "dpop_bound_access_tokens_required": false,
    "http_status": 200,
    "jwks_uri": "https://example.com/jwks.json",
    "matches_issuer": true,
    "parseable": true,
    "resource": "https://example.com/.well-known/oauth-protected-resource",
    "resource_matches_origin": true,
    "resource_value": "https://example.com",
    "scopes_supported": [],
    "served_as_html": false
  }
  ```

  </details>

- **CORE-MACHINE-008** — Metadata quality (info): The entry page declares title, description, and Open Graph tags.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "issues": [],
    "meta_description": "Example API is a synthetic HTTP API used to exercise agent-readiness checks.",
    "missing": [],
    "title": "Example API"
  }
  ```

  </details>

- **CORE-MACHINE-009** — Heading structure (info): The entry page has a single H1 and no skipped heading levels.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "h1_count": 1,
    "heading_count": 1,
    "issues": [],
    "levels": [
      "h1"
    ]
  }
  ```

  </details>

- **CORE-MACHINE-010** — Language declaration (info): The entry page declares a valid `lang` attribute.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "html_lang": "en"
  }
  ```

  </details>

- **CORE-OPERABILITY-002** — Redirect chain complexity (info): The entry URL redirects 0 time(s) before settling.

  <details><summary>evidence</summary>

  ```json
  {
    "redirect_chain": [],
    "redirect_count": 0
  }
  ```

  </details>

- **CORE-OPERABILITY-005** — Agent parse cost (info): The entry page's estimated parse cost is ~38 tokens (low).

  <details><summary>evidence</summary>

  ```json
  {
    "dom_nodes": 18,
    "estimated_tokens": 38,
    "html_bytes": 753,
    "level": "LOW",
    "link_count": 4,
    "script_bytes": 0,
    "script_ratio": 0.0,
    "structured_bytes": 0,
    "text_chars": 155,
    "token_chars_ratio": 4
  }
  ```

  </details>

- **CORE-OPERABILITY-008** — Unknown paths return 404 (info): Unknown paths answer with a real 404.

  <details><summary>evidence</summary>

  ```json
  {
    "final_url": "https://example.com/scovant-core-probe-9b580505",
    "probed_url": "https://example.com/scovant-core-probe-9b580505",
    "redirected": false,
    "served_html": false,
    "status": 404
  }
  ```

  </details>

- **CORE-OPERABILITY-010** — Challenge pages are not served as 200 (info): No challenge page is served with HTTP 200.

  <details><summary>evidence</summary>

  ```json
  {
    "honest_challenges": 0,
    "pages": [],
    "pages_checked": 3
  }
  ```

  </details>

- **CORE-SECURITY-001** — HTTPS baseline (info): Served over https; http:// redirects to https.

  <details><summary>evidence</summary>

  ```json
  {
    "downgrade_attempted": true,
    "downgrade_status": 301,
    "final_scheme": "https",
    "redirected_to_https": true
  }
  ```

  </details>

- **CORE-SECURITY-007** — Credential-like value exposed in a machine-facing surface (info): No credential-like values in the gathered machine-facing surfaces.

  <details><summary>evidence</summary>

  ```json
  {
    "hit_count": 0,
    "hits": [],
    "surfaces_scanned": 1
  }
  ```

  </details>

- **CORE-SECURITY-008** — Internal network reference exposed (info): No internal network references found.

  <details><summary>evidence</summary>

  ```json
  {
    "hits": [],
    "surfaces_scanned": 1
  }
  ```

  </details>

- **CORE-TRUST-001** — Contact/support discoverability (info): A contact or support link was found on the entry page.

  <details><summary>evidence</summary>

  ```json
  {
    "contact_url": "https://example.com/contact",
    "kind": "page"
  }
  ```

  </details>

### N/A (20)

`CORE-ACCESS-006`, `CORE-ACCESS-009`, `CORE-ACCESS-010`, `CORE-INTERFACE-001`, `CORE-INTERFACE-002`, `CORE-INTERFACE-003`, `CORE-MACHINE-001`, `CORE-MACHINE-004`, `CORE-MACHINE-005`, `CORE-MACHINE-006`, `CORE-MACHINE-007`, `CORE-MACHINE-011`, `CORE-OPERABILITY-006`, `CORE-OPERABILITY-009`, `CORE-SECURITY-004`, `CORE-SECURITY-006`, `CORE-TRUST-002`, `CORE-TRUST-003`, `CORE-TRUST-006`, `CORE-TRUST-007`

## Experimental (not scored)

- **CORE-SECURITY-011** (PASS) — No indicators found.
- **CORE-SECURITY-012** (PASS) — No indicators found.
- **CORE-SECURITY-013** (PASS) — No indicators found.
- **CORE-SECURITY-014** (PASS) — No indicators found.
- **CORE-SECURITY-017** (PASS) — Protected-resource metadata names this origin and uses https throughout.
- **CORE-SECURITY-018** (PASS) — Authorization-server metadata is consistent and advertises PKCE and issuer identification.

N/A: `CORE-ACCESS-011`, `CORE-INTERFACE-004`, `CORE-INTERFACE-008`, `CORE-INTERFACE-009`, `CORE-MACHINE-012`, `CORE-OPERABILITY-007`, `CORE-OPERABILITY-011`, `CORE-SECURITY-009`, `CORE-SECURITY-010`, `CORE-SECURITY-015`, `CORE-SECURITY-016`

## Agentic Security & Trust

_PASSIVE SIGNALS ONLY_

| | |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 2 |
| Web baseline | PASS 1  WARN 2  FAIL 1 |
| Disclosure | PASS 0  WARN 0  FAIL 0 |
| Data exposure | PASS 2  WARN 0  FAIL 0 |
| Prompt surface | PASS 4  WARN 0  FAIL 0 |
| auth | PASS 2  WARN 0  FAIL 0 |

- Observed authorization: NOT TESTED
- Verified agent identity: NOT TESTED
- Prompt-injection resilience: NOT TESTED
- Tool invocation safety: NOT TESTED

### CORE-SECURITY-002 (SEC-WEB-002) — HSTS presence

- Status: WARN · Severity: low · Confidence: high · Verification: PASSIVE_OBSERVED
- Fix owner: edge_cdn · Domain: web_baseline
- No Strict-Transport-Security header.
- Remediation: Send Strict-Transport-Security: max-age=31536000 (add includeSubDomains once every subdomain is https).
- Limitations: Passive signal only. Scovant Core did not authenticate, submit forms or invoke tools; observed authorization behaviour is not tested.
  - Remediation: Send Strict-Transport-Security: max-age=31536000 (add includeSubDomains once every subdomain is https).

  <details><summary>evidence</summary>

  ```json
  {
    "header": null,
    "max_age": null
  }
  ```

  </details>

### CORE-SECURITY-003 (SEC-WEB-003) — Content-Security-Policy / framing policy

- Status: FAIL · Severity: medium · Confidence: high · Verification: PASSIVE_OBSERVED
- Fix owner: frontend · Domain: web_baseline
- Neither Content-Security-Policy nor X-Frame-Options is sent.
- Remediation: Send a Content-Security-Policy with frame-ancestors, or at least X-Frame-Options: DENY.
- Limitations: Passive signal only. Scovant Core did not authenticate, submit forms or invoke tools; observed authorization behaviour is not tested.
  - Remediation: Send a Content-Security-Policy with frame-ancestors, or at least X-Frame-Options: DENY.

  <details><summary>evidence</summary>

  ```json
  {
    "csp_present": false,
    "csp_report_only": false,
    "frame_ancestors": false,
    "x_frame_options": null
  }
  ```

  </details>

### CORE-SECURITY-005 (SEC-WEB-005) — Referrer / MIME hygiene headers

- Status: WARN · Severity: low · Confidence: high · Verification: PASSIVE_OBSERVED
- Fix owner: edge_cdn · Domain: web_baseline
- Missing: referrer-policy, x-content-type-options.
- Remediation: Send Referrer-Policy: strict-origin-when-cross-origin and X-Content-Type-Options: nosniff.
- Limitations: Passive signal only. Scovant Core did not authenticate, submit forms or invoke tools; observed authorization behaviour is not tested.
  - Remediation: Send Referrer-Policy: strict-origin-when-cross-origin and X-Content-Type-Options: nosniff.

  <details><summary>evidence</summary>

  ```json
  {
    "missing": [
      "referrer-policy",
      "x-content-type-options"
    ],
    "referrer_policy": null,
    "x_content_type_options": null
  }
  ```

  </details>

This section evaluates tested AI-agent security controls and machine-facing security signals. It is not an overall website or application security rating.

## Not tested by Scovant Core

- Observed WAF access
- Real agent tasks
- MCP tool execution
- WebMCP state parity
- Multi-model reliability
- Regression stability

## Provenance

Core 0.16.0 · ruleset 2026.10 (digest `7f440d6205c3`) · scan `local-golden` · 2026-09-04T00:00:00Z

Verify with real agents: [scovant.com/scan](https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss)

