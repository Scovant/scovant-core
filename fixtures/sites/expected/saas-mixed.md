# Scovant Core — https://example.com/

## Score

**Scovant Core Static Signal Score:** 81 / 100 · grade B · coverage 100%
**Scope:** CANONICAL · **Status:** OK · **Errors:** 0
**Profile:** saas (requested auto, confidence 80%)

**Capabilities detected** (descriptive, not scored): mcp: absent · webmcp: absent · ucp: not_checked · llms_txt: absent · openapi: absent · oauth: invalid · content_signal: absent · security_txt: present
**Standards:** AgentReady v1.0 (descriptive, not scored): MUST 3/3 measured — 1 pass, 2 warn · SHOULD 4/12 measured — 4 warn · MAY none measured (0/3) — Mapping: docs/standards/agentready.md

## Categories

| Category | Weight | Score | Evaluated / applicable |
|---|---:|---:|---:|
| Access & Discovery | 25 | 81 | 21 / 21 |
| Machine Understanding | 25 | 92 | 12 / 12 |
| Agent Interfaces | 20 | 50 | 4 / 4 |
| Trust & Commerce | 15 | 100 | 11 / 11 |
| Operability & Efficiency | 15 | 86 | 18 / 18 |

66 checks: 29 PASS, 10 WARN, 2 FAIL, 25 N/A, 0 ERROR

## Top findings

- **CORE-ACCESS-003** — robots.txt declares PerplexityBot as disallowed.
- **CORE-OPERABILITY-001** — The entry page's static HTML carries only 90 chars of visible text (< 200).
- **CORE-ACCESS-004** — Search/retrieval crawlers are restricted together with training crawlers — intent unclear.
- **CORE-ACCESS-006** — The newest lastmod in the sitemap is over 730 days old.
- **CORE-INTERFACE-006** — An authorization-server metadata document was found but is incomplete or does not parse.
- **CORE-INTERFACE-007** — A protected-resource metadata document was found but is incomplete or does not parse.
- **CORE-MACHINE-002** — An Organization entity is missing url.
- **CORE-OPERABILITY-006** — 1 control(s) across 1 form(s) lack a label or accessible name.
- **[security]** **CORE-SECURITY-003** — Neither Content-Security-Policy nor X-Frame-Options is sent.
- **[security]** **CORE-SECURITY-006** — Expires missing or unparsable.
- **[security]** **CORE-SECURITY-002** — No Strict-Transport-Security header.
- **[security]** **CORE-SECURITY-005** — Missing: referrer-policy, x-content-type-options.

## Findings

### FAIL (2)

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

- **CORE-SECURITY-006** — security.txt validity (RFC 9116) (medium): Expires missing or unparsable.
  - Remediation: Set Expires to a future date (RFC 3339) and keep it fresh.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_location": true,
    "canonical_uris": [],
    "contact": true,
    "expired": null,
    "expires": null,
    "found_url": "https://example.com/.well-known/security.txt"
  }
  ```

  </details>

### WARN (10)

- **CORE-ACCESS-003** — AI search crawler policy (high): robots.txt declares PerplexityBot as disallowed.
  - Remediation: Review whether blocking these retrieval crawlers is intended; they power answer-engine discovery, not model training.

  <details><summary>evidence</summary>

  ```json
  {
    "declared_policy": {
      "Applebot": true,
      "Bingbot": true,
      "Claude-SearchBot": true,
      "Googlebot": true,
      "OAI-SearchBot": true,
      "PerplexityBot": false
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

- **CORE-ACCESS-004** — Training vs. search crawler separation (low): Search/retrieval crawlers are restricted together with training crawlers — intent unclear.
  - Remediation: Restrict only the training-purpose crawler tokens; leave search/retrieval crawlers allowed.

  <details><summary>evidence</summary>

  ```json
  {
    "explicit_separation": false,
    "http_status": 200,
    "resource": "https://example.com/robots.txt",
    "search_blocked": [
      "PerplexityBot"
    ],
    "training_blocked": []
  }
  ```

  </details>

- **CORE-ACCESS-006** — Sitemap freshness (low): The newest lastmod in the sitemap is over 730 days old.
  - Remediation: Regenerate the sitemap so lastmod reflects real content changes.

  <details><summary>evidence</summary>

  ```json
  {
    "dated_entry_count": 4,
    "entry_count": 4,
    "newest": "2020-01-01",
    "oldest": "2020-01-01",
    "url": "https://example.com/sitemap.xml"
  }
  ```

  </details>

- **CORE-INTERFACE-006** — OAuth authorization-server metadata (medium): An authorization-server metadata document was found but is incomplete or does not parse.
  - Remediation: Publish RFC 8414 metadata with `issuer`, `authorization_endpoint`, and `token_endpoint` at /.well-known/oauth-authorization-server.

  <details><summary>evidence</summary>

  ```json
  {
    "has_endpoints": false,
    "http_status": 200,
    "parseable": true,
    "resource": "https://example.com/.well-known/oauth-authorization-server",
    "served_as_html": false
  }
  ```

  </details>

- **CORE-INTERFACE-007** — OAuth protected-resource metadata (medium): A protected-resource metadata document was found but is incomplete or does not parse.
  - Remediation: Publish RFC 9728 metadata with `resource` and a non-empty `authorization_servers` list at /.well-known/oauth-protected-resource.

  <details><summary>evidence</summary>

  ```json
  {
    "dpop_bound_access_tokens_required": false,
    "http_status": 200,
    "jwks_uri": null,
    "matches_issuer": true,
    "parseable": true,
    "resource": "https://example.com/.well-known/oauth-protected-resource",
    "resource_matches_origin": true,
    "scopes_supported": [],
    "served_as_html": false
  }
  ```

  </details>

- **CORE-MACHINE-002** — Organization entity (medium): An Organization entity is missing url.
  - Remediation: Add the missing fields (url) to the Organization entity.

  <details><summary>evidence</summary>

  ```json
  {
    "found": true,
    "missing": [
      "url"
    ],
    "pages_parsed": 4
  }
  ```

  </details>

- **CORE-OPERABILITY-001** — Server-rendered core content (medium): The entry page's static HTML carries only 90 chars of visible text (< 200).
  - Remediation: Server-render (or statically pre-render) the core content so an agent's plain HTTP fetch sees it.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "spa_shell_marker": false,
    "visible_text_chars": 90
  }
  ```

  </details>

- **CORE-OPERABILITY-006** — Form/control labels (medium): 1 control(s) across 1 form(s) lack a label or accessible name.
  - Remediation: Add a <label> (or aria-label/aria-labelledby) to every input/select, and a name or accessible text to every button.

  <details><summary>evidence</summary>

  ```json
  {
    "totals": {
      "forms": 1,
      "inputs": 2,
      "unlabeled_inputs": 1,
      "unlabeled_selects": 0,
      "unnamed_buttons": 0
    }
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

### PASS (25)

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
    "sha256": "3986b6edab342dfd005c7e59bf3e6876ce79173402727d30bb6c632805c1a1da",
    "sitemap_count": 1,
    "status": 200,
    "unknown_directives": []
  }
  ```

  </details>

- **CORE-ACCESS-005** — Sitemap availability (info): A valid urlset sitemap was found at https://example.com/sitemap.xml.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_count": 4,
    "exists": true,
    "kind": "urlset",
    "parse_error": null,
    "probe_error": null,
    "probe_status": 200,
    "served_as_html": false,
    "url": "https://example.com/sitemap.xml",
    "valid": true
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

- **CORE-MACHINE-001** — JSON-LD parseability (info): Every JSON-LD block on the sampled pages parses as valid JSON.

  <details><summary>evidence</summary>

  ```json
  {
    "pages": [
      {
        "parsed": 2,
        "raw": 2,
        "url": "https://example.com/"
      },
      {
        "parsed": 0,
        "raw": 0,
        "url": "https://example.com/pricing"
      },
      {
        "parsed": 1,
        "raw": 1,
        "url": "https://example.com/docs"
      },
      {
        "parsed": 0,
        "raw": 0,
        "url": "https://example.com/signup"
      }
    ],
    "parsed_total": 3,
    "raw_total": 3
  }
  ```

  </details>

- **CORE-MACHINE-003** — WebSite/WebPage entity (info): A WebSite or WebPage entity was found on the sampled pages.

  <details><summary>evidence</summary>

  ```json
  {
    "found": true,
    "pages_parsed": 4
  }
  ```

  </details>

- **CORE-MACHINE-007** — Breadcrumbs (info): A sampled non-entry page declares a BreadcrumbList.

  <details><summary>evidence</summary>

  ```json
  {
    "has_breadcrumb": true,
    "non_entry_pages": [
      "https://example.com/pricing",
      "https://example.com/docs",
      "https://example.com/signup"
    ],
    "non_entry_parsed": 3
  }
  ```

  </details>

- **CORE-MACHINE-008** — Metadata quality (info): The entry page declares title, description, and Open Graph tags.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "issues": [],
    "meta_description": "Example SaaS is a synthetic subscription service used to exercise agent-readiness checks.",
    "missing": [],
    "title": "Example SaaS"
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

- **CORE-OPERABILITY-003** — Cache validators (info): The entry response carries an ETag or Last-Modified validator.

  <details><summary>evidence</summary>

  ```json
  {
    "cache_control": null,
    "etag": "\"abc\"",
    "last_modified": null
  }
  ```

  </details>

- **CORE-OPERABILITY-004** — Broken machine-consumable endpoints (info): All 4 checked machine-consumable reference(s) resolve.

  <details><summary>evidence</summary>

  ```json
  {
    "broken": [],
    "broken_count": 0,
    "inconclusive": [],
    "refs_checked": 4,
    "refs_resolved": 4,
    "unresolved": []
  }
  ```

  </details>

- **CORE-OPERABILITY-005** — Agent parse cost (info): The entry page's estimated parse cost is ~22 tokens (low).

  <details><summary>evidence</summary>

  ```json
  {
    "dom_nodes": 26,
    "estimated_tokens": 22,
    "html_bytes": 1278,
    "level": "LOW",
    "link_count": 7,
    "script_bytes": 218,
    "script_ratio": 0.1705790297339593,
    "structured_bytes": 218,
    "text_chars": 90,
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
    "pages_checked": 5
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
    "surfaces_scanned": 3
  }
  ```

  </details>

- **CORE-SECURITY-008** — Internal network reference exposed (info): No internal network references found.

  <details><summary>evidence</summary>

  ```json
  {
    "hits": [],
    "surfaces_scanned": 3
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

- **CORE-TRUST-004** — Privacy policy discoverability (info): A privacy policy page was found with substantive content.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": true,
    "status": 200,
    "text_chars": 342,
    "url": "https://example.com/privacy"
  }
  ```

  </details>

- **CORE-TRUST-005** — Terms/conditions discoverability (info): A terms/conditions page was found with substantive content.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": true,
    "status": 200,
    "text_chars": 324,
    "url": "https://example.com/terms"
  }
  ```

  </details>

- **CORE-TRUST-006** — security.txt discoverability (info): A valid security.txt was found with a contact method.

  <details><summary>evidence</summary>

  ```json
  {
    "contact": true,
    "expires": null,
    "expires_valid": null,
    "found_url": "https://example.com/.well-known/security.txt",
    "status": 200
  }
  ```

  </details>

- **CORE-TRUST-007** — Pricing discoverability (info): A pricing page was found with a readable price.

  <details><summary>evidence</summary>

  ```json
  {
    "has_price_text": true,
    "has_structured_price": false,
    "status": 200,
    "url": "https://example.com/pricing"
  }
  ```

  </details>

### N/A (14)

`CORE-ACCESS-009`, `CORE-ACCESS-010`, `CORE-INTERFACE-001`, `CORE-INTERFACE-002`, `CORE-INTERFACE-003`, `CORE-INTERFACE-005`, `CORE-MACHINE-004`, `CORE-MACHINE-005`, `CORE-MACHINE-006`, `CORE-MACHINE-011`, `CORE-OPERABILITY-009`, `CORE-SECURITY-004`, `CORE-TRUST-002`, `CORE-TRUST-003`

## Experimental (not scored)

- **CORE-SECURITY-011** (PASS) — No indicators found.
- **CORE-SECURITY-012** (PASS) — No indicators found.
- **CORE-SECURITY-013** (PASS) — No indicators found.
- **CORE-SECURITY-014** (PASS) — No indicators found.

N/A: `CORE-ACCESS-011`, `CORE-INTERFACE-004`, `CORE-INTERFACE-008`, `CORE-INTERFACE-009`, `CORE-MACHINE-012`, `CORE-OPERABILITY-007`, `CORE-OPERABILITY-011`, `CORE-SECURITY-009`, `CORE-SECURITY-010`, `CORE-SECURITY-015`, `CORE-SECURITY-016`

## Agentic Security & Trust

_PASSIVE SIGNALS ONLY_

| | |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 2 |
| Web baseline | PASS 1  WARN 2  FAIL 1 |
| Disclosure | PASS 0  WARN 0  FAIL 1 |
| Data exposure | PASS 2  WARN 0  FAIL 0 |
| Prompt surface | PASS 4  WARN 0  FAIL 0 |

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

### CORE-SECURITY-006 (SEC-TXT-001) — security.txt validity (RFC 9116)

- Status: FAIL · Severity: medium · Confidence: high · Verification: DECLARED
- Fix owner: security · Domain: disclosure
- Expires missing or unparsable.
- Remediation: Set Expires to a future date (RFC 3339) and keep it fresh.
- Limitations: Passive signal only. Scovant Core did not authenticate, submit forms or invoke tools; observed authorization behaviour is not tested.
  - Remediation: Set Expires to a future date (RFC 3339) and keep it fresh.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_location": true,
    "canonical_uris": [],
    "contact": true,
    "expired": null,
    "expires": null,
    "found_url": "https://example.com/.well-known/security.txt"
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

Core 0.6.0 · ruleset 2026.10 (digest `fd062c67627f`) · scan `local-golden` · 2026-09-04T00:00:00Z

Verify with real agents: [scovant.com/scan](https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss)

