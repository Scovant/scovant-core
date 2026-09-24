# Scovant Core — https://example.com/

## Score

**Scovant Core Static Signal Score:** 100 / 100 · grade A · coverage 100%
**Scope:** CANONICAL · **Status:** OK · **Errors:** 0
**Profile:** commerce (requested auto, confidence 85%)

**Capabilities detected** (descriptive, not scored): mcp: present · webmcp: absent · ucp: present · llms_txt: present · openapi: not_checked · oauth: not_checked · content_signal: present · security_txt: present
**Standards:** AgentReady v1.0 (descriptive, not scored): MUST 3/3 measured — 3 pass · SHOULD 5/12 measured — 5 pass · MAY none measured (0/3) — Mapping: docs/standards/agentready.md

## Categories

| Category | Weight | Score | Evaluated / applicable |
|---|---:|---:|---:|
| Access & Discovery | 25 | 100 | 25 / 25 |
| Machine Understanding | 25 | 100 | 23 / 23 |
| Agent Interfaces | 20 | 100 | 5 / 5 |
| Trust & Commerce | 15 | 100 | 15 / 15 |
| Operability & Efficiency | 15 | 100 | 16 / 16 |

66 checks: 51 PASS, 3 WARN, 1 FAIL, 11 N/A, 0 ERROR

## Top findings

- **[security]** **CORE-SECURITY-003** — Neither Content-Security-Policy nor X-Frame-Options is sent.
- **[security]** **CORE-SECURITY-002** — No Strict-Transport-Security header.
- **[security]** **CORE-SECURITY-005** — Missing: referrer-policy, x-content-type-options.

## Findings

### FAIL (1)

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

### WARN (2)

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

### PASS (41)

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
    "sha256": "a3b24ab6056572a5c127bc7a4dba409e656da1245ef936633bab52b8b395efcf",
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

- **CORE-ACCESS-004** — Training vs. search crawler separation (info): Training/content-use crawler(s) GPTBot, Google-Extended are restricted while search/retrieval crawlers remain allowed.

  <details><summary>evidence</summary>

  ```json
  {
    "explicit_separation": true,
    "http_status": 200,
    "resource": "https://example.com/robots.txt",
    "search_blocked": [],
    "training_blocked": [
      "GPTBot",
      "Google-Extended"
    ]
  }
  ```

  </details>

- **CORE-ACCESS-005** — Sitemap availability (info): A valid urlset sitemap was found at https://example.com/sitemap.xml.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_count": 3,
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

- **CORE-ACCESS-006** — Sitemap freshness (info): Sitemap lastmod values look plausible.

  <details><summary>evidence</summary>

  ```json
  {
    "dated_entry_count": 3,
    "entry_count": 3,
    "newest": "2026-08-15",
    "oldest": "2026-07-01",
    "url": "https://example.com/sitemap.xml"
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

- **CORE-ACCESS-009** — llms.txt presence and integrity (info): llms.txt is well-formed and its 2 checked references resolve.

  <details><summary>evidence</summary>

  ```json
  {
    "errors": [],
    "references_broken": [],
    "references_checked": 2,
    "references_unresolved": [],
    "resource": "https://example.com/llms.txt",
    "valid": true
  }
  ```

  </details>

- **CORE-ACCESS-010** — Content-Signal declaration (info): Content-Signal is declared and internally consistent.

  <details><summary>evidence</summary>

  ```json
  {
    "declared": true,
    "dimensions": {
      "ai-input": "yes",
      "ai-train": "no",
      "search": "yes"
    },
    "syntax_errors": []
  }
  ```

  </details>

- **CORE-INTERFACE-001** — MCP discovery presence (info): An MCP discovery file is published and well-formed.

  <details><summary>evidence</summary>

  ```json
  {
    "declared_name": "example-shop",
    "endpoints": [
      "https://example.com/mcp"
    ],
    "exists": true,
    "http_status": 200,
    "resource": "https://example.com/.well-known/mcp.json",
    "server_card": false,
    "valid": true
  }
  ```

  </details>

- **CORE-INTERFACE-002** — MCP server declaration quality (info): Every declared MCP server has a name, url, transport, and a real description.

  <details><summary>evidence</summary>

  ```json
  {
    "servers_count": 1
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
        "parsed": 2,
        "raw": 2,
        "url": "https://example.com/products/widget"
      },
      {
        "parsed": 0,
        "raw": 0,
        "url": "https://example.com/contact"
      }
    ],
    "parsed_total": 4,
    "raw_total": 4
  }
  ```

  </details>

- **CORE-MACHINE-002** — Organization entity (info): An Organization entity declares name and url.

  <details><summary>evidence</summary>

  ```json
  {
    "found": true,
    "has_description": false,
    "has_logo": true,
    "has_sameAs": false,
    "name": "Example Shop",
    "pages_parsed": 3,
    "url": "https://example.com/"
  }
  ```

  </details>

- **CORE-MACHINE-003** — WebSite/WebPage entity (info): A WebSite or WebPage entity was found on the sampled pages.

  <details><summary>evidence</summary>

  ```json
  {
    "found": true,
    "pages_parsed": 3
  }
  ```

  </details>

- **CORE-MACHINE-004** — Product structured data (info): A sampled product page exposes a Product entity with an identifier.

  <details><summary>evidence</summary>

  ```json
  {
    "has_identifiers": true,
    "pages_parsed": 3,
    "product_pages": [
      "https://example.com/products/widget"
    ]
  }
  ```

  </details>

- **CORE-MACHINE-005** — Offer price, currency, and availability (info): The product's Offer declares price, currency, and availability.

  <details><summary>evidence</summary>

  ```json
  {
    "availability": "https://schema.org/InStock",
    "currency": "USD",
    "missing": [],
    "price": 19.99,
    "url": "https://example.com/products/widget"
  }
  ```

  </details>

- **CORE-MACHINE-006** — Product identifier count (info): Product entities declare two or more stable identifiers.

  <details><summary>evidence</summary>

  ```json
  {
    "count": 2,
    "identifier_keys": [
      "brand",
      "sku"
    ],
    "pages_parsed": 3
  }
  ```

  </details>

- **CORE-MACHINE-007** — Breadcrumbs (info): A sampled non-entry page declares a BreadcrumbList.

  <details><summary>evidence</summary>

  ```json
  {
    "has_breadcrumb": true,
    "non_entry_pages": [
      "https://example.com/products/widget",
      "https://example.com/contact"
    ],
    "non_entry_parsed": 2
  }
  ```

  </details>

- **CORE-MACHINE-008** — Metadata quality (info): The entry page declares title, description, and Open Graph tags.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "issues": [],
    "meta_description": "Example Shop sells widgets.",
    "missing": [],
    "title": "Example Shop — Widgets"
  }
  ```

  </details>

- **CORE-MACHINE-009** — Heading structure (info): The entry page has a single H1 and no skipped heading levels.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "h1_count": 1,
    "heading_count": 2,
    "issues": [],
    "levels": [
      "h1",
      "h2"
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

- **CORE-MACHINE-011** — Image alt coverage (info): 1/1 images have an alt attribute (ratio 100%).

  <details><summary>evidence</summary>

  ```json
  {
    "covered": 1,
    "empty_alt": 0,
    "pages_parsed": 3,
    "ratio": 1.0,
    "total": 1,
    "with_alt": 1
  }
  ```

  </details>

- **CORE-OPERABILITY-001** — Server-rendered core content (info): The entry page's static HTML carries 337 chars of visible text.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/",
    "spa_shell_marker": false,
    "visible_text_chars": 337
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
    "etag": "\"commerce-good-v1\"",
    "last_modified": null
  }
  ```

  </details>

- **CORE-OPERABILITY-004** — Broken machine-consumable endpoints (info): All 6 checked machine-consumable reference(s) resolve.

  <details><summary>evidence</summary>

  ```json
  {
    "broken": [],
    "broken_count": 0,
    "inconclusive": [
      {
        "source": "mcp_endpoint",
        "status": 404,
        "url": "https://example.com/mcp"
      }
    ],
    "refs_checked": 7,
    "refs_resolved": 6,
    "unresolved": []
  }
  ```

  </details>

- **CORE-OPERABILITY-005** — Agent parse cost (info): The entry page's estimated parse cost is ~84 tokens (low).

  <details><summary>evidence</summary>

  ```json
  {
    "dom_nodes": 24,
    "estimated_tokens": 84,
    "html_bytes": 1315,
    "level": "LOW",
    "link_count": 7,
    "script_bytes": 247,
    "script_ratio": 0.18783269961977186,
    "structured_bytes": 247,
    "text_chars": 337,
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
    "pages_checked": 4
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

- **CORE-SECURITY-006** — security.txt validity (RFC 9116) (info): security.txt is at the canonical location, has Contact and a future Expires.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_location": true,
    "canonical_uris": [],
    "contact": true,
    "expired": false,
    "expires": "2030-01-01T00:00:00Z",
    "found_url": "https://example.com/.well-known/security.txt"
  }
  ```

  </details>

- **CORE-SECURITY-007** — Credential-like value exposed in a machine-facing surface (info): No credential-like values in the gathered machine-facing surfaces.

  <details><summary>evidence</summary>

  ```json
  {
    "hit_count": 0,
    "hits": [],
    "surfaces_scanned": 7
  }
  ```

  </details>

- **CORE-SECURITY-008** — Internal network reference exposed (info): No internal network references found.

  <details><summary>evidence</summary>

  ```json
  {
    "hits": [],
    "surfaces_scanned": 7
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

- **CORE-TRUST-002** — Shipping policy discoverability (info): A shipping policy page was found with substantive content.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": true,
    "status": 200,
    "text_chars": 300,
    "url": "https://example.com/shipping"
  }
  ```

  </details>

- **CORE-TRUST-003** — Returns/refund policy discoverability (info): A returns/refund policy page was found with substantive content.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": true,
    "status": 200,
    "text_chars": 312,
    "url": "https://example.com/returns"
  }
  ```

  </details>

- **CORE-TRUST-004** — Privacy policy discoverability (info): A privacy policy page was found with substantive content.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": true,
    "status": 200,
    "text_chars": 303,
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
    "text_chars": 334,
    "url": "https://example.com/terms"
  }
  ```

  </details>

- **CORE-TRUST-006** — security.txt discoverability (info): A valid security.txt was found with a contact method.

  <details><summary>evidence</summary>

  ```json
  {
    "contact": true,
    "expires": "2030-01-01T00:00:00Z",
    "expires_valid": true,
    "found_url": "https://example.com/.well-known/security.txt",
    "status": 200
  }
  ```

  </details>

- **CORE-TRUST-007** — Pricing discoverability (info): Prices are exposed as structured product data.

  <details><summary>evidence</summary>

  ```json
  {
    "structured_price": 19.99,
    "url": "https://example.com/products/widget"
  }
  ```

  </details>

### N/A (7)

`CORE-INTERFACE-003`, `CORE-INTERFACE-005`, `CORE-INTERFACE-006`, `CORE-INTERFACE-007`, `CORE-OPERABILITY-006`, `CORE-OPERABILITY-009`, `CORE-SECURITY-004`

## Experimental (not scored)

- **CORE-ACCESS-011** (PASS) — llms.txt links useful same-origin pages and carries no misplaced policy or template text.
- **CORE-INTERFACE-008** (PASS) — A UCP profile is published and valid.
- **CORE-MACHINE-012** (PASS) — The structured price matches a visible price on the page.
- **CORE-OPERABILITY-011** (WARN) — 3 of 3 machine surface(s) are not linked from anything an agent reads: llms_txt, mcp, ucp.
- **CORE-SECURITY-009** (PASS) — No administrative/destructive interfaces advertised.
- **CORE-SECURITY-011** (PASS) — No indicators found.
- **CORE-SECURITY-012** (PASS) — No indicators found.
- **CORE-SECURITY-013** (PASS) — No indicators found.
- **CORE-SECURITY-014** (PASS) — No indicators found.
- **CORE-SECURITY-015** (PASS) — No indicators found.
- **CORE-SECURITY-016** (PASS) — No indicators found.

N/A: `CORE-INTERFACE-004`, `CORE-INTERFACE-009`, `CORE-OPERABILITY-007`, `CORE-SECURITY-010`

## Agentic Security & Trust

_PASSIVE SIGNALS ONLY_

| | |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 2 |
| Web baseline | PASS 1  WARN 2  FAIL 1 |
| Disclosure | PASS 1  WARN 0  FAIL 0 |
| Data exposure | PASS 3  WARN 0  FAIL 0 |
| Prompt surface | PASS 6  WARN 0  FAIL 0 |

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

Core 0.5.2 · ruleset 2026.10 (digest `fd062c67627f`) · scan `local-golden` · 2026-09-04T00:00:00Z

Verify with real agents: [scovant.com/scan](https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss)

