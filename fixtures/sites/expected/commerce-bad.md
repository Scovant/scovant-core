# Scovant Core — https://example.com/step4

## Score

**Scovant Core Static Signal Score:** 38 / 100 · grade F · coverage 100%
**Scope:** CANONICAL · **Status:** OK · **Errors:** 0
**Profile:** commerce (requested auto, confidence 85%)

**Capabilities detected** (descriptive, not scored): mcp: absent · webmcp: absent · ucp: invalid · llms_txt: invalid · openapi: not_checked · oauth: not_checked · content_signal: invalid · security_txt: invalid
**Standards:** AgentReady v1.0 (descriptive, not scored): MUST 3/3 measured — 1 warn, 2 fail · SHOULD 4/12 measured — 3 warn, 1 fail · MAY none measured (0/3) — Mapping: docs/standards/agentready.md

## Categories

| Category | Weight | Score | Evaluated / applicable |
|---|---:|---:|---:|
| Access & Discovery | 25 | 17 | 23 / 23 |
| Machine Understanding | 25 | 41 | 22 / 22 |
| Agent Interfaces | 20 | n/a | 0 / 0 |
| Trust & Commerce | 15 | 42 | 12 / 12 |
| Operability & Efficiency | 15 | 64 | 18 / 18 |

66 checks: 12 PASS, 26 WARN, 10 FAIL, 18 N/A, 0 ERROR

## Top findings

- **CORE-ACCESS-003** — robots.txt declares every major search and answer-engine crawler as disallowed. User-triggered fetch agents blocked: ChatGPT-User, Claude-User, Perplexity-User, DuckAssistBot.
- **CORE-MACHINE-005** — The Product entity has no Offer with price, currency, or availability.
- **CORE-ACCESS-005** — No sitemap was found.
- **CORE-ACCESS-007** — The canonical URL points off-host.
- **CORE-ACCESS-008** — The entry page declares noindex.
- **CORE-OPERABILITY-004** — 2 of 2 machine-consumable reference(s) do not resolve.
- **CORE-ACCESS-002** — robots.txt disallows all crawlers from the entire site.
- **CORE-TRUST-004** — No privacy policy page was found linked from the entry page.
- **[security]** **CORE-SECURITY-003** — Neither Content-Security-Policy nor X-Frame-Options is sent.
- **[security]** **CORE-SECURITY-006** — Expires is in the past.
- **[security]** **CORE-SECURITY-002** — No Strict-Transport-Security header.
- **[security]** **CORE-SECURITY-005** — Missing: referrer-policy, x-content-type-options.

## Findings

### FAIL (10)

- **CORE-ACCESS-002** — robots.txt availability and syntax (medium): robots.txt disallows all crawlers from the entire site.
  - Remediation: Scope Disallow rules to specific paths instead of blocking `/` for `*`.

  <details><summary>evidence</summary>

  ```json
  {
    "error": null,
    "resource": "https://example.com/robots.txt",
    "served_as_html": false,
    "sha256": "901c28336f0ee2ceb8b00545721bc3a75c09d539b54d031ab78f34d43f7e5294",
    "sitemap_count": 0,
    "status": 200,
    "unknown_directives": []
  }
  ```

  </details>

- **CORE-ACCESS-003** — AI search crawler policy (high): robots.txt declares every major search and answer-engine crawler as disallowed. User-triggered fetch agents blocked: ChatGPT-User, Claude-User, Perplexity-User, DuckAssistBot.
  - Remediation: Allow search/retrieval crawlers (OAI-SearchBot, Claude-SearchBot, PerplexityBot, …) in robots.txt while keeping any training restrictions separate.

  <details><summary>evidence</summary>

  ```json
  {
    "declared_policy": {
      "Applebot": false,
      "Bingbot": false,
      "Claude-SearchBot": false,
      "Googlebot": false,
      "OAI-SearchBot": false,
      "PerplexityBot": false
    },
    "http_status": 200,
    "resource": "https://example.com/robots.txt",
    "robots_present": true,
    "user_fetch_policy": {
      "ChatGPT-User": false,
      "Claude-User": false,
      "DuckAssistBot": false,
      "Perplexity-User": false
    }
  }
  ```

  </details>

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

- **CORE-ACCESS-007** — Canonical URL integrity (medium): The canonical URL points off-host.
  - Remediation: Point the canonical tag at a URL on this site's own host.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_url": "https://example.org/elsewhere",
    "entry_url": "https://example.com/step4"
  }
  ```

  </details>

- **CORE-ACCESS-008** — Indexability (high): The entry page declares noindex.
  - Remediation: Remove the noindex directive from the meta robots tag or X-Robots-Tag header.

  <details><summary>evidence</summary>

  ```json
  {
    "robots_meta": "noindex",
    "x_robots_tag": null
  }
  ```

  </details>

- **CORE-MACHINE-005** — Offer price, currency, and availability (high): The Product entity has no Offer with price, currency, or availability.
  - Remediation: Add an Offer with price, priceCurrency, and availability to the Product entity.

  <details><summary>evidence</summary>

  ```json
  {
    "availability": null,
    "currency": null,
    "missing": [
      "price",
      "priceCurrency",
      "availability"
    ],
    "price": null,
    "url": "https://example.com/step4"
  }
  ```

  </details>

- **CORE-OPERABILITY-004** — Broken machine-consumable endpoints (high): 2 of 2 machine-consumable reference(s) do not resolve.
  - Remediation: Fix or remove the broken references (sitemap, llms.txt, OpenAPI spec, policy links) so agents don't hit dead links.

  <details><summary>evidence</summary>

  ```json
  {
    "broken": [
      {
        "source": "canonical",
        "status": 404,
        "url": "https://example.org/elsewhere"
      },
      {
        "source": "llms",
        "status": 404,
        "url": "https://example.com/does-not-exist"
      }
    ],
    "broken_count": 2,
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

- **CORE-SECURITY-006** — security.txt validity (RFC 9116) (medium): Expires is in the past.
  - Remediation: Set Expires to a future date (RFC 3339) and keep it fresh.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_location": true,
    "canonical_uris": [],
    "contact": false,
    "expired": true,
    "expires": "2020-01-01T00:00:00Z",
    "found_url": "https://example.com/.well-known/security.txt"
  }
  ```

  </details>

- **CORE-TRUST-004** — Privacy policy discoverability (high): No privacy policy page was found linked from the entry page.
  - Remediation: Publish a privacy policy page and link it from the entry page's nav or footer.
### WARN (24)

- **CORE-ACCESS-001** — HTTPS reachability (low): The entry URL redirects 4 times before settling.
  - Remediation: Collapse the redirect chain to at most one hop.

  <details><summary>evidence</summary>

  ```json
  {
    "final_url": "https://example.com/step4",
    "input_url": "https://example.com/",
    "redirect_chain": [
      "https://example.com/",
      "https://example.com/step1",
      "https://example.com/step2",
      "https://example.com/step3"
    ],
    "redirect_count": 4,
    "status": 200
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
      "OAI-SearchBot",
      "Claude-SearchBot",
      "PerplexityBot",
      "Applebot",
      "Googlebot",
      "Bingbot"
    ],
    "training_blocked": [
      "GPTBot",
      "ClaudeBot",
      "Applebot-Extended",
      "CCBot",
      "Google-Extended"
    ]
  }
  ```

  </details>

- **CORE-ACCESS-009** — llms.txt presence and integrity (low): llms.txt references 1 link(s) that do not resolve.
  - Remediation: Remove or fix the broken references in llms.txt.

  <details><summary>evidence</summary>

  ```json
  {
    "errors": [],
    "references_broken": [
      "https://example.com/does-not-exist"
    ],
    "references_checked": 1,
    "references_unresolved": [],
    "resource": "https://example.com/llms.txt",
    "valid": true
  }
  ```

  </details>

- **CORE-ACCESS-010** — Content-Signal declaration (low): Content-Signal is declared but has syntax error(s).
  - Remediation: Fix the Content-Signal directive, e.g. "Content-Signal: search=yes, ai-input=yes, ai-train=no".

  <details><summary>evidence</summary>

  ```json
  {
    "declared": true,
    "dimensions": {
      "ai-input": "unset",
      "ai-train": "unset",
      "search": "unset"
    },
    "syntax_errors": [
      "unrecognized value for 'search': 'maybe' (expected yes|no)"
    ]
  }
  ```

  </details>

- **CORE-MACHINE-001** — JSON-LD parseability (medium): Some JSON-LD blocks on the sampled pages fail to parse as valid JSON.
  - Remediation: Fix the malformed JSON-LD blocks so every one parses (validate with a JSON linter before publishing).

  <details><summary>evidence</summary>

  ```json
  {
    "pages": [
      {
        "parsed": 1,
        "raw": 2,
        "url": "https://example.com/step4"
      }
    ],
    "parsed_total": 1,
    "raw_total": 2
  }
  ```

  </details>

- **CORE-MACHINE-002** — Organization entity (medium): No Organization entity was found on the sampled pages.
  - Remediation: Add JSON-LD with "@type": "Organization" declaring at least name and url.

  <details><summary>evidence</summary>

  ```json
  {
    "found": false,
    "pages_parsed": 1
  }
  ```

  </details>

- **CORE-MACHINE-003** — WebSite/WebPage entity (low): No WebSite or WebPage entity was found on the sampled pages.
  - Remediation: Add JSON-LD with "@type": "WebSite" or "WebPage".

  <details><summary>evidence</summary>

  ```json
  {
    "found": false,
    "pages_parsed": 1
  }
  ```

  </details>

- **CORE-MACHINE-004** — Product structured data (high): A Product entity exists but carries no identifiers.
  - Remediation: Add a stable identifier (sku, gtin, mpn, or brand) to the Product entity.

  <details><summary>evidence</summary>

  ```json
  {
    "has_identifiers": false,
    "pages_parsed": 1,
    "product_pages": [
      "https://example.com/step4"
    ]
  }
  ```

  </details>

- **CORE-MACHINE-006** — Product identifier count (medium): Product entities declare no stable identifiers.
  - Remediation: Add a stable identifier (sku, gtin, mpn, or brand) to the Product entity.

  <details><summary>evidence</summary>

  ```json
  {
    "count": 0,
    "identifier_keys": [],
    "pages_parsed": 1
  }
  ```

  </details>

- **CORE-MACHINE-008** — Metadata quality (low): The entry page's metadata has issues: og:title, og:description.
  - Remediation: Add the missing metadata tags and give title and description distinct content.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/step4",
    "issues": [
      "og:title",
      "og:description"
    ],
    "meta_description": "A synthetic fixture site with several broken agent-readiness signals.",
    "missing": [
      "og:title",
      "og:description"
    ],
    "title": "Example Bad Shop"
  }
  ```

  </details>

- **CORE-MACHINE-009** — Heading structure (low): The entry page's heading structure has issues: multiple H1.
  - Remediation: Use exactly one H1 per page and avoid skipping heading levels (e.g. h1 to h3).

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/step4",
    "h1_count": 2,
    "heading_count": 2,
    "issues": [
      "multiple H1"
    ],
    "levels": [
      "h1",
      "h1"
    ]
  }
  ```

  </details>

- **CORE-MACHINE-010** — Language declaration (low): The entry page's `lang` attribute is absent or invalid.
  - Remediation: Add a valid `lang` attribute to the `<html>` tag (e.g. `lang="en"`).

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/step4",
    "html_lang": null
  }
  ```

  </details>

- **CORE-MACHINE-011** — Image alt coverage (medium): Only 0/1 images have an alt attribute (ratio 0%).
  - Remediation: Add an alt attribute (or an explicit empty alt for decorative images) to every image.

  <details><summary>evidence</summary>

  ```json
  {
    "covered": 0,
    "empty_alt": 0,
    "pages_parsed": 1,
    "ratio": 0.0,
    "total": 1,
    "with_alt": 0
  }
  ```

  </details>

- **CORE-OPERABILITY-001** — Server-rendered core content (medium): The entry page's static HTML carries only 148 chars of visible text (< 200).
  - Remediation: Server-render (or statically pre-render) the core content so an agent's plain HTTP fetch sees it.

  <details><summary>evidence</summary>

  ```json
  {
    "entry_url": "https://example.com/step4",
    "spa_shell_marker": false,
    "visible_text_chars": 148
  }
  ```

  </details>

- **CORE-OPERABILITY-002** — Redirect chain complexity (low): The entry URL redirects 4 times before settling.
  - Remediation: Collapse the redirect chain to at most one hop.

  <details><summary>evidence</summary>

  ```json
  {
    "redirect_chain": [
      "https://example.com/",
      "https://example.com/step1",
      "https://example.com/step2",
      "https://example.com/step3"
    ],
    "redirect_count": 4
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

- **CORE-OPERABILITY-006** — Form/control labels (medium): 1 control(s) across 1 form(s) lack a label or accessible name.
  - Remediation: Add a <label> (or aria-label/aria-labelledby) to every input/select, and a name or accessible text to every button.

  <details><summary>evidence</summary>

  ```json
  {
    "totals": {
      "forms": 1,
      "inputs": 1,
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

- **CORE-TRUST-001** — Contact/support discoverability (low): No contact or support link found on the entry page.
  - Remediation: Add a clearly labeled contact or support link (a page or a mailto link) to the entry page.

  <details><summary>evidence</summary>

  ```json
  {
    "contact_url": null,
    "kind": null
  }
  ```

  </details>

- **CORE-TRUST-002** — Shipping policy discoverability (medium): No shipping policy page was found linked from the entry page.
  - Remediation: Publish a shipping policy page (cost, timing, carriers) and link it from the entry page's nav or footer.
- **CORE-TRUST-003** — Returns/refund policy discoverability (medium): No returns/refund policy page was found linked from the entry page.
  - Remediation: Publish a returns/refund policy page and link it from the entry page's nav or footer.
- **CORE-TRUST-005** — Terms/conditions discoverability (medium): No terms/conditions page was found linked from the entry page.
  - Remediation: Publish a terms/conditions page and link it from the entry page's nav or footer.
- **CORE-TRUST-006** — security.txt discoverability (medium): security.txt was found but has no Contact field.
  - Remediation: Add a Contact field (RFC 9116) to security.txt.

  <details><summary>evidence</summary>

  ```json
  {
    "contact": false,
    "expires": "2020-01-01T00:00:00Z",
    "expires_valid": false,
    "found_url": "https://example.com/.well-known/security.txt",
    "status": 200
  }
  ```

  </details>

### PASS (6)

- **CORE-OPERABILITY-005** — Agent parse cost (info): The entry page's estimated parse cost is ~37 tokens (low).

  <details><summary>evidence</summary>

  ```json
  {
    "dom_nodes": 16,
    "estimated_tokens": 37,
    "html_bytes": 725,
    "level": "LOW",
    "link_count": 0,
    "script_bytes": 88,
    "script_ratio": 0.12137931034482759,
    "structured_bytes": 88,
    "text_chars": 148,
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
    "pages_checked": 2
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
    "surfaces_scanned": 4
  }
  ```

  </details>

- **CORE-SECURITY-008** — Internal network reference exposed (info): No internal network references found.

  <details><summary>evidence</summary>

  ```json
  {
    "hits": [],
    "surfaces_scanned": 4
  }
  ```

  </details>

### N/A (11)

`CORE-ACCESS-006`, `CORE-INTERFACE-001`, `CORE-INTERFACE-002`, `CORE-INTERFACE-003`, `CORE-INTERFACE-005`, `CORE-INTERFACE-006`, `CORE-INTERFACE-007`, `CORE-MACHINE-007`, `CORE-OPERABILITY-009`, `CORE-SECURITY-004`, `CORE-TRUST-007`

## Experimental (not scored)

- **CORE-ACCESS-011** (PASS) — llms.txt links useful same-origin pages and carries no misplaced policy or template text.
- **CORE-INTERFACE-008** (WARN) — A UCP profile is published but fails validation.
- **CORE-OPERABILITY-011** (WARN) — 2 of 2 machine surface(s) are not linked from anything an agent reads: llms_txt, ucp.
- **CORE-SECURITY-011** (PASS) — No indicators found.
- **CORE-SECURITY-012** (PASS) — No indicators found.
- **CORE-SECURITY-013** (PASS) — No indicators found.
- **CORE-SECURITY-014** (PASS) — No indicators found.
- **CORE-SECURITY-015** (PASS) — No indicators found.

N/A: `CORE-INTERFACE-004`, `CORE-INTERFACE-009`, `CORE-MACHINE-012`, `CORE-OPERABILITY-007`, `CORE-SECURITY-009`, `CORE-SECURITY-010`, `CORE-SECURITY-016`

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
| Prompt surface | PASS 5  WARN 0  FAIL 0 |

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
- Expires is in the past.
- Remediation: Set Expires to a future date (RFC 3339) and keep it fresh.
- Limitations: Passive signal only. Scovant Core did not authenticate, submit forms or invoke tools; observed authorization behaviour is not tested.
  - Remediation: Set Expires to a future date (RFC 3339) and keep it fresh.

  <details><summary>evidence</summary>

  ```json
  {
    "canonical_location": true,
    "canonical_uris": [],
    "contact": false,
    "expired": true,
    "expires": "2020-01-01T00:00:00Z",
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

Core 0.4.0 · ruleset 2026.10 (digest `fd062c67627f`) · scan `local-golden` · 2026-09-04T00:00:00Z

Verify with real agents: [scovant.com/scan](https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss)

