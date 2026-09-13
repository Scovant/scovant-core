# Scovant Core — https://example.com/step4

## Score

**Scovant Core Static Signal Score:** 35 / 100 · grade F · coverage 100%
**Scope:** CANONICAL · **Status:** OK · **Errors:** 0
**Profile:** commerce (requested auto, confidence 85%)

## Categories

| Category | Weight | Score | Evaluated / applicable |
|---|---:|---:|---:|
| Access & Discovery | 25 | 17 | 23 / 23 |
| Machine Understanding | 25 | 41 | 22 / 22 |
| Agent Interfaces | 20 | n/a | 0 / 0 |
| Trust & Commerce | 15 | 42 | 12 / 12 |
| Operability & Efficiency | 15 | 50 | 13 / 13 |

45 checks: 1 PASS, 23 WARN, 8 FAIL, 13 N/A, 0 ERROR

## Top findings

- **CORE-ACCESS-003** — robots.txt declares every major search and answer-engine crawler as disallowed. User-triggered fetch agents blocked: ChatGPT-User, Claude-User, Perplexity-User, DuckAssistBot.
- **CORE-MACHINE-005** — The Product entity has no Offer with price, currency, or availability.
- **CORE-ACCESS-005** — No sitemap was found.
- **CORE-ACCESS-007** — The canonical URL points off-host.
- **CORE-ACCESS-008** — The entry page declares noindex.
- **CORE-OPERABILITY-004** — 2 of 2 machine-consumable reference(s) do not resolve.
- **CORE-ACCESS-002** — robots.txt disallows all crawlers from the entire site.
- **CORE-TRUST-004** — No privacy policy page was found linked from the entry page.

## Findings

### FAIL (8)

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

- **CORE-TRUST-004** — Privacy policy discoverability (high): No privacy policy page was found linked from the entry page.
  - Remediation: Publish a privacy policy page and link it from the entry page's nav or footer.
### WARN (22)

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

### PASS (1)

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

### N/A (9)

`CORE-ACCESS-006`, `CORE-INTERFACE-001`, `CORE-INTERFACE-002`, `CORE-INTERFACE-003`, `CORE-INTERFACE-005`, `CORE-INTERFACE-006`, `CORE-INTERFACE-007`, `CORE-MACHINE-007`, `CORE-TRUST-007`

## Experimental (not scored)

- **CORE-INTERFACE-008** (WARN) — A UCP profile is published but fails validation.

N/A: `CORE-INTERFACE-004`, `CORE-INTERFACE-009`, `CORE-MACHINE-012`, `CORE-OPERABILITY-007`

## Not tested by Scovant Core

- Observed WAF access
- Real agent tasks
- MCP tool execution
- WebMCP state parity
- Multi-model reliability
- Regression stability

## Provenance

Core 0.1.1 · ruleset 2026.09 (digest `ea4ada4fffbf`) · scan `local-golden` · 2026-09-04T00:00:00Z

Verify with real agents: [scovant.com/scan](https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss)

