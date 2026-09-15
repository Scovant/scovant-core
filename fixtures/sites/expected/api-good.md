# Scovant Core — https://example.com/

## Score

**Scovant Core Static Signal Score:** 90 / 100 · grade A · coverage 100%
**Scope:** CANONICAL · **Status:** OK · **Errors:** 0
**Profile:** api (requested auto, confidence 90%)

**Capabilities detected** (descriptive, not scored): mcp: absent · webmcp: absent · ucp: not_checked · llms_txt: absent · openapi: present · oauth: present · content_signal: absent · security_txt: present
**Standards:** AgentReady v1.0 (descriptive, not scored): MUST 3/3 measured — 2 pass, 1 warn · SHOULD 6/12 measured — 4 pass, 2 warn · MAY 1/3 measured — 1 pass — Mapping: docs/standards/agentready.md

## Categories

| Category | Weight | Score | Evaluated / applicable |
|---|---:|---:|---:|
| Access & Discovery | 25 | 100 | 21 / 21 |
| Machine Understanding | 25 | 81 | 8 / 8 |
| Agent Interfaces | 20 | 100 | 6 / 6 |
| Trust & Commerce | 15 | 75 | 8 / 8 |
| Operability & Efficiency | 15 | 88 | 16 / 16 |

50 checks: 23 PASS, 6 WARN, 0 FAIL, 21 N/A, 0 ERROR

## Top findings

- **CORE-OPERABILITY-001** — The entry page's static HTML carries only 155 chars of visible text (< 200).
- **CORE-MACHINE-002** — No Organization entity was found on the sampled pages.
- **CORE-TRUST-004** — A privacy policy page was found but has too little text (135 chars) to be a real policy document.
- **CORE-TRUST-005** — No terms/conditions page was found linked from the entry page.
- **CORE-MACHINE-003** — No WebSite or WebPage entity was found on the sampled pages.
- **CORE-OPERABILITY-003** — The entry response carries no cache validator (ETag, Last-Modified, or Cache-Control).

## Findings

### WARN (6)

- **CORE-MACHINE-002** — Organization entity (medium): No Organization entity was found on the sampled pages.
  - Remediation: Add JSON-LD with "@type": "Organization" declaring at least name and url.

  <details><summary>evidence</summary>

  ```json
  {
    "found": false,
    "pages_parsed": 3
  }
  ```

  </details>

- **CORE-MACHINE-003** — WebSite/WebPage entity (low): No WebSite or WebPage entity was found on the sampled pages.
  - Remediation: Add JSON-LD with "@type": "WebSite" or "WebPage".

  <details><summary>evidence</summary>

  ```json
  {
    "found": false,
    "pages_parsed": 3
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

- **CORE-TRUST-004** — Privacy policy discoverability (high): A privacy policy page was found but has too little text (135 chars) to be a real policy document.
  - Remediation: Publish a privacy policy page and link it from the entry page's nav or footer.

  <details><summary>evidence</summary>

  ```json
  {
    "served_as_html": true,
    "status": 200,
    "text_chars": 135,
    "url": "https://example.com/privacy"
  }
  ```

  </details>

- **CORE-TRUST-005** — Terms/conditions discoverability (medium): No terms/conditions page was found linked from the entry page.
  - Remediation: Publish a terms/conditions page and link it from the entry page's nav or footer.
### PASS (21)

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
    "newest": "2026-08-01",
    "oldest": "2026-08-01",
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

- **CORE-INTERFACE-005** — OpenAPI discovery (info): An OpenAPI/Swagger document was discovered and parses.

  <details><summary>evidence</summary>

  ```json
  {
    "candidates_checked": 5,
    "found_url": "https://example.com/openapi.json",
    "openapi_version": "3.1.0",
    "parseable": true
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
    "http_status": 200,
    "parseable": true,
    "resource": "https://example.com/.well-known/oauth-protected-resource",
    "resource_value": "https://example.com",
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
    "pages_checked": 4
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

### N/A (16)

`CORE-ACCESS-009`, `CORE-ACCESS-010`, `CORE-INTERFACE-001`, `CORE-INTERFACE-002`, `CORE-INTERFACE-003`, `CORE-MACHINE-001`, `CORE-MACHINE-004`, `CORE-MACHINE-005`, `CORE-MACHINE-006`, `CORE-MACHINE-007`, `CORE-MACHINE-011`, `CORE-OPERABILITY-006`, `CORE-OPERABILITY-009`, `CORE-TRUST-002`, `CORE-TRUST-003`, `CORE-TRUST-007`

## Experimental (not scored)

- **CORE-INTERFACE-009** (PASS) — An agent discovery surface is published (a2a_card).
- **CORE-OPERABILITY-011** (PASS) — All 1 present machine surface(s) are linked from something an agent reads.

N/A: `CORE-ACCESS-011`, `CORE-INTERFACE-004`, `CORE-INTERFACE-008`, `CORE-MACHINE-012`, `CORE-OPERABILITY-007`

## Not tested by Scovant Core

- Observed WAF access
- Real agent tasks
- MCP tool execution
- WebMCP state parity
- Multi-model reliability
- Regression stability

## Provenance

Core 0.3.1 · ruleset 2026.10 (digest `ab5851b14f6a`) · scan `local-golden` · 2026-09-04T00:00:00Z

Verify with real agents: [scovant.com/scan](https://scovant.com/scan?utm_source=scovant-core&utm_medium=cli&utm_campaign=oss)

