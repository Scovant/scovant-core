# Fixture provenance

Every file under `fixtures/` is listed here. `synthetic` means it was written
by hand for the test suite and contains no third-party content.

`sites/commerce-good/.well-known/mcp.json` deliberately declares an MCP
endpoint (`/mcp`) that the fixture site answers 404 to. That is not an
oversight: an MCP endpoint speaks JSON-RPC over POST and Core never performs
the handshake, so whatever it answers to a GET is inconclusive — the fixture
is what pins CORE-OPERABILITY-004 recording it as `inconclusive` rather than
reporting it as a broken link.

| path | origin |
|---|---|
| html/blog_page.html | synthetic |
| html/product_page.html | synthetic |
| html/spa_shell.html | synthetic |
| sites/commerce-good/index.html | synthetic |
| sites/commerce-good/index.html.headers | synthetic (ETag sidecar so CORE-OPERABILITY-003 PASSes on this fixture) |
| sites/commerce-good/robots.txt | synthetic |
| sites/commerce-good/sitemap.xml | synthetic |
| sites/commerce-good/products/widget.html | synthetic |
| sites/commerce-good/llms.txt | synthetic |
| sites/commerce-good/.well-known/mcp.json | synthetic |
| sites/commerce-good/contact.html | synthetic |
| sites/commerce-good/shipping.html | synthetic |
| sites/commerce-good/returns.html | synthetic |
| sites/commerce-good/privacy.html | synthetic |
| sites/commerce-good/terms.html | synthetic |
| sites/commerce-good/.well-known/ucp | synthetic (valid UCP profile so CORE-INTERFACE-008 PASSes on this fixture) |
| sites/commerce-good/.well-known/security.txt | synthetic (Contact + a 2030 Expires so CORE-TRUST-006 PASSes on this fixture) |
| sites/commerce-bad/index.html.redirect | synthetic |
| sites/commerce-bad/step1.redirect | synthetic |
| sites/commerce-bad/step2.redirect | synthetic |
| sites/commerce-bad/step3.redirect | synthetic |
| sites/commerce-bad/step4.html | synthetic |
| sites/commerce-bad/robots.txt | synthetic |
| sites/commerce-bad/llms.txt | synthetic |
| sites/commerce-bad/.well-known/ucp | synthetic (deliberately malformed JSON so CORE-INTERFACE-008 WARNs on this fixture) |
| sites/commerce-bad/.well-known/security.txt | synthetic (no Contact field so CORE-TRUST-006 WARNs on this fixture) |
| sites/api-good/index.html | synthetic |
| sites/api-good/openapi.json | synthetic |
| sites/api-good/robots.txt | synthetic |
| sites/api-good/sitemap.xml | synthetic |
| sites/api-good/docs/index.html | synthetic |
| sites/api-good/contact.html | synthetic |
| sites/api-good/privacy.html | synthetic |
| sites/api-good/.well-known/oauth-authorization-server | synthetic |
| sites/api-good/.well-known/oauth-protected-resource | synthetic |
| sites/api-good/.well-known/agent-card.json | synthetic |
| sites/api-good/.well-known/security.txt | synthetic |
| sites/saas-mixed/index.html | synthetic (one image deliberately lacks alt text; CORE-MACHINE-011 scopes to content/commerce only, so on this `saas`-profiled fixture that image is inert for scoring and exists only for the fixture's §6 shape) |
| sites/saas-mixed/index.html.headers | synthetic (ETag sidecar so CORE-OPERABILITY-003 PASSes on this fixture) |
| sites/saas-mixed/pricing.html | synthetic (a visible `$9/month` price) |
| sites/saas-mixed/signup.html | synthetic (a form with one deliberately unlabeled input, for CORE-OPERABILITY-006) |
| sites/saas-mixed/contact.html | synthetic |
| sites/saas-mixed/privacy.html | synthetic |
| sites/saas-mixed/terms.html | synthetic |
| sites/saas-mixed/docs/index.html | synthetic (declares a BreadcrumbList) |
| sites/saas-mixed/robots.txt | synthetic (deliberately blocks PerplexityBot alongside Allow: / so CORE-ACCESS-004 WARNs on this fixture) |
| sites/saas-mixed/sitemap.xml | synthetic (deliberately stale `lastmod` dates so CORE-ACCESS-006 WARNs on this fixture) |
| sites/saas-mixed/.well-known/oauth-authorization-server | synthetic (valid JSON, deliberately incomplete so CORE-INTERFACE-006 WARNs on this fixture) |
| sites/saas-mixed/.well-known/oauth-protected-resource | synthetic (valid JSON, deliberately incomplete so CORE-INTERFACE-007 WARNs on this fixture) |
| sites/saas-mixed/.well-known/security.txt | synthetic (Contact but no Expires) |
| sites/expected/commerce-good.json | generated (golden) |
| sites/expected/commerce-bad.json | generated (golden) |
| sites/expected/api-good.json | generated (golden) |
| sites/expected/saas-mixed.json | generated (golden) |
| sites/expected/commerce-good.md | generated (golden) |
| sites/expected/commerce-bad.md | generated (golden) |
| sites/expected/api-good.md | generated (golden) |
| sites/expected/saas-mixed.md | generated (golden) |
| sites/expected/commerce-good.html | generated (golden) |
| sites/expected/commerce-bad.html | generated (golden) |
| sites/expected/api-good.html | generated (golden) |
| sites/expected/saas-mixed.html | generated (golden) |
