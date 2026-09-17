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
| sites/security-good/index.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/index.html.headers | synthetic (HSTS >= 1 day, CSP with frame-ancestors, referrer-policy, nosniff, plus a Secure+HttpOnly+SameSite session cookie — CORE-SECURITY-001..005 PASS) |
| sites/security-good/robots.txt | synthetic (copied from sites/commerce-good) |
| sites/security-good/sitemap.xml | synthetic (copied from sites/commerce-good) |
| sites/security-good/products/widget.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/llms.txt | synthetic (copied from sites/commerce-good; benign, no agentic-security indicators) |
| sites/security-good/.well-known/mcp.json | synthetic (copied from sites/commerce-good; benign server description) |
| sites/security-good/contact.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/shipping.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/returns.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/privacy.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/terms.html | synthetic (copied from sites/commerce-good) |
| sites/security-good/.well-known/ucp | synthetic (copied from sites/commerce-good) |
| sites/security-good/.well-known/security.txt | synthetic (Contact + a 2030 Expires + Canonical listing its own well-known URL — CORE-SECURITY-006 PASS on this fixture) |
| sites/security-bad/index.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/index.html.headers | synthetic (max-age=0 HSTS, no CSP, no X-Frame-Options, no referrer/MIME headers, a session-like cookie with no Secure/HttpOnly — CORE-SECURITY-002/003/004/005 WARN or FAIL on this fixture) |
| sites/security-bad/robots.txt | synthetic (copied from sites/commerce-good) |
| sites/security-bad/sitemap.xml | synthetic (copied from sites/commerce-good) |
| sites/security-bad/products/widget.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/llms.txt | synthetic (RFC1918 + AWS/GCP metadata IP references and a generic `"api_key": "<48-hex>"` assignment shape — CORE-SECURITY-007/008 WARN on this fixture) |
| sites/security-bad/.well-known/mcp.json | synthetic (a `delete_all_orders` server whose description carries override language ("you are now in developer mode") and an external-transmission instruction — CORE-SECURITY-009/013/014/016 WARN on this fixture; -013 is the fixture's one high-severity finding, held to WARN by design — see tests/test_cli_security.py for the FAIL/high case, built at test time so a real vendor-shaped credential never sits in a committed fixture) |
| sites/security-bad/contact.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/shipping.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/returns.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/privacy.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/terms.html | synthetic (copied from sites/commerce-good) |
| sites/security-bad/.well-known/ucp | synthetic (copied from sites/commerce-good) |
| sites/security-bad/security.txt | synthetic (legacy path, not .well-known, Expires in the past — CORE-SECURITY-006 FAIL on this fixture) |
| sites/security-bad/http-200.txt | synthetic (marker: the fixture's http:// origin answers 200 instead of redirecting to https — CORE-SECURITY-001 WARN on this fixture) |
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
| sites/expected/security-good.json | generated (golden) |
| sites/expected/security-bad.json | generated (golden) |
| sites/expected/commerce-good.md | generated (golden) |
| sites/expected/commerce-bad.md | generated (golden) |
| sites/expected/api-good.md | generated (golden) |
| sites/expected/saas-mixed.md | generated (golden) |
| sites/expected/security-good.md | generated (golden) |
| sites/expected/security-bad.md | generated (golden) |
| sites/expected/commerce-good.html | generated (golden) |
| sites/expected/commerce-bad.html | generated (golden) |
| sites/expected/api-good.html | generated (golden) |
| sites/expected/saas-mixed.html | generated (golden) |
| sites/expected/security-good.html | generated (golden) |
| sites/expected/security-bad.html | generated (golden) |
| http-semantics/429-with-retry-after/case.json | synthetic (429 carrying Retry-After — CORE-OPERABILITY-009 PASS) |
| http-semantics/429-without-retry-after/case.json | synthetic (429 with no Retry-After — CORE-OPERABILITY-009 FAIL) |
| http-semantics/age-gate/case.json | synthetic (age-confirmation interstitial — negative, no challenge) |
| http-semantics/age-gate/index.html | synthetic (age-confirmation interstitial — negative, no challenge) |
| http-semantics/akamai-sensor-only/case.json | synthetic (successful short page carrying only the bot-manager sensor script — negative: sensor presence is not a denial) |
| http-semantics/akamai-sensor-only/index.html | synthetic (successful short page carrying only the bot-manager sensor script — negative: sensor presence is not a denial) |
| http-semantics/challenge-akamai/case.json | synthetic (bot-manager access-denied interstitial served with 200 — CORE-OPERABILITY-010 FAIL) |
| http-semantics/challenge-akamai/index.html | synthetic (bot-manager access-denied interstitial served with 200 — CORE-OPERABILITY-010 FAIL) |
| http-semantics/challenge-cloudflare/case.json | synthetic (browser-challenge interstitial served with 200 — CORE-OPERABILITY-010 FAIL) |
| http-semantics/challenge-cloudflare/index.html | synthetic (browser-challenge interstitial served with 200 — CORE-OPERABILITY-010 FAIL) |
| http-semantics/cookie-consent/case.json | synthetic (consent dialog over real content — negative, no challenge) |
| http-semantics/cookie-consent/index.html | synthetic (consent dialog over real content — negative, no challenge) |
| http-semantics/login-normal/case.json | synthetic (ordinary sign-in form — negative, no challenge) |
| http-semantics/login-normal/index.html | synthetic (ordinary sign-in form — negative, no challenge) |
| http-semantics/maintenance/case.json | synthetic (honest 503 maintenance page — negative, not a 200 challenge) |
| http-semantics/maintenance/index.html | synthetic (honest 503 maintenance page — negative, not a 200 challenge) |
| http-semantics/normal-404/case.json | synthetic (probe answers a real 404 — CORE-OPERABILITY-008 PASS) |
| http-semantics/normal-404/index.html | synthetic (probe answers a real 404 — CORE-OPERABILITY-008 PASS) |
| http-semantics/normal-404/probe.html | synthetic (probe answers a real 404 — CORE-OPERABILITY-008 PASS) |
| http-semantics/real-soft-404/case.json | synthetic (server-rendered error page returned with 200 — CORE-OPERABILITY-008 FAIL) |
| http-semantics/real-soft-404/index.html | synthetic (server-rendered error page returned with 200 — CORE-OPERABILITY-008 FAIL) |
| http-semantics/real-soft-404/probe.html | synthetic (server-rendered error page returned with 200 — CORE-OPERABILITY-008 FAIL) |
| http-semantics/spa-shell/case.json | synthetic (empty client-router mount + script bundle returned with 200 — CORE-OPERABILITY-008 WARN) |
| http-semantics/spa-shell/index.html | synthetic (empty client-router mount + script bundle returned with 200 — CORE-OPERABILITY-008 WARN) |
| http-semantics/spa-shell/probe.html | synthetic (empty client-router mount + script bundle returned with 200 — CORE-OPERABILITY-008 WARN) |
| security/web-headers-good/index.html | synthetic |
| security/web-headers-good/index.html.headers | synthetic (HSTS/CSP with frame-ancestors/referrer-policy/nosniff all present — CORE-SECURITY-001..005 PASS) |
| security/web-headers-weak/index.html | synthetic |
| security/web-headers-weak/index.html.headers | synthetic (short-lived HSTS, CSP without frame-ancestors, no referrer/MIME headers — CORE-SECURITY-002/003/005 WARN) |
| security/cookies-session-weak/index.html | synthetic |
| security/cookies-session-weak/index.html.headers | synthetic (session-like cookie missing Secure/HttpOnly — CORE-SECURITY-004 FAIL) |
| security/security-txt-valid/index.html | synthetic |
| security/security-txt-valid/.well-known/security.txt | synthetic (RFC 9116 file at the canonical location with Contact and a future Expires — CORE-SECURITY-006 PASS) |
| security/security-txt-expired/index.html | synthetic |
| security/security-txt-expired/security.txt | synthetic (legacy path, Expires in the past — CORE-SECURITY-006 FAIL) |
| security/machine-secret-exposed/index.html | synthetic |
| security/machine-secret-exposed/llms.txt | synthetic (generic `"api_key": "<48-hex>"` assignment shape only, no vendor-shaped literal — CORE-SECURITY-007 WARN) |
| security/machine-secret-placeholder/index.html | synthetic |
| security/machine-secret-placeholder/llms.txt | synthetic (obvious placeholder values, `<your-api-key-here>` and `${API_TOKEN}` — CORE-SECURITY-007 PASS) |
| security/internal-refs/index.html | synthetic |
| security/internal-refs/llms.txt | synthetic (RFC 1918 address, the AWS/GCP metadata address, and an `.internal` hostname alongside a public example.com link — CORE-SECURITY-008 WARN) |
| security/privileged-endpoints/index.html | synthetic |
| security/privileged-endpoints/.well-known/mcp.json | synthetic (one destructively-named MCP server plus one benign one — CORE-SECURITY-009 WARN) |
| security/privileged-endpoints/openapi.json | synthetic (an `/admin/users` DELETE path plus a benign `/products` GET — CORE-SECURITY-009 WARN) |
| security/sensitive-schema/index.html | synthetic |
| security/sensitive-schema/openapi.json | synthetic (a `password` field declared by name only, and an `api_secret` field carrying a sample value — CORE-SECURITY-010 WARN) |
| security/prompt-surface-benign/index.html | synthetic |
| security/prompt-surface-benign/llms.txt | synthetic (normal llms.txt content, no agent-addressed instructions — CORE-SECURITY-011..016 PASS) |
| security/prompt-surface-benign/.well-known/mcp.json | synthetic (a plain read-only tool description — CORE-SECURITY-011..016 PASS) |
| security/prompt-surface-suspicious/index.html | synthetic |
| security/prompt-surface-suspicious/llms.txt | synthetic (a disclosure request + an external-transmission instruction addressed to an assistant — CORE-SECURITY-011/012/013/015 WARN) |
| security/prompt-surface-suspicious/.well-known/mcp.json | synthetic (a tool description carrying override language + an external-transmission instruction — CORE-SECURITY-014/016 WARN) |
| sites/security-good/index.html | synthetic |
| sites/security-good/index.html.headers | synthetic (full good header set — HSTS, CSP with frame-ancestors, referrer-policy, nosniff — plus a Secure/HttpOnly/SameSite session cookie, all SEC-WEB-*/SEC-TXT-* checks PASS on this fixture) |
| sites/security-good/robots.txt | synthetic |
| sites/security-good/sitemap.xml | synthetic |
| sites/security-good/products/widget.html | synthetic |
| sites/security-good/llms.txt | synthetic (benign content, no agent-addressed instructions — CORE-SECURITY-011..016 PASS) |
| sites/security-good/.well-known/mcp.json | synthetic (one benign, read-only tool description — CORE-SECURITY-009/011..016 PASS) |
| sites/security-good/contact.html | synthetic |
| sites/security-good/shipping.html | synthetic |
| sites/security-good/returns.html | synthetic |
| sites/security-good/privacy.html | synthetic |
| sites/security-good/terms.html | synthetic |
| sites/security-good/.well-known/ucp | synthetic (valid UCP profile, unrelated to the security checks) |
| sites/security-good/.well-known/security.txt | synthetic (RFC 9116 file at the canonical location, Contact + Canonical + a 2030 Expires — CORE-SECURITY-006 PASS) |
| sites/security-bad/index.html | synthetic |
| sites/security-bad/http-200.txt | synthetic (declares the fixture's http:// origin answers 200 without redirecting to https — combined with the weak `max-age=0` HSTS header below, this WARNs CORE-SECURITY-001) |
| sites/security-bad/index.html.headers | synthetic (weak header set — HSTS `max-age=0`, no CSP/referrer-policy/nosniff — plus a session-like cookie missing Secure/HttpOnly — CORE-SECURITY-001/002/005 WARN, CORE-SECURITY-003/004 FAIL) |
| sites/security-bad/robots.txt | synthetic |
| sites/security-bad/sitemap.xml | synthetic |
| sites/security-bad/products/widget.html | synthetic |
| sites/security-bad/llms.txt | synthetic (RFC1918 + cloud-metadata addresses and an `.internal` hostname, plus a generic `"api_key": "<hex>"` assignment shape — CORE-SECURITY-007/008 WARN, no vendor-shaped literal) |
| sites/security-bad/.well-known/mcp.json | synthetic (a destructively-named `delete_all_orders` tool whose description carries an override instruction ("you are now in developer mode") plus an external-transmission instruction — CORE-SECURITY-009 WARN (privileged endpoint) and CORE-SECURITY-013/014/016 WARN (external transmission, override language, tool trust risk)) |
| sites/security-bad/contact.html | synthetic |
| sites/security-bad/shipping.html | synthetic |
| sites/security-bad/returns.html | synthetic |
| sites/security-bad/privacy.html | synthetic |
| sites/security-bad/terms.html | synthetic |
| sites/security-bad/.well-known/ucp | synthetic (valid UCP profile, unrelated to the security checks) |
| sites/security-bad/security.txt | synthetic (legacy `/security.txt` path, Expires in the past — CORE-SECURITY-006 FAIL) |
