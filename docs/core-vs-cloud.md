# Scovant Core vs Scovant Cloud

Scovant Core measures what a site declares. Scovant Cloud measures what real agents actually experience.

Core identifies itself as `ScovantCore/<version>` and never presents as ScovantBot, the Scovant Cloud crawler identity.

This is a technical comparison, not a marketing one: everything below traces to a real check or a real gap in what a static, unauthenticated fetch can prove.

## Capability matrix

| Capability | Core | Cloud |
|---|:---:|:---:|
| HTTP reachability | ✅ | ✅ |
| robots.txt | ✅ | ✅ |
| Sitemap | ✅ | ✅ |
| llms.txt | ✅ | ✅ |
| Structured data (JSON-LD) | ✅ | ✅ |
| Product/Offer data | ✅ | ✅ |
| Static crawler policy | ✅ | ✅ |
| Content-Signal | ✅ | ✅ |
| MCP discovery | ✅ | ✅ |
| WebMCP static presence | ✅ | ✅ |
| OpenAPI presence | ✅ | ✅ |
| OAuth authorization-server / protected-resource metadata | ✅ | ✅ |
| UCP profile validity | ✅ (experimental) | ✅ |
| Agent discovery surface (A2A cards, AI-plugin, agents.json, Agent Skills) | ✅ (experimental) | ✅ |
| Core Score | ✅ | — |
| Cloud's full compatibility score | ❌ | ✅ |
| Cloud's full production ruleset | ❌ | ✅ |
| Observed WAF/bot-firewall behavior | ❌ | ✅ |
| Real crawler network access | ❌ | ✅ |
| Browser-based agent simulation | ❌ | ✅ |
| Multi-model execution | ❌ | ✅ |
| MCP tool invocation | ❌ | ✅ |
| WebMCP tool execution/state parity | ❌ | ✅ |
| Tool/UI parity checking | ❌ | ✅ |
| Checkout/task completion | ❌ | ✅ |
| CAPTCHA/challenge behavior | ❌ | ✅ |
| Verified-agent access | ❌ | ✅ |
| Failure attribution | ❌ | ✅ |
| Temporal stability / regressions | ❌ | ✅ |
| Scheduled monitoring | ❌ | ✅ |
| Alerts/webhooks | ❌ | ✅ |
| Hosted, shareable reports | ❌ | ✅ |
| Contextual fix plan | ❌ | ✅ |

`(experimental)` marks a check that evaluates and reports on every scan but
is excluded from Core's Static Signal Score until it has been calibrated
against real-world traffic — see `docs/methodology.md`.

## Examples

**Core can determine:** `robots.txt` declares `OAI-SearchBot` allowed.

**Core cannot determine:** whether a bot firewall in front of the site actually admits `OAI-SearchBot` traffic rather than challenging or blocking it.

**Scovant Cloud can test:** observed access — a real crawl attempt against the live site, with the result (admitted, challenged, blocked) recorded.

---

**Core can determine:** an MCP discovery file (or server card) is published and well-formed.

**Core cannot determine:** whether the server behind it answers an `initialize` handshake, or whether its tools work when invoked.

**Scovant Cloud can test:** both — a live MCP handshake with tool enumeration, and a real-browser WebMCP probe.

---

**Core can determine:** a Product page carries a well-formed `Offer` with price, currency, and availability.

**Core cannot determine:** whether an autonomous agent can actually complete a purchase against that page — add to cart, reach checkout, and confirm.

**Scovant Cloud can test:** a real, browser-driven agent attempting the purchase end to end, with the outcome (and failure attribution, if it fails) recorded.

---

**Core can determine:** a UCP profile, an OAuth authorization-server/protected-resource metadata document, or an A2A/agent-skills discovery surface is published at its declared well-known path and is schema-valid JSON.

**Core cannot determine:** whether the OAuth flow it describes actually completes, whether the UCP checkout it declares actually works, or whether the discovered agent surface's own tools behave as documented.

**Scovant Cloud can test:** the live OAuth handshake, an end-to-end UCP-declared checkout, and invocation of the discovered agent surface's own capabilities.
