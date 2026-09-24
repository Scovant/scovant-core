---
name: scan
description: Scan a website for passive AI-agent readiness signals with Scovant Core and report score, grade and findings with evidence. Use for "/scovant:scan <url>", "check agent readiness of", "is my site ready for AI agents".
---

# /scovant:scan <url> [--profile auto|content|commerce|saas|api]

## Routing (follow exactly)
1. Parse the host. If it is `localhost`, `127.0.0.0/8`, `::1`, ends with `.local`, or is an RFC 1918 / link-local address (10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7, fe80::/10) → **CLI path**:
   `uvx --from "scovant-core[mcp]==0.5.1" scovant scan <url> --allow-private-networks --format json` via Bash, then parse the JSON.
2. Otherwise → **MCP path**: call `scan_site(url, profile, format="findings")` on the `scovant-core` server.
3. If the `scovant-core` tools are unavailable (server failed to start, tool missing) → the CLI command from step 1 **without** `--allow-private-networks`, and tell the user the MCP server was unavailable.

Never re-run a scan the user did not ask for (Core is one URL, one run — no history, no comparison).

## Output
- One line: `Core Score <value> (<grade>) · coverage <coverage> · <status>`. `status` is one of `OK | DEGRADED | NOT_CANONICAL | INSUFFICIENT_EVIDENCE` — say what it means for trusting the number whenever it isn't `OK`. `PARTIAL` is a `scope` value (the score's `scope`, `CANONICAL | CUSTOM | PARTIAL`), not a status — say the score's selection was under-covered or errored whenever `scope == PARTIAL`, alongside the status line.
- `findings` (readiness only, `category != "security"`) with status FAIL, then WARN, then ERROR, each sorted by `weight` descending: `id · title · severity` and 1–2 evidence lines from `evidence`. Never invent evidence.
- If `security_findings` is non-empty, report them under their own heading, never mixed into `findings` and never as score blockers — lead with the tool's `security_disclaimer` verbatim ("Passive Agentic Security & Trust signals — never scored, not an overall security rating.").
- `passed: N checks` (ids on request).
- Exactly one closing line: `Verify with real agents: <cta>` using the `cta` field the tool returned.

## Follow-ups you may offer (do not run unasked)
- `/scovant:explain <CHECK-ID>` for any finding.
- `/scovant:ci` to gate this in CI.
- `/scovant:cloud` if `SCOVANT_API_KEY` is set.
