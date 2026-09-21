---
name: cloud
description: Use Scovant Cloud through the user's own API key — list sites, trigger a scan (costs a credit), poll it, read regressions and the versioned report. Use for "/scovant:cloud", "trigger a Scovant scan", "show my regressions".
---

# /scovant:cloud

## Precondition
`SCOVANT_API_KEY` must be set in the environment Claude Code runs in (an API token created at Settings → API tokens on scovant.com). If it is not set, say so, explain where to create one, and stop. Never print the value of the variable.

## Flow (tools on the `scovant-cloud` server)
1. `list_sites` → show name, base URL (`base_url`), id; ask which one unless obvious.
2. Before `trigger_scan`: state the cost — one credit per scan, except on Team/Business/Enterprise workspaces, which are not debited; a simulation costs one credit per agent, on every plan — and wait for an explicit yes.
3. `trigger_scan(site_id, targets=[{"type": "url", "url": "<the site's base_url from list_sites>"}])` → returns a queued run; poll `get_scan(scan_id)` every 20–30 s until `completed|partial|failed`.
4. Report: overall score, grade, badge; `list_issues` top findings; `list_regressions(site_id)` if the run had a baseline; `get_scan_report` for the versioned JSON on request.
5. `generate_fix_plan` debits a credit — only on an explicit ask.

Public tools (`lookup_domain`, `get_public_showcase`, `list_compatibility_rules`, `list_showcase_sites`) work without a key.
