---
name: explain
description: Explain one Scovant Core check (why it matters, limitations, what Scovant Cloud adds, references). Use for "/scovant:explain CORE-XXX-NNN" or "what does CORE-... mean".
---

# /scovant:explain <CHECK-ID>

1. Call `explain_check(check_id)` on the `scovant-core` server.
2. If the server is unavailable, read `${CLAUDE_PLUGIN_ROOT}/skills/references/checks.md` and answer from it (it is generated from the same registry as the tool).
3. Always report: title, category and weight, `why_it_matters`, `limitations` (what a passive scan cannot prove), `cloud_extension` (what Scovant Cloud adds), references. Say when the check is experimental (not scored).
4. If the user has a finding for this check, tie the explanation to its evidence; do not speculate beyond the evidence.
