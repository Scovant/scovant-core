---
name: ci
description: Add a Scovant Core agent-readiness gate to the repository's GitHub Actions (min-core-score, fail-on, private staging). Use for "/scovant:ci", "gate agent readiness in CI".
---

# /scovant:ci

1. Ask which URL the workflow should scan (production, or a staging URL from a repository variable) unless the user said.
2. Write `.github/workflows/scovant.yml` with exactly this content, changing only the `url:` value (and removing the four private-network lines — the two flags and their two comment lines — when the URL is public):

```yaml
# Free tier: gate a deploy on the open-source Scovant Core scanner.
#
# Runs entirely inside your workflow — no account, no token, no data leaves the
# runner except the HTTP requests the scanner makes to the URL you name. The
# step fails when the Core score drops below `min-core-score` or a check FAILs.
#
# Pin `@v0.6.0` instead of the moving `@v0` for an exact, never-moving version.
name: Scovant Core gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  core-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: Scovant/scovant-core@v0
        id: scan
        with:
          url: https://staging.example.com
          min-core-score: '70'
          fail-on: fail
          # Scanning your own not-yet-public staging host on a private runner:
          # both flags are required together; never honoured for fork PRs.
          allow-private-networks: 'true'
          trusted-target: 'true'

      - name: Show the result
        if: always()
        run: echo "core score ${{ steps.scan.outputs.score }} (${{ steps.scan.outputs.grade }})"
      # The full HTML report is uploaded as the workflow artifact
      # `scovant-core-report`; a Markdown summary lands in the Step Summary.
```

3. Explain the knobs in one line each: `min-core-score` (fail below), `fail-on` (`never|fail|warn`), `require-canonical`, `fail-on-security`; for a private staging host `allow-private-networks: 'true'` + `trusted-target: 'true'` are both required and are never honoured for fork pull requests.
4. Pin `@v0.6.0` instead of `@v0` if the user wants an exact, never-moving version.
5. If `SCOVANT_API_KEY` is set, OFFER (do not write unasked) the Scovant Cloud trigger step for post-deploy regression detection — `/scovant:cloud` explains it.
