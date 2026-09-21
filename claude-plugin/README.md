# Scovant plugin for Claude Code

Scovant Core is an open-source, evidence-first scanner for passive AI-agent
readiness signals on websites. This plugin lets Claude Code run it directly
— scan a URL, explain any check offline, wire a CI gate into your GitHub
Actions, and (with your own API key) drive Scovant Cloud for multi-agent
simulation, CI regression detection, and fix plans.

## Install

```
/plugin marketplace add Scovant/scovant-core
/plugin install scovant@scovant
```

For local development against a checkout of this repository:

```
claude --plugin-dir ./claude-plugin
```

## Requirements

[`uv`](https://docs.astral.sh/uv/) must be installed so `uvx` can run the
`scovant-core` MCP server — the plugin does not vendor a Python
installation. The first tool call downloads the package (10–30 s); every
call after that is fast, since `uvx` caches the environment.

## Skills

| Skill | Command | What it does |
|---|---|---|
| `scan` | `/scovant:scan <url>` | Runs a Core scan (local, no account) and reports score, grade, and findings with evidence. |
| `explain` | `/scovant:explain <CHECK-ID>` | Explains one check — why it matters, its limitations, what Scovant Cloud adds, references. |
| `ci` | `/scovant:ci` | Writes a GitHub Actions workflow that gates a deploy on the Core score. |
| `cloud` | `/scovant:cloud` | Drives Scovant Cloud (sites, scans, regressions, fix plans) through your own API key. |

## Scovant Cloud (optional)

The `cloud` skill and the `scovant-cloud` MCP server only activate once you
export your own API token:

```
export SCOVANT_API_KEY=...
```

Create one at Settings → API tokens on scovant.com. With it set, the
`cloud` skill can list your sites, trigger scans (one credit per scan,
except on Team/Business/Enterprise workspaces, which are not debited) and
simulations (one credit per agent, on every plan), poll results, read CI
regressions, and generate fix plans (which also debit a credit). The
plugin never echoes the key's value back to you or writes it anywhere.

Without a key, the `scovant-cloud` MCP server still starts and its public
tools (`lookup_domain`, `get_public_showcase`, `list_compatibility_rules`,
`list_showcase_sites`) still work — only the authenticated tools
(`trigger_scan`, `get_scan`, `list_sites`, `list_regressions`, …) need one.
`.mcp.json` expands the unset variable to an empty string
(`${SCOVANT_API_KEY:-}`), so Claude Code shows no warning about it; an
authenticated tool call without a key simply gets an authentication error
back from the server.

## What leaves your machine

- **Core** (`scan`, `explain`, `ci` skills): only the HTTP requests the
  scanner itself makes to the URL you ask it to scan. No account, no
  telemetry, nothing sent to Scovant.
- **Cloud** (`cloud` skill, only if `SCOVANT_API_KEY` is set): the requests
  the Cloud MCP tools make to scovant.com, authenticated with your key.

## Manifest notes

`plugin.json` uses the stable field subset `name, version, description,
author, repository, license, keywords, skills, mcpServers` — every one of
these is documented as a plugin-manifest field in the current Claude Code
plugin reference. `marketplace.json`'s `owner` field is likewise part of
the documented marketplace-manifest schema.

A remote (non-stdio) MCP server entry inside `.mcp.json` — `{"type":
"http", "url": ..., "headers": {...}}`, with `${VAR}` / `${VAR:-default}`
expansion inside `headers` — is documented at
[code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp)
(checked 2026-09-21); `scovant-cloud`'s entry uses exactly that shape.
`plugin` `source` as a marketplace-relative path (`"./claude-plugin"`, as
`.claude-plugin/marketplace.json` uses) is documented at
[code.claude.com/docs/en/plugin-marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)
(checked 2026-09-21) — the `github` marketplace source has no `path`
field, so a marketplace-relative path (not a second `github` entry
pointing at the `claude-plugin` subdirectory) is the only way to keep the
plugin and the package in the same repository. `docs/releasing.md` lists
both as checklist items to re-verify before each tag, since they are
external contracts this package does not control.

## License

Apache-2.0.
