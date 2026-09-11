# Contributing

Thank you for helping make AI-agent readiness measurable.

## How changes land

This repository is a mirror. Pull requests are welcome and are reviewed here,
but they are merged in Scovant's development monorepo and appear here in the
next sync commit with your authorship preserved as a co-author trailer.
Please do not be surprised when your PR is closed with a reference to the
sync commit that contains it.

## What we accept

New deterministic checks, parser improvements, support for new public
standards, test fixtures, output formats, documentation.

A new check must satisfy at least four of: machine-verifiable, deterministic,
reproducible, useful across many sites, linked to an authoritative standard,
meaningful to agent access/understanding/action, low operational cost, safe
to evaluate passively. Checks that need a real agent or a browser session
belong to Scovant Cloud, not here.

## Requirements for every PR

- tests for every parser or check touched (fixtures must be synthetic — see
  `fixtures/PROVENANCE.md`);
- no network access in unit tests;
- no new runtime dependency without discussion;
- `ruff check` and `pytest` green.
- `mypy src` clean.
- A ruleset change must update the golden reports explicitly
  (`SCOVANT_CORE_UPDATE_GOLDENS=1 pytest tests/test_golden.py`) and the diff
  must be reviewed.
