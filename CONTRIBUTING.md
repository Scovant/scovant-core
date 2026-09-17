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

## Ruleset freeze

The scored (non-experimental) check set and its weights are frozen within a
ruleset version — `tests/test_registry.py::test_scored_set_is_exact` pins the
exact id list. Changing which checks score, or their weights, is not a
drive-by edit: it needs its own dedicated PR with calibration evidence (a
fixture corpus and a false-positive review), a `RULESET_VERSION` bump, and a
CHANGELOG entry noting that scores are not comparable across ruleset
versions. Experimental checks are welcome any time — they are visible in
reports but excluded from the score until a separate, calibrated PR promotes
them.

`ruleset_digest` covers the check set, each check's `check_version` and the
scoring constants — so a change to a detector's SEMANTICS (what it flags, not
how it is worded) must bump that check's `check_version`, which changes the
digest and tells a reader that a re-scan may legitimately differ.

Security-category checks are unscored by construction and may be added
within a ruleset version; the scored set remains frozen.

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
