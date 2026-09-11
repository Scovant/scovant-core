# @scovant/core

A thin `npm` launcher for [`scovant-core`](https://pypi.org/project/scovant-core/), the
passive AI-agent-readiness scanner. This package contains no scanning logic of its own —
running `scovant` from Node just finds a way to run the real Python engine and execs it,
forwarding your arguments and its exit code unchanged.

## Usage

```sh
npx @scovant/core scan https://example.com
```

or install it globally:

```sh
npm install -g @scovant/core
scovant scan https://example.com --format json
```

## How it works

On each run, the launcher looks for a way to run the Python package `scovant-core`
(requires Python >= 3.12), in order:

1. [`uv`](https://docs.astral.sh/uv/) via `uvx --from scovant-core==<version> scovant`
2. [`pipx`](https://pipx.pypa.io/) via `pipx run --spec scovant-core==<version> scovant`
3. a `python3` on `PATH` that already has `scovant_core` installed, via `python3 -m scovant_core`

If none of those are available, it exits with code `9` and prints instructions for
installing one of them. Any other exit code is the underlying `scovant-core` engine's own
— see its documentation for the exit-code contract (0-5).

The first two paths pin the exact version: `npx @scovant/core@X` resolves
`scovant-core==X`, so you get engine X. **The third path does not** — it runs whatever
version of `scovant_core` that interpreter happens to have. The launcher checks, and if
the versions differ it prints a warning naming both and runs anyway (leaving you with a
working engine beats refusing to start), but scores are only comparable within one ruleset
version. Install `uv` or `pipx` if you need the pin.

Each candidate is probed before use, and on the first run on a machine that probe includes
`uvx`/`pipx` downloading the Python package. On a slow link a probe can be killed by its
own timeout; the launcher says so explicitly (it never reports a slow tool as a missing
one), and you can raise the budget:

```sh
SCOVANT_NPM_PROBE_TIMEOUT_MS=300000 npx @scovant/core scan https://example.com
```

## Platform support

Developed and tested on Linux and macOS. The launcher is POSIX-shaped: it probes for
executables by name (`uvx`, `pipx`, `python3.13`/`python3.12`/`python3`) and its
"nothing found" message suggests `python3 -m pip`. On Windows, `uvx`/`pipx` on `PATH` do
resolve, but a Python installed as `python`/`py` (rather than `python3`) will not be
found by the third fallback. Windows is not covered by CI, so it is not claimed as
supported.

## Why a launcher instead of a bundled binary?

`scovant-core` is a Python package; this package exists only so `npx @scovant/core ...`
works without you needing to already have a Python environment set up for it, provided
`uv` or `pipx` is available. It has zero npm runtime dependencies and never installs
anything on its own (no `postinstall`) — the actual engine is fetched on demand by
whichever runner it finds, and only when you invoke `scovant`.

## Provenance

This npm package carries no build-provenance attestation (npm cannot generate one from a
private source repository), while the `scovant-core` Python package it fetches from PyPI
does.

## License

Apache-2.0
