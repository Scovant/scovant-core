#!/usr/bin/env node
// backend/scovant-core/npm/bin/scovant.js
'use strict';
const { spawnSync } = require('child_process');
const { statSync } = require('fs');
const { delimiter, join: pathJoin } = require('path');
const { version } = require('../package.json');

const SPEC = `scovant-core==${version}`;
// A probe that resolves the spec (uvx/pipx) may fetch the engine from PyPI
// on the first run on a machine — see the comment at resolveRunner — which
// can take much longer than a plain local `--version` call, so those get a
// longer budget than the cheap local-only probes. Both budgets are
// overridable: a genuinely slow link is a real case, and the alternative
// (a killed probe) is reported as "no runner found", which is worse.
const OVERRIDE_MS = Number.parseInt(process.env.SCOVANT_NPM_PROBE_TIMEOUT_MS || '', 10);
const HAS_OVERRIDE = Number.isFinite(OVERRIDE_MS) && OVERRIDE_MS > 0;
const PROBE = { stdio: 'ignore', timeout: HAS_OVERRIDE ? OVERRIDE_MS : 10000 };
const PROBE_RESOLVE = { stdio: 'ignore', timeout: HAS_OVERRIDE ? OVERRIDE_MS : 60000 };
// Same budget as PROBE, but keeps stdout so the printed version can be
// compared with this launcher's own (see checkVersion).
const PROBE_CAPTURE = {
  stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8', timeout: PROBE.timeout,
};
const TESTING = process.env.SCOVANT_NPM_TEST === '1';

// A probe that is killed by its own timeout is NOT the same thing as a
// missing tool: reporting "install uv" to someone whose uv is installed and
// merely slow is false. Track the two apart so the no-runner message can.
let timedOut = false;
// Every python3.NN candidate that answered the probe with the WRONG engine
// version (only populated once the loop in resolveRunner has exhausted
// every candidate with no match) — see mismatchExhaustedMessage.
let versionMismatches = [];

function probe(cmd, args, opts = PROBE) {
  const r = spawnSync(cmd, args, opts);
  if (r.error && r.error.code === 'ETIMEDOUT') {
    timedOut = true;
    return { ok: false, stdout: '' };
  }
  return { ok: !r.error && r.status === 0, stdout: r.stdout || '' };
}

function works(cmd, args, opts = PROBE) {
  return probe(cmd, args, opts).ok;
}

// A fake test double doesn't necessarily behave like the real `uvx` when
// probed with `--version`, so under SCOVANT_NPM_TEST=1 we skip that
// behavioral check and only verify an executable named `uvx` exists on
// PATH. Everything downstream (the real invocation) is identical either way.
function existsOnPath(cmd) {
  const pathEnv = process.env.PATH || '';
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    try {
      const st = statSync(pathJoin(dir, cmd));
      if (st.isFile() && (st.mode & 0o111)) return true;
    } catch {
      // not found in this dir; keep looking
    }
  }
  return false;
}

// `npx @scovant/core@X` must execute engine X. The uvx and pipx paths get
// that for free — they resolve the pinned SPEC. The `python3 -m
// scovant_core` path runs whatever that interpreter happens to have, so the
// guarantee only holds if we check it: parse the version the probe printed
// and compare. Scores are only comparable within one ruleset version, so a
// mismatch here is not a warning-and-continue situation — it is a launcher
// that is about to run a different engine than the one it claims to be —
// and this fails CLOSED (exit 9), naming BOTH versions on stderr, unless
// the caller explicitly opts into the old warn-and-continue behavior via
// SCOVANT_ALLOW_VERSION_MISMATCH=1.
// Returns the version string the probe reported, or null if `stdout`
// didn't carry a recognizable one.
function extractVersion(stdout) {
  const m = /scovant-core\s+(\S+)/.exec(stdout || '');
  return m ? m[1] : null;
}

function mismatchWarning(cmd, found) {
  const what = found ? `version ${found}` : 'an unknown version';
  return (
    `scovant: warning — scovant: engine version mismatch — "${cmd} -m scovant_core" runs scovant-core ${what}, ` +
    `but this launcher is @scovant/core ${version}.\n` +
    `Scores are only comparable within one ruleset version, so the launcher refuses to run a different engine.\n` +
    `Fix: install uv or pipx (they pin "${SPEC}"), or "${cmd} -m pip install \\"${SPEC}\\"".\n`
  );
}

// Every candidate that answered the probe but carried the wrong version —
// a mismatched EARLIER candidate must not abort the whole loop when a
// LATER one carries the exact version, so this is only consulted once the
// loop has exhausted every candidate with no match.
function mismatchExhaustedMessage(tried) {
  const lines = tried.map(({ cmd, found }) => `  - "${cmd} -m scovant_core --version" reported ${found ? `version ${found}` : 'an unknown version'}`);
  return (
    `scovant: engine version mismatch — every Python interpreter tried on PATH runs a different\n` +
    `scovant-core version than this launcher (@scovant/core ${version}):\n` +
    lines.join('\n') + '\n' +
    `Scores are only comparable within one ruleset version, so the launcher refuses to run a different engine.\n` +
    `Fix: install uv or pipx (they pin "${SPEC}"), or "python3 -m pip install \\"${SPEC}\\"".\n` +
    `Override (not recommended): SCOVANT_ALLOW_VERSION_MISMATCH=1\n`
  );
}

function resolveRunner() {
  // Probe exactly what will be run, not just whether the launcher binary
  // itself exists: if the spec can't be resolved (e.g. yanked/unpublished
  // version, no network, index unreachable), `uvx`/`pipx` exit with their
  // OWN 1 or 2 — indistinguishable from the engine's real "threshold
  // failed" (1) / "invalid input" (2) exit codes. A failed probe here means
  // exit 9 ("no usable runner"), never a runner that's about to lie about
  // what its exit code means. This does mean the very first invocation on a
  // machine pays uvx/pipx's package download during the probe itself.
  const uvxAvailable = TESTING
    ? existsOnPath('uvx')
    : works('uvx', ['--from', SPEC, 'scovant', '--version'], PROBE_RESOLVE);
  if (uvxAvailable) {
    return { cmd: 'uvx', pre: ['--from', SPEC, 'scovant'] };
  }
  if (works('pipx', ['run', '--spec', SPEC, 'scovant', '--version'], PROBE_RESOLVE)) {
    return { cmd: 'pipx', pre: ['run', '--spec', SPEC, 'scovant'] };
  }
  // Probe exactly what will be run — `-m scovant_core --version` — not just
  // whether the package can be imported. A package with no `__main__.py`
  // (or one whose CLI blows up before parsing `--version`) can import fine
  // and still fail to execute as a module; a probe that only checks import
  // would hand back a runner that crashes on the real invocation instead of
  // reporting "no runner found".
  // A mismatched EARLIER candidate must not abort the probe: keep trying
  // later candidates, and only report failure once every one of them has
  // been tried and none matched.
  const mismatches = [];
  for (const py of ['python3.13', 'python3.12', 'python3']) {
    const r = probe(py, ['-m', 'scovant_core', '--version'], PROBE_CAPTURE);
    if (!r.ok) continue;
    const found = extractVersion(r.stdout);
    if (found === version) {
      return { cmd: py, pre: ['-m', 'scovant_core'] };
    }
    if (process.env.SCOVANT_ALLOW_VERSION_MISMATCH === '1') {
      process.stderr.write(mismatchWarning(py, found));
      return { cmd: py, pre: ['-m', 'scovant_core'] };
    }
    mismatches.push({ cmd: py, found });
  }
  if (mismatches.length) {
    versionMismatches = mismatches;
  }
  return null;
}

const runner = resolveRunner();
if (!runner) {
  if (versionMismatches.length) {
    process.stderr.write(mismatchExhaustedMessage(versionMismatches));
    process.exit(9);
  }
  if (timedOut) {
    process.stderr.write(
      `scovant: a runner was found but its probe timed out, so nothing could be started.\n\n` +
      `This is usually a slow or offline network: uvx/pipx download the Python package\n` +
      `"scovant-core" the first time you run this, and that happens during the probe.\n` +
      `Try again (a partial download is cached), or raise the budget:\n` +
      `  SCOVANT_NPM_PROBE_TIMEOUT_MS=300000 npx @scovant/core ...\n\n` +
      `Docs: https://github.com/Scovant/scovant-core\n`);
    process.exit(9);
  }
  process.stderr.write(
    `scovant: no way to run the scanner was found.\n\n` +
    `This package is a thin launcher; the scanner itself is the Python package\n` +
    `"scovant-core" (Python >= 3.12). Install ONE of:\n` +
    `  - uv/uvx (recommended):  https://docs.astral.sh/uv/   then re-run this command\n` +
    `  - pipx:                  https://pipx.pypa.io/        then re-run this command\n` +
    `  - the package directly:  python3 -m pip install "${SPEC}"\n\n` +
    `Docs: https://github.com/Scovant/scovant-core\n`);
  process.exit(9);
}

const r = spawnSync(runner.cmd, [...runner.pre, ...process.argv.slice(2)], { stdio: 'inherit' });
if (r.error) {
  process.stderr.write(`scovant: failed to start ${runner.cmd}: ${r.error.message}\n`);
  process.exit(9);
}
if (r.signal) {
  process.exit(128 + (require('os').constants.signals[r.signal] || 0));
}
// `status` can be null with no signal and no error (rare, platform-
// dependent). Exit codes here are a published contract the GitHub Action
// branches on, so an unresolved child state must never read as "scan
// passed" — fall back to 9, the launcher's own "could not run" code.
process.exit(r.status === null || r.status === undefined ? 9 : r.status);
