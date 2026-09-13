import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'scovant.js');
const VERSION = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8')).version;

// A `python3` double that answers `--version` the way the real engine does
// (`scovant-core <version>`), so the launcher's version check sees a match.
// `body` handles every other invocation.
function fakePython(reportedVersion, body) {
  return fakeRunner('python3',
    `case "$*" in *--version) echo "scovant-core ${reportedVersion}"; exit 0;; esac\n${body}`);
}

function fakeRunner(name, body) {
  const dir = mkdtempSync(join(tmpdir(), 'fakebin-'));
  const p = join(dir, name);
  // Use an absolute #!/bin/sh shebang (not `#!/usr/bin/env bash`): the tests
  // below run the launcher with a deliberately empty/minimal PATH, and
  // `/usr/bin/env bash` would itself fail to resolve `bash` under that PATH.
  // `/bin/sh` is an absolute path the kernel execs directly, no PATH lookup.
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return dir;
}

test('no runner available → exit 9 and an actionable message', () => {
  const empty = mkdtempSync(join(tmpdir(), 'emptybin-'));
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: empty, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 9);
  assert.match(r.stderr, /uvx/);
  assert.match(r.stderr, /pipx/);
  assert.match(r.stderr, /python3/);
});

test('uvx is preferred, argv passes through verbatim', () => {
  const dir = fakeRunner('uvx', 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com', '--format', 'json'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /scan https:\/\/example\.com --format json/);
});

test('the engine exit code is forwarded, not swallowed', () => {
  const dir = fakeRunner('uvx', 'exit 3');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 3);
});

test('no uvx → falls back to pipx, argv and exit code intact', () => {
  const dir = fakeRunner('pipx', 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com', '--format', 'json'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /run --spec scovant-core==\S+ scovant scan https:\/\/example\.com --format json/);
});

test('no uvx, no pipx → falls back to python3 -m scovant_core, argv and exit code intact', () => {
  const dir = fakePython(VERSION, 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com', '--format', 'json'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /-m scovant_core scan https:\/\/example\.com --format json/);
  // A matching engine version is the silent case — no warning at all.
  assert.equal(r.stderr, '');
});

test('a python3 carrying a DIFFERENT engine version is refused, naming both versions', () => {
  const dir = fakePython('0.0.1-other', 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 9, 'a mismatched engine cannot prove a match, so it is refused by default');
  assert.match(r.stderr, /0\.0\.1-other/);
  assert.ok(r.stderr.includes(VERSION), 'the message must name the launcher version too');
  assert.match(r.stderr, /SCOVANT_ALLOW_VERSION_MISMATCH/);
});

test('...with SCOVANT_ALLOW_VERSION_MISMATCH=1, the mismatched engine runs anyway, with a warning', () => {
  const dir = fakePython('0.0.1-other', 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1', SCOVANT_ALLOW_VERSION_MISMATCH: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /-m scovant_core scan/);
  assert.match(r.stderr, /warning/);
  assert.match(r.stderr, /0\.0\.1-other/);
});

test('a python3 whose --version is unparseable is refused, not silently trusted', () => {
  const dir = fakeRunner('python3', 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 9, 'an unparseable answer cannot prove a match either, so it is refused by default');
  assert.match(r.stderr, /an unknown version/);
  assert.match(r.stderr, /SCOVANT_ALLOW_VERSION_MISMATCH/);
});

test('...with SCOVANT_ALLOW_VERSION_MISMATCH=1, the unparseable-version engine runs anyway, with a warning', () => {
  const dir = fakeRunner('python3', 'echo "ARGS:$@"; exit 0');
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1', SCOVANT_ALLOW_VERSION_MISMATCH: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /-m scovant_core scan/);
  assert.match(r.stderr, /warning/);
  assert.match(r.stderr, /an unknown version/);
});

// The interpreter-loop case (a first python3.NN candidate answers with a
// mismatched version, a later candidate answers with a match, so the
// launcher succeeds via the later one) needs TWO distinctly-named fake
// interpreters on PATH at once — `fakeRunner`/`fakePython` above only ever
// stage one binary per temp dir, and `resolveRunner`'s loop tries fixed
// names (`python3.13`, `python3.12`, `python3`) in order, so exercising the
// fallback for real would mean faking `python3.13` (mismatched) AND
// `python3` (matching) side by side in the same directory. That's
// expressible; do it explicitly rather than skipping.
test('a mismatched python3.13 is skipped in favor of a matching python3', () => {
  const dir = mkdtempSync(join(tmpdir(), 'fakebin-'));
  const bad = join(dir, 'python3.13');
  writeFileSync(bad, `#!/bin/sh\ncase "$*" in *--version) echo "scovant-core 0.0.1-other"; exit 0;; esac\necho "ARGS:$@"; exit 0\n`);
  chmodSync(bad, 0o755);
  const good = join(dir, 'python3');
  writeFileSync(good, `#!/bin/sh\ncase "$*" in *--version) echo "scovant-core ${VERSION}"; exit 0;; esac\necho "ARGS:$@"; exit 0\n`);
  chmodSync(good, 0o755);
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1' }, encoding: 'utf8' });
  assert.equal(r.status, 0, 'a later, matching candidate must still let the launcher succeed');
  assert.match(r.stdout, /-m scovant_core scan/);
  assert.equal(r.stderr, '', 'the matching candidate that actually ran leaves no warning');
});

test('a probe killed by its own timeout is not reported as a missing tool', () => {
  // Sleep via node itself (an absolute path that always exists): `sleep`
  // is not resolvable under the deliberately minimal PATH these tests use.
  const dir = fakeRunner('pipx', `exec ${process.execPath} -e "setTimeout(() => {}, 5000)"`);
  const r = spawnSync(process.execPath, [BIN, 'scan', 'https://example.com'],
    { env: { PATH: dir, SCOVANT_NPM_TEST: '1', SCOVANT_NPM_PROBE_TIMEOUT_MS: '300' },
      encoding: 'utf8' });
  assert.equal(r.status, 9);
  assert.match(r.stderr, /timed out/);
  assert.doesNotMatch(r.stderr, /Install ONE of/,
    'telling a user with pipx installed to install pipx is the bug this test pins');
  assert.match(r.stderr, /SCOVANT_NPM_PROBE_TIMEOUT_MS/);
});
