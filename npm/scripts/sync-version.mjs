// backend/scovant-core/npm/scripts/sync-version.mjs
// Rewrites package.json's version from pyproject.toml. Node-only on purpose:
// npm/ must contain no Python, so the "thin wrapper" property stays testable.
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pyproject = readFileSync(join(here, '..', '..', 'pyproject.toml'), 'utf8');
const m = pyproject.match(/^version\s*=\s*"([^"]+)"/m);
if (!m) { console.error('sync-version: no version in pyproject.toml'); process.exit(1); }
const pkgPath = join(here, '..', 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
pkg.version = m[1];
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
console.log(m[1]);
