import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, basename } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const manifest = JSON.parse(readFileSync(resolve(root, 'vendor/manifest.json'), 'utf8'));
assert.equal(manifest.schema_version, 1);
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const dependencies = { ...pkg.dependencies, ...pkg.devDependencies };
const seen = new Set();
for (const item of manifest.packages) {
  assert.equal(item.file, basename(item.file));
  assert(!seen.has(item.name), 'Duplicate package in manifest'); seen.add(item.name);
  assert.equal(dependencies[item.name], 'file:vendor/' + item.file);
  assert.equal(createHash('sha256').update(readFileSync(resolve(root, 'vendor', item.file))).digest('hex'), item.sha256, 'Vendor bytes differ: ' + item.name);
}
for (const [name, spec] of Object.entries(dependencies)) {
  assert(!spec.startsWith('workspace:') && !spec.startsWith('link:'), 'Sibling workspace dependency: ' + name);
  if (spec.startsWith('file:')) assert(spec.startsWith('file:vendor/') && seen.has(name), 'Unverified local package: ' + name);
}
assert.equal(readdirSync(resolve(root, 'vendor')).filter(name => name.endsWith('.tgz')).length, seen.size);
console.log('Verified ' + seen.size + ' pinned, project-owned package snapshots.');
