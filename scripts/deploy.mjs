import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import './check-vendor.mjs';

const directory = resolve(import.meta.dirname, '..');
const { values, positionals } = parseArgs({ options: { 'dry-run': { type: 'boolean' }, staging: { type: 'boolean' }, 'secrets-file': { type: 'string' } } });
assert.equal(positionals.length, 0);
assert(!values['dry-run'] || !values['secrets-file'], 'Dry run must not load credentials.');
const configFile = values.staging ? 'wrangler.staging.jsonc' : 'wrangler.remote.jsonc';
const config = JSON.parse(readFileSync(resolve(directory, configFile), 'utf8'));
assert.equal(config.name, values.staging ? 'gatopago-wallet-core-staging' : 'gatopago-wallet-core');
assert.equal(config.vars.GATOPAGO_ENVIRONMENT, values.staging ? 'staging' : 'production');
assert.equal(config.d1_databases.length, 1);
assert.equal(config.d1_databases[0].binding, 'WALLET_DB');
assert(/^[0-9a-f-]{36}$/i.test(config.d1_databases[0].database_id) && !config.d1_databases[0].database_id.startsWith('00000000'), 'Provision D1 before deployment.');
if (!values['dry-run']) {
  if (values.staging) {
    const manifests = JSON.parse(readFileSync(new URL(import.meta.resolve('@gatopago/environment/environments.json')), 'utf8'));
    assert.equal(manifests.staging.status, 'provisioned', 'Finish staging admission before publishing.');
    assert.equal(manifests.staging.firebase_project_id, config.vars.FIREBASE_PROJECT_ID);
    assert.notEqual(manifests.staging.firebase_project_id, manifests.production.firebase_project_id);
    assert(values['secrets-file'], 'Staging publication requires an explicitly supplied secret file.');
    const secrets = JSON.parse(readFileSync(resolve(values['secrets-file']), 'utf8'));
    for (const key of ['FIREBASE_CUSTOM_TOKEN_SIGNER_JSON', 'TURNSTILE_SECRET_KEY', 'AUTH_RATE_LIMIT_PEPPER', 'WALLET_RPC_ENDPOINTS', 'PRIVATE_KEY']) assert(typeof secrets[key] === 'string' && secrets[key].trim(), `Missing staging secret: ${key}`);
  }
  assert(/^[0-9a-f]{40}$/.test(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: directory, encoding: 'utf8' }).trim()));
  assert.equal(execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all', '--', '.'], { cwd: directory, encoding: 'utf8' }).trim(), '', 'Commit this project before deploying; unrelated projects do not block this release.');
}
const require = createRequire(import.meta.url);
const cli = resolve(require.resolve('wrangler/package.json'), '..', 'bin/wrangler.js');
const args = [cli, 'deploy', '--config', configFile, '--env-file', '.dev.vars.example', '--minify'];
if (values['dry-run']) args.push('--dry-run');
if (values['secrets-file']) args.push('--secrets-file', resolve(values['secrets-file']));
execFileSync(process.execPath, args, { cwd: directory, stdio: 'inherit' });
