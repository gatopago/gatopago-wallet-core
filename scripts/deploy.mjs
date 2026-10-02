import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import './check-vendor.mjs';

const directory = resolve(import.meta.dirname, '..');
const { values, positionals } = parseArgs({ options: { 'dry-run': { type: 'boolean' }, 'secrets-file': { type: 'string' } } });
assert.equal(positionals.length, 0);
assert(!values['dry-run'] || !values['secrets-file'], 'Dry run must not load credentials.');
const configFile = 'wrangler.remote.jsonc';
const config = JSON.parse(readFileSync(resolve(directory, configFile), 'utf8'));
assert.equal(config.name, 'gatopago-wallet-core');
assert.equal(config.vars.GATOPAGO_ENVIRONMENT, 'production');
assert.equal(config.vars.GATOPAGO_WEB_ORIGIN, 'https://gatopago.com');
assert.equal(config.vars.GATOPAGO_API_ORIGIN, 'https://api.gatopago.com');
assert.equal(config.vars.GATOPAGO_BUSINESS_ORIGIN, 'https://business.gatopago.com');
assert.equal(config.vars.CREATION_QUEUE_NAME, 'gatopago-wallet-core-jobs');
assert.deepEqual(config.queues.producers, [{ binding: 'CREATION_JOBS', queue: config.vars.CREATION_QUEUE_NAME }]);
assert.equal(config.queues.consumers.length, 1);
assert.equal(config.queues.consumers[0].queue, config.vars.CREATION_QUEUE_NAME);
assert.equal(config.queues.consumers[0].dead_letter_queue, 'gatopago-wallet-core-jobs-dlq');
assert.equal(config.d1_databases.length, 1);
assert.equal(config.d1_databases[0].binding, 'WALLET_DB');
assert(/^[0-9a-f-]{36}$/i.test(config.d1_databases[0].database_id) && !config.d1_databases[0].database_id.startsWith('00000000'), 'Provision D1 before deployment.');
if (!values['dry-run']) {
  assert(/^[0-9a-f]{40}$/.test(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: directory, encoding: 'utf8' }).trim()));
  assert.equal(execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=all', '--', '.'], { cwd: directory, encoding: 'utf8' }).trim(), '', 'Commit this project before deploying; unrelated projects do not block this release.');
}
const require = createRequire(import.meta.url);
const cli = resolve(require.resolve('wrangler/package.json'), '..', 'bin/wrangler.js');
if (!values['dry-run']) {
  // Never auto-provision replacement queues and strand pending production jobs.
  // Complete the resource-name transition before publishing this configuration.
  for (const name of [config.vars.CREATION_QUEUE_NAME, config.queues.consumers[0].dead_letter_queue]) {
    execFileSync(process.execPath, [cli, 'queues', 'info', name, '--config', configFile, '--env-file', '.dev.vars.example'], { cwd: directory, stdio: 'inherit' });
  }
}
const args = [cli, 'deploy', '--config', configFile, '--env-file', '.dev.vars.example', '--minify'];
if (values['dry-run']) args.push('--dry-run');
if (values['secrets-file']) args.push('--secrets-file', resolve(values['secrets-file']));
execFileSync(process.execPath, args, { cwd: directory, stdio: 'inherit' });
