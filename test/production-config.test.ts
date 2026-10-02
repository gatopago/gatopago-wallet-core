import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

const root = new URL('../', import.meta.url);
const config = JSON.parse(readFileSync(new URL('wrangler.remote.jsonc', root), 'utf8'));

describe('production deployment configuration (no remote writes)', () => {
  it('has only the production Worker and consumer origins', () => {
    expect(config.name).toBe('gatopago-wallet-core');
    expect(config.vars.GATOPAGO_ENVIRONMENT).toBe('production');
    expect(config.vars.GATOPAGO_WEB_ORIGIN).toBe('https://gatopago.com');
    expect(config.vars.GATOPAGO_API_ORIGIN).toBe('https://api.gatopago.com');
    expect(config.routes).toEqual([{ pattern: 'api.gatopago.com', custom_domain: true }]);
    expect(JSON.stringify(config)).not.toMatch(/staging/i);
    expect(existsSync(new URL('wrangler.staging.jsonc', root))).toBe(false);
  });
  it('preserves the real database identity and aligns all queue names', () => {
    expect(config.d1_databases).toEqual([{ binding: 'WALLET_DB',
      database_id: 'f9aa958c-2c16-4fed-b3e4-a76d9160eb33', migrations_dir: 'migrations' }]);
    expect(config.vars.CREATION_QUEUE_NAME).toBe('gatopago-wallet-core-jobs');
    expect(config.queues.producers).toEqual([{ binding: 'CREATION_JOBS', queue: config.vars.CREATION_QUEUE_NAME }]);
    expect(config.queues.consumers).toHaveLength(1);
    expect(config.queues.consumers[0]).toMatchObject({ queue: config.vars.CREATION_QUEUE_NAME,
      dead_letter_queue: 'gatopago-wallet-core-jobs-dlq' });
  });
  it('keeps local data and jobs isolated from remote resources', () => {
    const local = readFileSync(new URL('wrangler.jsonc', root), 'utf8');
    expect(local).toContain('"GATOPAGO_ENVIRONMENT": "production"');
    expect(local).toContain('"remote": false');
    expect(local).not.toContain(config.d1_databases[0].database_id);
    expect(local).not.toContain('staging');
    expect(readFileSync(new URL('.env.example', root), 'utf8')).toContain('GATOPAGO_ENVIRONMENT=production');
  });
  it('uses production configuration in CI, without real Firebase credentials', () => {
    const ci = readFileSync(new URL('.github/workflows/ci.yml', root), 'utf8');
    expect(ci).toContain('GATOPAGO_ENVIRONMENT: production');
    expect(ci).toContain('FIREBASE_PROJECT_ID: v3-build-test');
    expect(ci).not.toContain('staging');
  });
  it('rejects the removed deployment switch before invoking Wrangler', () => {
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('scripts/deploy.mjs', root)), '--dry-run', '--staging'], {
      cwd: root, encoding: 'utf8', timeout: 10_000,
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('ERR_PARSE_ARGS_UNKNOWN_OPTION');
  });
});
