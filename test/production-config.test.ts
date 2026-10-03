import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const root = new URL('../', import.meta.url);
const config = JSON.parse(readFileSync(new URL('wrangler.jsonc', root), 'utf8'));

describe('Worker deployment configuration', () => {
  it('has only the production Worker and consumer origins', () => {
    expect(config.name).toBe('gatopago-wallet-core');
    expect(config.vars.GATOPAGO_ENVIRONMENT).toBe('production');
    expect(config.vars.GATOPAGO_WEB_ORIGIN).toBe('https://gatopago.com');
    expect(config.vars.GATOPAGO_API_ORIGIN).toBe('https://api.gatopago.com');
    expect(config.routes).toEqual([{ pattern: 'api.gatopago.com', custom_domain: true }]);
    expect(readdirSync(root).filter(name => /^wrangler\..*jsonc$/.test(name)).sort()).toEqual(['wrangler.jsonc']);
  });
  it('binds the verified production database and aligns all queue names', () => {
    expect(config.d1_databases).toEqual([{ binding: 'WALLET_DB',
      database_name: 'gatopago-wallet-core',
      database_id: '48996f36-0c69-4b0c-af75-b73e88b4f09b', migrations_dir: 'migrations' }]);
    expect(config.vars.CREATION_QUEUE_NAME).toBe('gatopago-wallet-core-jobs');
    expect(config.queues.producers).toEqual([{ binding: 'CREATION_JOBS', queue: config.vars.CREATION_QUEUE_NAME }]);
    expect(config.queues.consumers).toHaveLength(1);
    expect(config.queues.consumers[0]).toMatchObject({ queue: config.vars.CREATION_QUEUE_NAME,
      dead_letter_queue: 'gatopago-wallet-core-jobs-dlq' });
  });
  it('uses production configuration in CI, without real Firebase credentials', () => {
    const ci = readFileSync(new URL('.github/workflows/ci.yml', root), 'utf8');
    expect(ci).toContain('GATOPAGO_ENVIRONMENT: production');
    expect(ci).toContain('FIREBASE_PROJECT_ID: v3-build-test');
  });
});
