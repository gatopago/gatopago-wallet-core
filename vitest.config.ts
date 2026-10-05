import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';
import { FORK_RPC, RELAYER_KEY, SPONSOR_KEY } from './test/fork.ts';

export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      main: './src/index.ts',
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        // Newest date the installed workerd supports.
        compatibilityDate: '2026-08-22',
        bindings: {
          WALLET_NETWORKS: 'eip155:421614',
          WALLET_RPC_URLS: JSON.stringify({ 'eip155:421614': FORK_RPC }),
          RELAYER_PRIVATE_KEY: RELAYER_KEY,
          SPONSOR_PRIVATE_KEY: SPONSOR_KEY,
          SESSION_PRIVATE_JWK: JSON.stringify(
            generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' }),
          ),
          TURNSTILE_SECRET_KEY: 'test-turnstile-secret',
          TEST_MIGRATIONS: await readD1Migrations(
            fileURLToPath(new URL('./migrations', import.meta.url)),
          ),
        },
      },
    })),
  ],
  test: {
    include: ['test/**/*.test.ts'],
    globalSetup: ['./test/fork.ts'],
    setupFiles: ['./test/setup.ts'],
    testTimeout: 60_000,
    hookTimeout: 180_000,
  },
});
