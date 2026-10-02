import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [cloudflareTest(async () => ({
    main: './src/index.ts',
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: {
      // Installed workerd's supported date; same restriction as the existing suite.
      compatibilityDate: '2026-07-08',
      bindings: {
        GATOPAGO_ENVIRONMENT: 'production', FIREBASE_PROJECT_ID: 'v3-runtime-test',
        TURNSTILE_SECRET_KEY: 'synthetic-turnstile-secret-for-tests',
        AUTH_RATE_LIMIT_PEPPER: 'synthetic-hmac-pepper-for-tests-only',
        V3_TEST_MIGRATIONS: await readD1Migrations(fileURLToPath(new URL('./migrations', import.meta.url))),
      },
    },
  }))],
  // Serialize file-level workerd/D1 fixtures to bound crypto/database contention.
  // In-test concurrency and financial deadlines remain unchanged.
  test: { include: ['test-worker/**/*.test.ts'], maxWorkers: 1 },
});
