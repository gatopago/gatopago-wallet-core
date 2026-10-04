import type { D1Migration } from '@cloudflare/vitest-pool-workers';

declare global {
  namespace Cloudflare {
    interface Env {
      V3_TEST_MIGRATIONS: D1Migration[];
    }
  }
}
