import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { environment: 'node', include: ['test/*.test.ts'],
    // Compiled ESM libraries remain real packages. Transform only these modules
    // in Node tests so existing spies can observe the SDK public boundaries.
    server: { deps: { inline: ['@gatopago/shared', '@gatopago/environment', '@gatopago/test-fixtures'] } },
  },
});
