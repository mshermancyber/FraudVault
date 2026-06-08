import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/src/**/__tests__/**/*.test.ts'],
    globals: false,
    testTimeout: 15_000,
    pool: 'forks',
  },
});
