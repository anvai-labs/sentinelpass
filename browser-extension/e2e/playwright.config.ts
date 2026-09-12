import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 180_000,
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  // The daemon harness provisions vaults and spawns processes per suite;
  // keep retries off so a flaky pass is visible.
  retries: 0,
});
