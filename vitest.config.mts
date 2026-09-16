import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      reportsDirectory: 'coverage/ts',
      include: [
        'sentinelpass-ui/credential-types.ts',
        'sentinelpass-ui/url-utils.ts',
        'browser-extension/chrome/save-heuristics.ts',
        'browser-extension/chrome/logger.ts'
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        statements: 90,
        branches: 80
      }
    }
  }
});
