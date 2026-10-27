import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/main.ts', 'src/vite-env.d.ts', 'src/**/*.test.ts'],
      thresholds: {
        statements: 95,
        branches: 90,
        functions: 95,
        lines: 95
      },
      reporter: ['text', 'json', 'json-summary']
    }
  }
});
