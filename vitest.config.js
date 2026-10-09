import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    {
      name: 'strip-shebang',
      transform(code) {
        if (typeof code === 'string' && code.startsWith('#!')) {
          return {
            code: code.replace(/^#![^\r\n]*/, ''),
            map: null
          };
        }
      }
    }
  ],
  test: {
    environment: 'node',
    include: ['tests/**/*.test.js'],
    globals: true,
    testTimeout: 10000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.js'],
    },
  },
});
