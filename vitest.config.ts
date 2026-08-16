import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'https://app.example.com/',
      },
    },
    include: ['test/**/*.test.ts'],
    setupFiles: ['test/setup.ts'],
  },
});
