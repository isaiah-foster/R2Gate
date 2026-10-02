import { defineProject } from 'vitest/config';

export default defineProject({
  test: {
    name: 'dashboard',
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
