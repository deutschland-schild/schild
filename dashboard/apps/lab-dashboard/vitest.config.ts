import { dashboardConfig } from '../../packages/app-kit/vite-config'
import { defineConfig, mergeConfig } from 'vitest/config'

export default mergeConfig(dashboardConfig(import.meta.dirname, 'test', 5174), defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    // Whole-app tests; a loaded CI runner needs more than the 5 s default.
    testTimeout: 20_000,
    include: ['test/**/*.test.ts'],
    setupFiles: ['../../packages/ui/test/setup.ts'],
    css: false,
  },
}))
