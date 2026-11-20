import { dashboardConfig } from '../../packages/app-kit/vite-config'
import { defineConfig, mergeConfig } from 'vitest/config'

export default mergeConfig(dashboardConfig(import.meta.dirname, 'test', 5173), defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    // A non-routable origin: tests must never reach a real server.
    environmentOptions: { jsdom: { url: 'http://dashboard.schild.test/' } },
    // Whole-app tests mount the shell and walk through pages; a loaded CI runner needs more than the 5 s default.
    testTimeout: 20_000,
    include: ['test/**/*.test.ts'],
    setupFiles: ['../../packages/ui/test/setup.ts', './test/setup.ts'],
    css: false,
  },
}))
