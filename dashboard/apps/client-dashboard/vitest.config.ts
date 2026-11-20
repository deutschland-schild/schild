import { dashboardConfig } from '../../packages/app-kit/vite-config'
import { defineConfig, mergeConfig } from 'vitest/config'

export default mergeConfig(dashboardConfig(import.meta.dirname, 'test', 5173), defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    // A non-routable origin: tests must never reach a real server.
    environmentOptions: { jsdom: { url: 'http://dashboard.schild.test/' } },
    include: ['test/**/*.test.ts'],
    setupFiles: ['../../packages/ui/test/setup.ts', './test/setup.ts'],
    css: false,
  },
}))
