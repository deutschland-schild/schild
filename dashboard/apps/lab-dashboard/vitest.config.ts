import { dashboardConfig } from '../../packages/app-kit/vite-config'
import { defineConfig, mergeConfig } from 'vitest/config'

export default mergeConfig(dashboardConfig(import.meta.dirname, 'test', 5174), defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    include: ['test/**/*.test.ts'],
    setupFiles: ['../../packages/ui/test/setup.ts'],
    css: false,
  },
}))
