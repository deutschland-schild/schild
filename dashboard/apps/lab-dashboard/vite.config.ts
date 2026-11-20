import { dashboardConfig } from '../../packages/app-kit/vite-config'
import { defineConfig, mergeConfig } from 'vite'

export default defineConfig(({ mode }) => mergeConfig(dashboardConfig(import.meta.dirname, mode, 5174), {
  // Scan lazy views and the mock up front, so the dev server does not re-optimise and reload mid-session.
  optimizeDeps: { entries: ['index.html', 'src/**/*.vue', 'src/**/*.ts'] },
}))
