import { dashboardConfig } from '../../packages/app-kit/vite-config'
import { defineConfig } from 'vite'

export default defineConfig(({ mode }) => dashboardConfig(import.meta.dirname, mode, 5173))
