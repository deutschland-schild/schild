import { defineConfig, devices } from '@playwright/test'

// E2E against the mock mode (MSW + contract fixtures). Uses the Chromium bundled with the pinned Playwright version;
// run `playwright install chromium` once after a version bump.
// Run: pnpm test:e2e
const PORT = Number(process.env.E2E_PORT ?? 5180)

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: `http://localhost:${PORT}/`,
    trace: 'retain-on-failure',
    locale: 'de-DE',
    timezoneId: 'Europe/Berlin',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-390', use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
  webServer: {
    command: `pnpm exec vite --mode mock --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    // The agent flows (MVP-11) stay covered while the dashboard hides agents by default (2026-11-02).
    env: { VITE_HOST_AGENTS: 'true' },
  },
})
