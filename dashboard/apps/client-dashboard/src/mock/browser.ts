/**
 * Mock mode bootstrap (pnpm dev:mock / e2e). Loaded only when VITE_MOCK=true, never in production builds.
 * Scenario via URL (before the hash): ?scenario=default|observe|review|first-run|login|degraded|empty|error|standalone|group|group-large
 * Without the request ring (MVP-22): ?ring=off.
 * The choice sticks for the browser tab (sessionStorage) so reloads keep it.
 */
import type { Scenario } from './data'
import { setupWorker } from 'msw/browser'
import { createState, SCENARIOS } from './data'
import { createHandlers } from './handlers'

const KEY = 'schild-mock-scenario'

export function currentScenario(): Scenario {
  const params = new URLSearchParams(window.location.search)
  const fromUrl = params.get('scenario') as Scenario | null
  if (fromUrl && SCENARIOS.includes(fromUrl)) {
    sessionStorage.setItem(KEY, fromUrl)
    return fromUrl
  }
  const stored = sessionStorage.getItem(KEY) as Scenario | null
  return stored && SCENARIOS.includes(stored) ? stored : 'default'
}

export async function startMock(prefix: string): Promise<void> {
  const scenario = currentScenario()
  const params = new URLSearchParams(window.location.search)
  // MVP-22: the request ring runs (Zugriffe, Kontext, bots); ?ring=off shows the gateway without it.
  const state = createState({ scenario, requestRing: params.get('ring') !== 'off' })
  // ?monitoring=off: the gateway runs with monitoring.enabled false (409 monitoring_off).
  if (params.get('monitoring') === 'off') state.monitoring.enabled = false
  const worker = setupWorker(...createHandlers(state, {
    prefix,
    latency: Number(params.get('latency') ?? 150),
    liveIntervalMs: Number(params.get('live') ?? 2500),
  }))
  await worker.start({ serviceWorker: { url: './mockServiceWorker.js' }, onUnhandledRequest: 'bypass', quiet: true })
  ;(window as unknown as { __schildMock: unknown }).__schildMock = state
  console.info(`[schild] Mock-Modus aktiv, Szenario „${scenario}“`)
}
