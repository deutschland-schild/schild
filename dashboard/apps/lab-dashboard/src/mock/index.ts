import type { Session } from '@/api/types'
import type { SessionStore } from './state'
import { labHandlers } from './handlers'
import { LabMock } from './state'

const KEY = 'schild-lab-mock-session'

/** Session kept in sessionStorage so a reload stays logged in (mock only; the real lab uses an HttpOnly cookie). */
function storageSession(): SessionStore {
  const initial: Session = { authenticated: false, first_run: new URLSearchParams(location.search).has('first-run') }
  return {
    get: () => {
      try {
        return (JSON.parse(sessionStorage.getItem(KEY) ?? 'null') as Session | null) ?? initial
      }
      catch {
        return initial
      }
    },
    set: s => sessionStorage.setItem(KEY, JSON.stringify(s)),
  }
}

/** Start the MSW worker with the stateful lab mock (mock mode only, never in production bundles). */
export async function startLabMock(prefix: string): Promise<LabMock> {
  const { setupWorker } = await import('msw/browser')
  const mock = new LabMock(storageSession())
  const worker = setupWorker(...labHandlers(mock, prefix))
  await worker.start({ serviceWorker: { url: './mockServiceWorker.js' }, onUnhandledRequest: 'bypass', quiet: true })
  console.info('[schild] Lab-Mock aktiv (Testdaten, Zustand nur im Speicher). Passwort "falsch" simuliert einen Fehler.')
  return mock
}
