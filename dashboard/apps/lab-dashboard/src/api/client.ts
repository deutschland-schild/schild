import type { paths } from './generated/schema'
import { createApi, defaultBaseUrl } from '@schild/app-kit'
import { authProvider } from './auth-state'
import { apiPrefix } from './generated/operations'

/** Typed client for the lab API (contracts/api/lab-dashboard.openapi.yaml, generated with `pnpm gen:api`). */
export const api = createApi<paths>({
  prefix: apiPrefix,
  auth: authProvider,
  credentials: 'same-origin',
  // Resolve fetch per call (not once at import), so test interceptors and polyfills apply.
  fetch: (req: Request) => globalThis.fetch(req),
})

/** Absolute URL below the API prefix, e.g. for EventSource. */
export function apiUrl(path: string): string {
  return `${defaultBaseUrl(apiPrefix)}${path}`
}
