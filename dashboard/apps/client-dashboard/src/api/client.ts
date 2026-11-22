import type { paths } from './generated/schema'
import type { Problem, Session } from './types'
import { ApiError, createApi } from '@schild/app-kit'
import { reactive } from 'vue'
import { withNode } from '../lib/node-filter'
import { apiPrefix } from './generated/operations'

/**
 * Session state shared by the API client (CSRF header) and the router guard.
 * The session cookie itself is HttpOnly and never visible here.
 */
export const session = reactive<{ value: Session | null, loaded: boolean }>({ value: null, loaded: false })

type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | undefined
/** Called by the router setup: what to do when the API answers 401 (session expired). */
export function setUnauthorizedHandler(fn: UnauthorizedHandler) {
  onUnauthorized = fn
}

/**
 * Typed client for the local Schild API (/api/v0 next to the dashboard page).
 * Every state-changing request carries X-CSRF-Token from GET /auth/session.
 */
export const api = createApi<paths>({
  prefix: apiPrefix,
  credentials: 'same-origin',
  // Resolve fetch per call (not at import time), so test interceptors and polyfills apply.
  // In a cluster the counters and charts take the gateway chosen in the filter "Server" (lib/node-filter).
  fetch: (req: Request) => globalThis.fetch(withNode(req)),
  auth: {
    headers: (): Record<string, string> => {
      const token = session.value?.csrf_token
      return token ? { 'X-CSRF-Token': token } : {}
    },
    onUnauthorized: () => onUnauthorized?.(),
  },
})

/**
 * Typed `header` parameter for state-changing calls. The auth middleware sets the same header;
 * this only satisfies the generated types, which mark X-CSRF-Token as required.
 */
export function csrf(): { 'X-CSRF-Token': string } {
  return { 'X-CSRF-Token': session.value?.csrf_token ?? '' }
}

/** The RFC 9457 problem behind an error, if any. */
export function problemOf(err: unknown): Problem | null {
  if (err instanceof ApiError && err.body && typeof err.body === 'object') {
    const b = err.body as Partial<Problem>
    if (typeof b.status === 'number' || typeof b.code === 'string' || typeof b.title === 'string') {
      return { type: b.type ?? 'about:blank', title: b.title ?? '', status: b.status ?? err.status, ...b } as Problem
    }
  }
  return null
}

export function statusOf(err: unknown): number | null {
  if (err instanceof ApiError) return err.status
  return null
}

/** Field errors of a problem, keyed by JSON pointer without leading "/" ("confirm/password"). */
export function fieldErrors(err: unknown): Record<string, string> {
  const p = problemOf(err)
  const out: Record<string, string> = {}
  for (const e of p?.errors ?? []) out[e.pointer.replace(/^#?\//, '')] = e.detail
  return out
}

/**
 * German, calm message for an API error: what happened and the next step.
 * The UI never parses `detail`; it maps the stable `code`.
 */
export function errorMessage(err: unknown, fallback = 'Das hat nicht geklappt. Versuch es gleich noch einmal.'): string {
  const p = problemOf(err)
  const status = statusOf(err)
  const code = p?.code
  if (code === 'unauthenticated' || status === 401) return 'Deine Anmeldung ist abgelaufen. Melde dich bitte neu an.'
  if (code === 'csrf') return 'Die Sitzung ist nicht mehr gültig. Lade die Seite neu und versuch es noch einmal.'
  if (code === 'forbidden' || status === 403) return 'Dafür fehlt die Berechtigung, oder das Passwort stimmt nicht.'
  if (code === 'not_found' || status === 404) return 'Nicht gefunden. Prüf die Eingabe.'
  if (code === 'conflict' || status === 409) return 'Das wurde inzwischen schon geändert. Die Ansicht ist jetzt aktuell.'
  if (code === 'rate_limited' || status === 429) return 'Zu viele Versuche. Warte eine Minute und versuch es dann noch einmal.'
  if (code === 'invalid' || status === 400 || status === 422) return 'Bitte prüf die markierten Eingaben.'
  if (status === null) return 'Schild ist gerade nicht erreichbar. Prüf, ob der Dienst läuft, und versuch es noch einmal.'
  return fallback
}
