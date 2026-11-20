import type { AuthProvider } from '@schild/app-kit'

/**
 * Auth state shared between the API client and the session gate.
 * The session cookie travels automatically (same origin); state changes carry X-CSRF-Token (lab-dashboard.openapi.yaml).
 */
let csrfToken = ''
let unauthorizedHandler: (() => void) | undefined

export function setCsrfToken(token: string | undefined): void {
  csrfToken = token ?? ''
}

export function getCsrfToken(): string {
  return csrfToken
}

export function onUnauthorized(handler: (() => void) | undefined): void {
  unauthorizedHandler = handler
}

/** Header object for operations that declare the CSRF parameter. */
export function csrf(): { 'X-CSRF-Token': string } {
  return { 'X-CSRF-Token': csrfToken }
}

export const authProvider: AuthProvider = {
  headers: (): Record<string, string> => (csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
  onUnauthorized: () => unauthorizedHandler?.(),
}
