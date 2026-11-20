import type { Problem } from '@/api/types'
import { ApiError } from '@schild/app-kit'

const BY_CODE: Record<string, string> = {
  unauthenticated: 'Deine Sitzung ist abgelaufen. Melde dich bitte neu an.',
  csrf: 'Die Sitzung passt nicht mehr. Lade die Seite neu und versuch es noch einmal.',
  forbidden: 'Das Passwort stimmt nicht, oder dir fehlt die Berechtigung.',
  not_found: 'Das gibt es nicht (mehr).',
  conflict: 'Das wurde inzwischen geändert. Lade neu und prüfe noch einmal.',
  invalid: 'Bitte prüf die markierten Felder.',
  rate_limited: 'Zu viele Versuche. Warte kurz und versuch es dann noch einmal.',
  internal: 'Im Lab ist etwas schiefgelaufen. Versuch es gleich noch einmal.',
  seclang: 'Die Regel liegt außerhalb der erlaubten SecLang-Teilmenge.',
  evidence: 'Die Belege reichen für diese Aktion nicht.',
  self_approval: 'Diesen Vorschlag hast du selbst eingereicht. Freigeben muss ihn eine andere Person.',
  threshold: 'Es fehlen noch Signaturen anderer Betreiber.',
  validity: 'Die Gültigkeit passt nicht.',
  config: 'Die Einstellung ist so nicht gültig.',
}

export function asProblem(err: unknown): Problem | undefined {
  if (err instanceof ApiError && err.body && typeof err.body === 'object') return err.body as Problem
  return undefined
}

/** One short German sentence for a failed request. */
export function problemMessage(err: unknown): string {
  const p = asProblem(err)
  if (p?.code && BY_CODE[p.code]) return p.detail && p.code !== 'internal' ? `${BY_CODE[p.code]} ${p.detail}` : BY_CODE[p.code]!
  if (p?.detail) return p.detail
  if (err instanceof ApiError) {
    if (err.status === 401) return BY_CODE.unauthenticated!
    if (err.status === 403) return BY_CODE.forbidden!
    if (err.status === 409) return BY_CODE.conflict!
    if (err.status === 429) return BY_CODE.rate_limited!
    if (err.status >= 500) return BY_CODE.internal!
  }
  if (err instanceof TypeError) return 'Das Lab ist gerade nicht erreichbar.'
  return 'Das hat nicht geklappt. Versuch es noch einmal.'
}

/** Field errors keyed by the first JSON-pointer segment ("/reason" -> "reason", "/scoring/min_issuers" -> "scoring.min_issuers"). */
export function fieldErrors(err: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  for (const e of asProblem(err)?.errors ?? []) {
    const key = e.pointer.replace(/^#?\/?/, '').replace(/^query\//, '').split('/').join('.')
    out[key] ??= e.detail
  }
  return out
}

/** Technical detail for collapsible error boxes. */
export function problemDetail(err: unknown): string | undefined {
  const p = asProblem(err)
  if (p) return [p.status && `HTTP ${p.status}`, p.code, p.title].filter(Boolean).join(' · ')
  return err instanceof Error ? err.message : undefined
}
