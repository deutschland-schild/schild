import type { BotCategory, BotVerification, GeoDb, RequestContext, RequestOutcome, RequestRecord, VisitorPattern } from '@/api/requests'
import { formatCompact, formatDateTime, formatNumber } from '@schild/ui'
import { BOT_CATEGORIES, TONES } from './monitoring'

/**
 * Wording and small helpers of the "Zugriffe" page (MVP-22, D35, D36): every request of the last 48 hours
 * from the request ring, bots and AI crawlers, the Kontext drawer. German, du-form, calm; "pseudonym",
 * never "anonym"; never an unqualified "geschützt" or "sicher". Humanizer pass applied.
 */
export const REQUESTS_COPY = {
  title: 'Zugriffe',
  description: 'Jede gespeicherte Anfrage: welche Seiten gefragt sind, woher die Besucher kommen, welche Bots vorbeischauen und was Schild erkannt oder gesperrt hat.',
  ringOffTitle: 'Das Zugriffsprotokoll ist ausgeschaltet',
  ringOff: 'Schild speichert gerade keine einzelnen Anfragen (monitoring.requests.enabled: false in schild.yaml). Die Summen im Überblick zählt es trotzdem weiter. Liste, Kontext und Bot-Prüfung brauchen das Zugriffsprotokoll.',
  monitoringOff: 'Die Messung ist ausgeschaltet (monitoring.enabled: false in schild.yaml). Ohne Messung gibt es weder Summen noch einzelne Anfragen.',
  busy: 'Gerade läuft schon eine andere Abfrage. Versuch es in ein paar Sekunden noch einmal.',
  sampled: 'Näherungswert: Das Zugriffsprotokoll ist an seiner Größengrenze. Schild behält darum nur die Anfragen eines Teils der Besucher, die aber vollständig.',
  sampledShort: (rate: number) => `Näherungswert: etwa ${formatNumber(Math.round(rate * 100))} % der Besucher gespeichert`,
  scanCapped: 'Schild hat für diese Seite 100.000 Anfragen gelesen und dort angehalten. „Mehr laden“ liest weiter.',
  ringOnly: 'Einzelne Anfragen bewahrt Schild so lange auf wie IP-Adressen, normalerweise 14 Tage. Ältere Zeiträume zeigen nur Summen.',
  ringClamped: 'Bots und KI-Crawler gibt es nur, so weit Schild einzelne Anfragen aufbewahrt. Darum zeigt dieser Bereich einen kürzeren Zeitraum.',
  privacy: 'Gespeichert werden IP-Adresse, User-Agent, Seite, Herkunftsdomain, Land und Antwortzeit, so lange wie IP-Adressen (normalerweise 14 Tage, retention.raw_ip_days in schild.yaml) und nur auf deinem Server. Keine Cookies, kein Skript im Browser.',
  uaScope: 'Alle gespeicherten Anfragen an diese Website mit diesem Text im User-Agent, so weit Schild sie aufbewahrt. Den User-Agent kann jeder frei wählen: Ob ein Bot echt ist, zeigt die Prüfung.',
  ipScope: 'Alle gespeicherten Anfragen dieser Adresse auf allen Websites dieses Servers, so weit Schild sie aufbewahrt.',
  filterNotInList: (labels: string) => `Nicht in der Liste anwendbar: ${labels}.`,
  noRequests: 'In diesem Zeitraum gibt es keine Anfragen mit diesen Filtern.',
  crawlerControl: ['Welche Crawler diese Website abrufen dürfen, legst du unter', 'fest. robots.txt setzt Schild nicht durch.'],
  verificationNote: 'Bestätigt heißt: Die Adresse gehört zu den Netzen, die der Betreiber selbst veröffentlicht. Die Prüfung läuft lokal auf deinem Server.',
  noBots: 'In diesem Zeitraum hat Schild keine bekannten Bots gesehen.',
  falsePositive: 'möglicher Fehlalarm',
  falsePositiveText: 'Diese Regel trifft auf dieser Seite fast nur Besucher, die sich sonst normal verhalten. Mit der Ausnahme unten prüft Schild hier dieses eine Feld nicht mehr mit dieser Regel.',
  exceptionNotApplied: 'Schild trägt die Ausnahme nicht von selbst ein. Du legst sie mit einem Klick an oder kopierst sie in dein Repository.',
  review: 'bitte ansehen',
  reviewText: 'Hier hat Schild Alarme erkannt, ohne zu sperren, und deine App hat mit 2xx geantwortet. Schau dir die Seite an.',
} as const

/** Sub-tabs of Zugriffe (URL `view`). */
export const REQUEST_TABS = [
  { key: 'overview', label: 'Überblick' },
  { key: 'pages', label: 'Seiten' },
  { key: 'sources', label: 'Herkunft' },
  { key: 'countries', label: 'Länder' },
  { key: 'bots', label: 'Bots & KI-Crawler' },
  { key: 'tech', label: 'Technik' },
  { key: 'errors', label: 'Fehler & Langsam' },
  { key: 'requests', label: 'Anfragen' },
] as const
export type RequestTabKey = typeof REQUEST_TABS[number]['key']
export function requestTabOf(v: unknown): RequestTabKey {
  return REQUEST_TABS.find(t => t.key === v)?.key ?? 'overview'
}

// ------------------------------------------------------------------ outcomes

/**
 * What schild did with a request (RequestOutcome). Label "Erkannt" for would_block and "Gesperrt" for the
 * blocked outcomes everywhere (initiator 2026-10-29); the detail names the reason. tone: how strong the
 * pill is drawn on the tonal scale (no red for traffic): plain, outline, strong, neutral (503).
 */
export const REQUEST_OUTCOMES: Record<RequestOutcome, { label: string, detail: string, tone: 'plain' | 'outline' | 'strong' | 'neutral' }> = {
  passed: { label: 'Durchgelassen', detail: 'Unauffällig, die Anfrage kam durch.', tone: 'plain' },
  would_block: { label: 'Erkannt', detail: 'Erkannt, aber durchgelassen.', tone: 'outline' },
  blocked_waf: { label: 'Gesperrt', detail: 'Gesperrt von einer Regel.', tone: 'strong' },
  blocked_behaviour: { label: 'Gesperrt', detail: 'Gesperrt wegen auffälligen Verhaltens.', tone: 'strong' },
  rate_limited: { label: 'Gesperrt', detail: 'Gesperrt, weil zu viele Anfragen kamen.', tone: 'strong' },
  rejected_limit: { label: 'Gesperrt', detail: 'Abgewiesen, weil die Anfrage zu groß oder ungültig war.', tone: 'strong' },
  fail_closed: { label: '503 von Schild', detail: 'Schild konnte die Anfrage nicht rechtzeitig prüfen und hat sie mit 503 beantwortet. Ungeprüft geht keine Anfrage durch.', tone: 'neutral' },
  blocked_crawler: { label: 'Gesperrt', detail: 'Gesperrt von der Crawler-Regel dieser Website.', tone: 'strong' },
}
export const REQUEST_OUTCOME_KEYS = Object.keys(REQUEST_OUTCOMES) as RequestOutcome[]
/** Options of the outcome filter (blocked outcomes keep their reason so the filter is exact). */
export const OUTCOME_FILTER_LABELS: Record<RequestOutcome, string> = {
  passed: 'Durchgelassen',
  would_block: 'Erkannt',
  blocked_waf: 'Gesperrt: Regel',
  blocked_behaviour: 'Gesperrt: Verhalten',
  rate_limited: 'Gesperrt: zu viele Anfragen',
  rejected_limit: 'Gesperrt: zu groß oder ungültig',
  fail_closed: '503 von Schild',
  blocked_crawler: 'Gesperrt: Crawler-Regel',
}
export const isAlert = (r: Pick<RequestRecord, 'outcome' | 'rules'>) => (r.outcome !== 'passed' && r.outcome !== 'fail_closed') || (r.rules?.length ?? 0) > 0

// ------------------------------------------------------------------ bots

/**
 * Verification of a bot (BotVerification) in words. mismatch names the bot it pretends to be:
 * "gibt sich als Googlebot aus".
 */
export const VERIFICATION: Record<BotVerification, { label: string, explain: string, tone: 'plain' | 'outline' | 'strong' | 'muted' }> = {
  verified: { label: 'bestätigt', explain: 'Die Adresse gehört zu einem Netz, das der Betreiber selbst veröffentlicht.', tone: 'plain' },
  claimed: { label: 'nicht prüfbar', explain: 'Der Betreiber veröffentlicht keine Adressen, oder die Prüfung ist aus. Schild kennt nur, was der Bot über sich sagt.', tone: 'muted' },
  mismatch: { label: 'gibt sich als … aus', explain: 'Der Betreiber veröffentlicht seine Adressen, und diese Adresse gehört nicht dazu. Jemand anderes nutzt den Namen.', tone: 'strong' },
  unknown_stale: { label: 'Prüfliste veraltet', explain: 'Die Adressliste des Betreibers ist älter als 30 Tage. Schild bestätigt damit nichts mehr, bis eine neue Liste kommt.', tone: 'outline' },
}
export const VERIFICATION_KEYS = Object.keys(VERIFICATION) as BotVerification[]
/** "bestätigt", "gibt sich als Googlebot aus" … */
export function verificationLabel(v: BotVerification, botName?: string): string {
  if (v === 'mismatch') return botName ? `gibt sich als ${botName} aus` : 'gibt sich als Bot aus'
  return VERIFICATION[v].label
}

export function robotsText(r: { respects: 'yes' | 'no' | 'unclear', disallowed_requests: number }): string {
  if (r.respects === 'no') return `nein, ${formatNumber(r.disallowed_requests)} ${r.disallowed_requests === 1 ? 'Anfrage' : 'Anfragen'} auf gesperrte Pfade`
  if (r.respects === 'yes') return 'ja'
  return 'unklar'
}

export const RANGE_SOURCE: Record<'release' | 'fetch', string> = {
  release: 'mit der Schild-Version',
  fetch: 'direkt vom Betreiber',
}

export function botCategoryLabel(c: BotCategory | string): string {
  return BOT_CATEGORIES[c] ?? c
}
export const AI_CATEGORIES: ReadonlySet<string> = new Set(['ai_training', 'ai_search', 'ai_assistant'])

// ------------------------------------------------------------------ Kontext

export const PATTERNS: Record<VisitorPattern, { label: string, explain: string }> = {
  alert_only: { label: 'nur Alarme, wirkt wie ein Scanner', explain: 'Jede Anfrage dieses Besuchers in diesen 10 Minuten hat einen Alarm ausgelöst.' },
  in_session: { label: 'Alarm mitten in normaler Nutzung', explain: 'Vor und nach dem Alarm hat dieser Besucher ganz normal Seiten aufgerufen. Das spricht eher für einen Fehlalarm.' },
  no_alert: { label: 'keine Alarme', explain: 'Dieser Besucher hat in diesen 10 Minuten keinen Alarm ausgelöst.' },
}

export const CONTEXT_STATES: Record<RequestContext['state'], { label: string, explain: string } | null> = {
  complete: null,
  sampled: { label: 'Näherungswert', explain: 'Das Zugriffsprotokoll war an seiner Größengrenze. Für diesen Zeitraum hat Schild nur die Anfragen eines Teils der Besucher behalten. Die Anfragen dieses Besuchers sind trotzdem vollständig, wenn er dazugehört.' },
  expired: { label: 'nicht mehr gespeichert', explain: 'Einzelne Anfragen bewahrt Schild so lange auf wie IP-Adressen, normalerweise 14 Tage. Das Ereignis selbst bleibt, die Anfragen davor und danach sind gelöscht.' },
}

/** "−2:15" / "+0:40" relative to the anchor (mm:ss), "jetzt" for the anchor itself. */
export function offsetText(t: string, anchor: string): string {
  const d = Math.round((Date.parse(t) - Date.parse(anchor)) / 1000)
  if (d === 0) return '0:00'
  const a = Math.abs(d)
  return `${d < 0 ? '−' : '+'}${Math.floor(a / 60)}:${String(a % 60).padStart(2, '0')}`
}

/** Anfragen, Seitenaufrufe, 2xx, Alarme in one line. */
export function visitorSummaryText(s: NonNullable<RequestContext['visitor_summary']>): string {
  const n = (v: number, one: string, many: string) => `${formatNumber(v)} ${v === 1 ? one : many}`
  return [n(s.requests, 'Anfrage', 'Anfragen'), n(s.page_views, 'Seitenaufruf', 'Seitenaufrufe'), `${formatNumber(s.status_2xx)} mit 2xx`, n(s.alerts, 'Alarm', 'Alarme')].join(' · ')
}

/** The Kontext drawer opens from any page with ?context=<event id> (incidents, events, alerts). */
export const CONTEXT_PARAM = 'context'
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export function contextIdOf(v: unknown): string | null {
  return typeof v === 'string' && UUID.test(v) ? v.toLowerCase() : null
}
/** Same page, plus the Kontext drawer for this event. */
export function contextLink(route: { path: string, query: Record<string, unknown> }, eventId: string) {
  return { path: route.path, query: { ...(route.query as Record<string, string>), [CONTEXT_PARAM]: eventId } }
}

// ------------------------------------------------------------------ time windows of the list

/**
 * A real path as people read it (D63): percent escapes decoded (/%C3%BCber-uns as /über-uns). Control
 * and bidi characters, slashes and question marks stay escaped, so the shown path is the path that was asked for.
 */
export function pathText(path: string): string {
  return path.replace(/(?:%[0-9a-f]{2})+/gi, (m) => {
    try {
      const d = decodeURIComponent(m)
      // eslint-disable-next-line no-control-regex -- control characters are what this keeps escaped
      return /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069/?#%]/.test(d) ? m : d
    }
    catch {
      return m
    }
  })
}

/** With an address queryRequests reads the whole ring (D49). */
export const RING_SECONDS = 48 * 3600
/** queryRequests reads at most 6 hours: the list shows a window ending `bis` hours ago. */
export const LIST_WINDOWS = { '15m': { label: '15 Minuten', seconds: 900 }, '1h': { label: '1 Stunde', seconds: 3600 }, '6h': { label: '6 Stunden', seconds: 6 * 3600 } } as const
export type ListWindowKey = keyof typeof LIST_WINDOWS
export const LIST_ENDS = [0, 6, 12, 18, 24, 30, 36, 42] as const
export function listWindowOf(v: unknown): ListWindowKey {
  return typeof v === 'string' && v in LIST_WINDOWS ? v as ListWindowKey : '1h'
}
export function listEndOf(v: unknown): number {
  const n = Number(v)
  return (LIST_ENDS as readonly number[]).includes(n) ? n : 0
}
export function listEndLabel(h: number): string {
  return h === 0 ? 'bis jetzt' : `bis vor ${h} Stunden`
}

// ------------------------------------------------------------------ geo database

const GEO_PROVIDERS: Record<string, string> = { dbip: 'DB-IP Lite', ipinfo: 'IPinfo', maxmind: 'MaxMind' }
const GEO_ERRORS: Record<string, string> = {
  token_missing: 'Der Schlüssel fehlt',
  token_rejected: 'Der Anbieter hat den Schlüssel abgelehnt',
  download_failed: 'Der Download hat nicht geklappt',
  too_large: 'Die Datei war zu groß',
  invalid_format: 'Die Datei hatte ein unbekanntes Format',
  sanity_failed: 'Die Stichprobe hat nicht gepasst',
}
const day = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })

/**
 * "Geo-Daten: IPinfo, Stand 01.10.2026" (Overview.geo_db, D35). Without a provider the bundled DB-IP
 * Lite. With a failed download: why, and that the previous database stays in use.
 */
export function geoDbText(g: GeoDb | undefined | null): { line: string, error: string | null } | null {
  if (!g || (!g.provider && !g.source && !g.built_at)) return null
  // A downloading provider without databases yet: the bundled DB-IP Lite answers until the first
  // download works (the gateway keeps it as fallback).
  const pending = !!g.provider && g.provider !== 'dbip' && (!g.databases || g.databases.length === 0)
  const name = pending ? 'DB-IP Lite (mitgeliefert)' : GEO_PROVIDERS[g.provider ?? 'dbip'] ?? g.provider ?? 'DB-IP Lite'
  const date = g.built_at ? `, Stand ${day.format(new Date(g.built_at))}` : ''
  const refreshed = pending
    ? `; ${GEO_PROVIDERS[g.provider!] ?? g.provider} ist noch nicht geladen`
    : g.refreshed_at ? `, zuletzt geladen ${formatDateTime(g.refreshed_at)}` : ''
  const error = g.last_error ? `${GEO_ERRORS[g.last_error] ?? 'Der letzte Download hat nicht geklappt'}${g.last_error_at ? ` (${formatDateTime(g.last_error_at)})` : ''}. Schild nutzt weiter die bisherige Datenbank.` : null
  return { line: `Geo-Daten: ${name}${date}${refreshed}`, error }
}

// ------------------------------------------------------------------ world map

/**
 * Sequential scale of the Länder map: the five validated steps of the one brand hue (light to dark in
 * light mode, dark to bright in dark mode), never red. Countries without requests use the muted surface.
 */
export const MAP_STEP_COLORS = [TONES.wash, TONES.light, TONES.mid, TONES.main, TONES.deep] as const

/** Log steps from 1 to the largest value (traffic per country spans orders of magnitude). */
export function mapSteps(values: number[]): { stepOf: (v: number) => number, labels: string[] } {
  const max = Math.max(1, ...values)
  const n = MAP_STEP_COLORS.length
  const lower = Array.from({ length: n }, (_, k) => Math.max(1, Math.ceil(max ** (k / n))))
  const stepOf = (v: number) => {
    if (!(v > 0)) return -1
    if (max <= 1) return n - 1
    return Math.min(n - 1, Math.floor((Math.log(v) / Math.log(max)) * n))
  }
  return { stepOf, labels: lower.map(l => `ab ${formatCompact(l)}`) }
}
