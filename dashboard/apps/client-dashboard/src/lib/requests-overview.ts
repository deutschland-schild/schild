import type { DonutSlice } from '@schild/ui'
import type { BreakdownDimension, TopEntry } from '@/api/monitoring'
import { BROWSERS, OS_FAMILIES, TONES } from './monitoring'
import { AI_CATEGORIES } from './requests'

/**
 * Überblick of Zugriffe (MVP-22, D36): who visits, from where, with what, in the manner of a cookie-free
 * web analytics view. Parts of a whole as donuts (at most five named slices plus "Andere"), long lists
 * as bars. Every number comes from the breakdowns, KPIs and series of the API; a share of a breakdown is
 * a share of requests (the breakdowns count requests, not visitors). German, du-form, calm; humanizer
 * pass applied.
 */
export const OVERVIEW_COPY = {
  sharesOfRequests: 'Anteile an den Anfragen.',
  noData: 'Noch keine Anfragen in diesem Zeitraum.',
  unavailable: 'Mit diesem Filter nur für einen kürzeren Zeitraum verfügbar.',
  security: 'Sicherheit',
  securityText: 'Was Schild in diesem Zeitraum an dieser Website abgefangen hat.',
  toEvents: 'Zu den Ereignissen',
  fpHint: 'Regeln, die vor allem Besucher:innen treffen, die sich sonst normal verhalten. Die Ausnahme dazu steht unter Ereignisse bei „Alarme nach Regel“.',
  fpNeedsRing: 'mit Zugriffsprotokoll',
} as const

/** "je 10 Minuten" for the step of a series. */
export function stepText(stepS: number): string {
  if (stepS < 60) return `je ${stepS} Sekunden`
  if (stepS === 60) return 'je Minute'
  if (stepS < 3600) return `je ${Math.round(stepS / 60)} Minuten`
  if (stepS === 3600) return 'je Stunde'
  return `je ${Math.round(stepS / 3600)} Stunden`
}

/** Sum of a series, null when it has no value at all. */
export function seriesSum(values: (number | null | undefined)[] | undefined): number | null {
  let sum = 0
  let any = false
  for (const v of values ?? []) {
    if (typeof v === 'number' && Number.isFinite(v)) {
      sum += v
      any = true
    }
  }
  return any ? sum : null
}

// ------------------------------------------------------------------ donuts

const C = (n: 1 | 2 | 3 | 4 | 5) => `var(--chart-${n})`
/** "Andere": the de-emphasis grey, never a categorical slot. */
export const OTHER_COLOR = TONES.neutral

/** One named slice: the keys of the breakdown it sums, its fixed colour and the filter a click sets. */
interface SliceDef {
  id: string
  label: string
  keys: (key: string) => boolean
  color: string
  /** `dimension:value` the click sets; without it the slice opens `tab` (or is not clickable). */
  filter?: string
  tab?: string
  hint?: string
}
export interface DonutDef {
  by: BreakdownDimension
  slices: SliceDef[]
  /** Keys left out of the whole (no device, no browser: bots and tools), named below the donut. */
  excluded?: (key: string) => boolean
  /** The slice that takes the breakdown's rest beyond the top list (else "Andere"). */
  restTo?: string
}

const one = (by: BreakdownDimension, key: string, label: string, color: string, hint?: string): SliceDef => ({ id: key, label, keys: k => k === key, color, filter: `${by}:${key}`, hint })

/**
 * The donuts of the Überblick. The colour of a slice follows the entity (fixed slot per key, in the
 * usual order of size so neighbours are validated pairs), never its rank; everything else folds into
 * "Andere" (grey). Mensch / Bot groups bot categories: KI-Crawler and Andere Bots span several
 * categories, a filter takes one value, so a click opens Bots & KI-Crawler instead.
 */
export const DONUTS = {
  bots: {
    by: 'bot_category',
    restTo: 'bots',
    slices: [
      { ...one('bot_category', 'likely_browser', 'Menschen', C(1)), hint: 'Wahrscheinlich Browser: kein bekannter Bot und kein Werkzeug in der Kennung.' },
      one('bot_category', 'search_engine', 'Suchmaschinen', C(2)),
      { id: 'ai', label: 'KI-Crawler', keys: k => AI_CATEGORIES.has(k), color: C(3), tab: 'bots', hint: 'KI-Training, KI-Suche und KI-Assistenten' },
      { id: 'bots', label: 'Andere Bots', keys: k => k !== 'likely_browser' && k !== 'search_engine' && !AI_CATEGORIES.has(k), color: C(4), tab: 'bots', hint: 'Vorschauen, Feed-Reader, Monitoring, SEO- und Sicherheitsscanner, Werkzeuge' },
    ],
  },
  device: {
    by: 'device',
    slices: [one('device', 'mobile', 'Mobil', C(1)), one('device', 'desktop', 'Desktop', C(2)), one('device', 'tablet', 'Tablet', C(3))],
    excluded: k => k === 'unknown',
  },
  browser: {
    by: 'browser',
    slices: (['chrome', 'safari', 'firefox', 'edge', 'samsung'] as const).map((k, i) => one('browser', k, BROWSERS[k]!, C((i + 1) as 1 | 2 | 3 | 4 | 5))),
    excluded: k => k === 'none',
  },
  os: {
    by: 'os',
    slices: (['android', 'windows', 'ios', 'macos', 'linux'] as const).map((k, i) => one('os', k, OS_FAMILIES[k]!, C((i + 1) as 1 | 2 | 3 | 4 | 5))),
    excluded: k => k === 'none',
  },
  status: {
    by: 'status_class',
    slices: [
      one('status_class', '2xx', '2xx Erfolg', C(1), 'Die Seite wurde ausgeliefert.'),
      one('status_class', '3xx', '3xx Umleitung', C(2), 'Weiterleitung auf eine andere Adresse.'),
      one('status_class', '4xx', '4xx Fehler', C(3), 'Fehler der Anfrage, zum Beispiel eine Seite, die es nicht gibt.'),
      // 5xx in violet, not pink: no red tones for answers of the website.
      one('status_class', '5xx', '5xx Serverfehler', C(4), 'Fehler deiner App oder des Servers.'),
    ],
  },
} satisfies Record<string, DonutDef>
export type DonutKey = keyof typeof DONUTS

export interface DonutView {
  slices: (DonutSlice & { filter?: string, tab?: string })[]
  /** Sum of the slices (the whole the shares refer to). */
  total: number
  /** Requests left out (no device or browser named). */
  excluded: number
}

/**
 * Slices of a breakdown: named slices largest first, then "Andere" (the rest of the items plus the
 * breakdown's own `other`). Excluded keys leave the whole and are counted separately. With
 * `otherCount` the breakdown's rest beyond the top list is added to "Andere".
 */
export function donutSlices(def: DonutDef, items: Pick<TopEntry, 'key' | 'requests'>[], otherCount = 0): DonutView {
  const named = def.slices.map(s => ({ s, value: 0 }))
  const restSlice = named.find(n => n.s.id === def.restTo)
  let rest = restSlice ? 0 : Math.max(0, otherCount)
  if (restSlice) restSlice.value += Math.max(0, otherCount)
  let excluded = 0
  for (const it of items) {
    if (def.excluded?.(it.key)) {
      excluded += it.requests
      continue
    }
    const hit = named.find(n => n.s.keys(it.key))
    if (hit) hit.value += it.requests
    else rest += it.requests
  }
  const slices: DonutView['slices'] = named
    .filter(n => n.value > 0)
    .sort((a, b) => b.value - a.value)
    .map(n => ({ id: n.s.id, label: n.s.label, value: n.value, color: n.s.color, clickable: !!(n.s.filter || n.s.tab), hint: n.s.hint, filter: n.s.filter, tab: n.s.tab }))
  if (rest > 0) slices.push({ id: '_other', label: 'Andere', value: rest, color: OTHER_COLOR, other: true })
  return { slices, total: slices.reduce((a, s) => a + s.value, 0), excluded }
}

/**
 * Neu / wiederkehrend: the new visitors are the sum of traffic.clients_new over the steps (a client is new
 * once: not seen in the 7 days before, or since the last start of schild); the rest of the KPI Besucher
 * (distinct visitors per day, summed over the days) came back. Both are estimates: a Näherungswert.
 */
export function newReturningSlices(visitors: number | null | undefined, fresh: number | null | undefined): DonutSlice[] {
  if (visitors === null || visitors === undefined || fresh === null || fresh === undefined) return []
  const unique = visitors
  const n = Math.max(0, Math.min(fresh, unique))
  return [
    { id: 'new', label: 'Neu', value: n, color: C(1), hint: 'In den 7 Tagen davor nicht gesehen.' },
    { id: 'returning', label: 'Wiederkehrend', value: Math.max(0, unique - n), color: C(2), hint: 'In den 7 Tagen davor schon einmal gesehen.' },
  ].sort((a, b) => b.value - a.value)
}

// ------------------------------------------------------------------ bars

export const isAiReferrer = (key: string) => key.startsWith('ai:')
