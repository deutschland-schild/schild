import type { FilterChip } from '@schild/ui'
import type { MaybeRefOrGetter } from 'vue'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import type { EventQuery } from '@/api/queries'
import type { EventSummary, Outcome } from '@/api/types'
import { countryName } from '@schild/ui'
import { computed, ref, toValue, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { eventTypeLabel, OUTCOMES } from '@/lib/labels'
import { METHODS, NET_CLASSES, UA_CLASSES } from '@/lib/monitoring'

/**
 * Event filters live in the URL (deep links): /events?time=24h&outcome=blocked&country=NL&ip=203.0.113.0/24,
 * the same on /w/<website>/events. Short URL names, API names inside.
 */
export const TIME_RANGES = [
  { value: '15m', label: 'Letzte 15 Minuten', ms: 15 * 60_000 },
  { value: '1h', label: 'Letzte Stunde', ms: 3600_000 },
  { value: '24h', label: 'Letzte 24 Stunden', ms: 24 * 3600_000 },
  { value: '7d', label: 'Letzte 7 Tage', ms: 7 * 24 * 3600_000 },
  { value: 'all', label: 'Alles Gespeicherte', ms: 0 },
] as const
export type TimeRange = typeof TIME_RANGES[number]['value']

/** URL name -> API name of the simple filters. */
export const FIELD_MAP = {
  outcome: 'outcome',
  ip: 'ip',
  country: 'country',
  asn: 'asn',
  path: 'path',
  rule: 'rule',
  session: 'session',
  type: 'type',
  website: 'site',
  net: 'net_class',
  method: 'method',
  client: 'ua_class',
  q: 'q',
} as const
export type UrlField = keyof typeof FIELD_MAP

export const FIELD_LABELS: Record<UrlField, string> = {
  outcome: 'Ergebnis',
  ip: 'IP',
  country: 'Land',
  asn: 'Netz (ASN)',
  path: 'Pfad',
  rule: 'Regel',
  session: 'Sitzung',
  type: 'Art',
  website: 'Website',
  net: 'Netzart',
  method: 'Methode',
  client: 'Client',
  q: 'Suche',
}

export interface EventFilterState {
  time: TimeRange
  outcome?: Outcome
  ip?: string
  country?: string
  asn?: string
  path?: string
  rule?: string
  session?: string
  type?: string
  /** D36: website id (contracts v0.5 `site`). */
  website?: string
  /** D36 amendment: breakdown rows link here with net class, method (OTHER) and UA class. */
  net?: string
  method?: string
  client?: string
  q?: string
}

const str = (v: LocationQuery[string]) => (Array.isArray(v) ? v[0] : v) ?? undefined

export function parseFilters(q: LocationQuery): EventFilterState {
  const time = str(q.time) as TimeRange | undefined
  const out: EventFilterState = { time: TIME_RANGES.some(t => t.value === time) ? time! : '24h' }
  for (const k of Object.keys(FIELD_MAP) as UrlField[]) {
    const v = str(q[k])?.trim()
    if (v) (out as unknown as Record<string, string>)[k] = v
  }
  if (out.outcome && !(out.outcome in OUTCOMES)) delete out.outcome
  if (out.country) out.country = out.country.toUpperCase()
  if (out.net && !(out.net in NET_CLASSES)) delete out.net
  if (out.method) out.method = out.method.toUpperCase()
  if (out.method && !/^[A-Z]{1,16}$/.test(out.method)) delete out.method
  if (out.client && !(out.client in UA_CLASSES)) delete out.client
  return out
}

/** API query for GET /events and /events/stream (without time for the stream). */
export function toApiQuery(f: EventFilterState, from?: string): EventQuery {
  const q: EventQuery = {}
  if (from) q.from = from
  if (f.outcome) q.outcome = f.outcome
  if (f.ip) q.ip = f.ip
  if (f.country) q.country = f.country
  if (f.asn && /^\d+$/.test(f.asn.replace(/^AS/i, ''))) q.asn = Number(f.asn.replace(/^AS/i, ''))
  if (f.path) q.path = f.path
  if (f.rule) q.rule = f.rule
  if (f.session) q.session = f.session
  if (f.type) q.type = f.type
  if (f.website) q.site = f.website
  if (f.net) q.net_class = f.net as EventQuery['net_class']
  if (f.method) q.method = f.method
  if (f.client) q.ua_class = f.client as EventQuery['ua_class']
  if (f.q) q.q = f.q
  return q
}

/** Methods of the method breakdown; every other method is OTHER ("Andere"). */
const BREAKDOWN_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT', 'TRACE'])

/**
 * Whether a live event fits the filters the stream cannot apply (net class, method). A UA class filter
 * needs the stored user agent, which a summary does not carry: live events are then left out and the
 * list shows what the server filtered.
 */
export function liveMatches(e: Pick<EventSummary, 'method' | 'geo'>, f: EventFilterState): boolean {
  if (f.client) return false
  if (f.net && e.geo?.net_class !== f.net) return false
  if (f.method === 'OTHER') return !!e.method && !BREAKDOWN_METHODS.has(e.method)
  if (f.method && e.method !== f.method) return false
  return true
}

export function chipsFor(f: EventFilterState): FilterChip[] {
  const chips: FilterChip[] = []
  for (const k of Object.keys(FIELD_MAP) as UrlField[]) {
    if (k === 'q') continue
    const v = f[k]
    if (!v) continue
    let shown = v
    if (k === 'outcome') shown = OUTCOMES[v as Outcome]?.label ?? v
    if (k === 'country') shown = `${countryName(v)} (${v})`
    if (k === 'type') shown = eventTypeLabel(v)
    if (k === 'asn') shown = `AS${v.replace(/^AS/i, '')}`
    if (k === 'net') shown = NET_CLASSES[v] ?? v
    if (k === 'method') shown = METHODS[v] ?? v
    if (k === 'client') shown = UA_CLASSES[v] ?? v
    chips.push({ key: k, label: FIELD_LABELS[k], value: shown })
  }
  return chips
}

/** Round to the minute so the query key stays stable between renders. */
function sinceIso(ms: number, now = Date.now()): string {
  return new Date(Math.floor((now - ms) / 60_000) * 60_000).toISOString().replace('.000Z', 'Z')
}

/**
 * site: a fixed website (its Ereignisse page, D68). It replaces the website filter of the URL and has no
 * chip of its own; without it the list covers every website.
 */
export function useEventFilters(site?: MaybeRefOrGetter<string>) {
  const route = useRoute()
  const router = useRouter()
  const fixedSite = computed(() => site === undefined ? null : toValue(site))
  const filters = computed(() => {
    const f = parseFilters(route.query)
    if (fixedSite.value !== null) f.website = fixedSite.value || undefined
    return f
  })
  const refreshedAt = ref(Date.now())
  // Recompute "since" only when the range changes or the user refreshes.
  const from = ref<string | undefined>()
  watch([() => filters.value.time, refreshedAt], () => {
    const r = TIME_RANGES.find(t => t.value === filters.value.time)!
    from.value = r.ms ? sinceIso(r.ms, refreshedAt.value) : undefined
  }, { immediate: true })

  const apiQuery = computed(() => toApiQuery(filters.value, from.value))
  // The stream has no net_class, method or ua_class filter (listEvents only): the live view filters these itself.
  const streamQuery = computed(() => {
    const { from: _f, net_class: _n, method: _m, ua_class: _u, ...rest } = apiQuery.value
    return rest
  })
  const chips = computed(() => chipsFor(filters.value).filter(c => fixedSite.value === null || c.key !== 'website'))

  function update(patch: Partial<Record<UrlField | 'time' | 'event' | 'live' | 'focus', string | undefined>>) {
    const query: LocationQueryRaw = { ...route.query }
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined || v === '') delete query[k]
      else query[k] = v
    }
    if (query.time === '24h') delete query.time
    void router.replace({ query })
  }

  function clear() {
    const keep: LocationQueryRaw = {}
    if (route.query.live) keep.live = route.query.live
    void router.replace({ query: keep })
  }

  function refresh() {
    refreshedAt.value = Date.now()
  }

  return { filters, apiQuery, streamQuery, chips, update, clear, refresh, from }
}
