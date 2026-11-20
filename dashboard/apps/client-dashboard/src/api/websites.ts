/**
 * Queries of the "websites" tag (contracts v0.5, D36): the website list and one website, the
 * Plausible-style overview (KPIs, series with partial points, annotations, Echtzeit, Letzte Alarme,
 * breakdowns with click-to-filter), incidents per website and the possible false positives.
 * Polling stays at 10 s or slower; the list is memory-only on the gateway and cheap.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { BreakdownDimension } from './monitoring'
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { computed, ref, toValue } from 'vue'
import { api, problemOf, statusOf } from './client'
import { isMonitoringOff, whileOn } from './monitoring'

type S = components['schemas']
export type WebsiteList = S['WebsiteList']
export type WebsiteSummary = S['WebsiteSummary']
export type WebsiteDetail = S['WebsiteDetail']
export type WebsiteStatus = S['WebsiteStatus']
export type WebsiteStatusReason = S['WebsiteStatusReason']
export type ServerHealth = S['ServerHealth']
export type WebsiteKpis = S['WebsiteKpis']
export type KpiSet = S['KpiSet']
export type KpiValue = S['KpiValue']
export type Annotation = S['Annotation']
export type AnnotationList = S['AnnotationList']
export type AlertItem = S['AlertItem']
export type AlertFeed = S['AlertFeed']
export type RuleCategory = S['RuleCategory']
export type IncidentPage = S['IncidentPage']
export type FalsePositiveHint = S['FalsePositiveHint']
export type SeriesResult = S['SeriesResult']

// ------------------------------------------------------------------ ranges

/** Time ranges of the website overview (URL `time`), D36 addendum. */
export type WebsiteRangeKey = 'echtzeit' | '6h' | '24h' | '48h' | '7d' | '14d'
export interface WebsiteRange {
  key: WebsiteRangeKey
  label: string
  seconds: number
  /** Explicit ring, or auto (7 and 14 days: 30 min points, merged by the gateway). */
  resolution: 'auto' | '10s' | '1m' | '10m'
  /** Expected seconds per point (the answer's step_s wins). */
  stepS: number
  refetchMs: number
}
export const WEBSITE_RANGES: Record<WebsiteRangeKey, WebsiteRange> = {
  'echtzeit': { key: 'echtzeit', label: 'Echtzeit', seconds: 30 * 60, resolution: '10s', stepS: 10, refetchMs: 10_000 },
  '6h': { key: '6h', label: '6 Std.', seconds: 6 * 3600, resolution: '1m', stepS: 60, refetchMs: 60_000 },
  '24h': { key: '24h', label: '24 Std.', seconds: 24 * 3600, resolution: '10m', stepS: 600, refetchMs: 120_000 },
  '48h': { key: '48h', label: '48 Std.', seconds: 48 * 3600, resolution: '10m', stepS: 600, refetchMs: 120_000 },
  '7d': { key: '7d', label: '7 Tage', seconds: 7 * 86400, resolution: 'auto', stepS: 1800, refetchMs: 300_000 },
  '14d': { key: '14d', label: '14 Tage', seconds: 14 * 86400, resolution: 'auto', stepS: 1800, refetchMs: 300_000 },
}
export const WEBSITE_RANGE_KEYS = Object.keys(WEBSITE_RANGES) as WebsiteRangeKey[]
export const DEFAULT_RANGE: WebsiteRangeKey = '24h'
export function websiteRangeOf(v: unknown): WebsiteRange {
  return typeof v === 'string' && v in WEBSITE_RANGES ? WEBSITE_RANGES[v as WebsiteRangeKey] : WEBSITE_RANGES[DEFAULT_RANGE]
}
/**
 * How far back the request ring answers (D66, RequestPage.keep_hours): combined filters, filters on
 * visitors or latency and the ip and user_agent breakdowns work for ranges within it. 48 h until the probe
 * answers; by default 14 days.
 */
export const ringWindowS = ref(48 * 3600)
/** Start of the oldest single request kept (ms, RequestPage.kept_from); null when unknown. */
export const ringKeptFrom = ref<number | null>(null)
/** Whether the request ring answers a range. */
export function ringCovers(range: WebsiteRangeKey): boolean {
  return WEBSITE_RANGES[range].seconds <= ringWindowS.value
}
/** The longest range the request ring answers. */
export function ringRange(): WebsiteRangeKey {
  return [...WEBSITE_RANGE_KEYS].reverse().find(ringCovers) ?? '6h'
}

const isoS = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
/** A ring or auto (queryMetricSeries accepts auto; the ring enum Resolution does not contain it). */
export type SeriesResolution = WebsiteRange['resolution']
/**
 * The resolution a series asks for. Without a filter, or when the request ring answers it, the range's own
 * resolution. A filter without the ring is answered from the per-website lists of the 10 min ring, so up
 * to 48 h it asks for 10m (no 409 per click). 7 and 14 days keep auto: an explicit 10m there is 1008 or
 * 2016 points and gets 400 too_many_points (Messung 2026-10-29 abend 4.4), auto reads the same ring merged.
 */
export function seriesResolutionFor(range: WebsiteRangeKey, filtered: boolean, ringAnswers: boolean): SeriesResolution {
  const own = WEBSITE_RANGES[range].resolution
  if (!filtered || ringAnswers) return own
  return WEBSITE_RANGES[range].seconds <= 48 * 3600 ? '10m' : 'auto'
}

/** [from, to) of a range ending now; the start rounded to the step so query results line up. */
export function windowOf(r: WebsiteRange, nowMs = Date.now()): { from: string, to: string } {
  const step = r.stepS * 1000
  const from = Math.floor((nowMs - r.seconds * 1000) / step) * step + step
  return { from: isoS(from), to: isoS(nowMs) }
}

// ------------------------------------------------------------------ errors

/** 409 filter_unavailable: the combination is only answered inside the 48 h request ring. */
export function isFilterUnavailable(err: unknown): boolean {
  return problemOf(err)?.code === 'filter_unavailable'
}
const noRetry = (count: number, err: unknown) => !isMonitoringOff(err) && !isFilterUnavailable(err) && (problemOf(err)?.status ?? 500) >= 500 && count < 2

export const websiteKeys = {
  list: ['websites'] as const,
  one: (id: string) => ['websites', id] as const,
  kpis: (id: string, range: string, filters: string[]) => ['websites', id, 'kpis', range, filters] as const,
  series: (id: string, range: string, metrics: string[], filters: string[]) => ['websites', id, 'series', range, metrics, filters] as const,
  annotations: (id: string, range: string) => ['websites', id, 'annotations', range] as const,
  realtime: (id: string) => ['websites', id, 'realtime'] as const,
  alerts: (id: string, range: string, filter: string | undefined) => ['websites', id, 'alerts', range, filter ?? ''] as const,
  breakdown: (id: string, by: string, range: string, filters: string[], top: number) => ['websites', id, 'breakdown', by, range, filters, top] as const,
  incidents: (id: string, days: number) => ['incidents', id, days] as const,
  hints: (id: string) => ['websites', id, 'fp-hints'] as const,
  botClients: (id: string) => ['websites', id, 'bot-clients'] as const,
}

// ------------------------------------------------------------------ list and one

export function useWebsites(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: websiteKeys.list,
    queryFn: () => unwrap(api.GET('/websites')),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
    enabled: computed(() => toValue(enabled)),
  })
}

export function useWebsite(id: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => websiteKeys.one(toValue(id))),
    queryFn: () => unwrap(api.GET('/websites/{website}', { params: { path: { website: toValue(id) } } })),
    refetchInterval: 30_000,
    placeholderData: keepPreviousData,
    retry: noRetry,
    enabled: computed(() => !!toValue(id)),
  })
}

// ------------------------------------------------------------------ overview

export interface OverviewQuery {
  site: string
  range: WebsiteRangeKey
  filters: string[]
}

export function useWebsiteKpis(q: MaybeRefOrGetter<OverviewQuery>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return websiteKeys.kpis(v.site, v.range, v.filters) }),
    queryFn: () => {
      const v = toValue(q)
      const w = windowOf(WEBSITE_RANGES[v.range])
      return unwrap(api.GET('/websites/{website}/kpis', { params: { path: { website: v.site }, query: { ...w, ...(v.filters.length ? { filter: v.filters } : {}) } } }))
    },
    refetchInterval: computed(() => Math.max(30_000, WEBSITE_RANGES[toValue(q).range].refetchMs)),
    placeholderData: keepPreviousData,
    retry: noRetry,
    enabled: whileOn(() => !!toValue(q).site && toValue(enabled)),
  })
}

/** Series of one website (queryMetricSeries with site and filter); the gateway merges points beyond 1000. */
export function useWebsiteSeries(q: MaybeRefOrGetter<OverviewQuery & { metrics: string[], resolution?: SeriesResolution }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return [...websiteKeys.series(v.site, v.range, v.metrics, v.filters), v.resolution ?? ''] as const }),
    queryFn: () => {
      const v = toValue(q)
      const r = WEBSITE_RANGES[v.range]
      return unwrap(api.GET('/monitoring/series', {
        params: { query: { metric: v.metrics, ...windowOf(r), resolution: v.resolution ?? r.resolution, site: v.site, ...(v.filters.length ? { filter: v.filters } : {}) } },
      }))
    },
    refetchInterval: computed(() => WEBSITE_RANGES[toValue(q).range].refetchMs),
    placeholderData: keepPreviousData,
    retry: noRetry,
    enabled: whileOn(() => !!toValue(q).site && toValue(q).metrics.length > 0 && toValue(enabled)),
  })
}

export function useAnnotations(q: MaybeRefOrGetter<{ site: string, range: WebsiteRangeKey }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return websiteKeys.annotations(v.site, v.range) }),
    queryFn: () => {
      const v = toValue(q)
      return unwrap(api.GET('/websites/{website}/annotations', { params: { path: { website: v.site }, query: windowOf(WEBSITE_RANGES[v.range]) } }))
    },
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
    retry: noRetry,
    enabled: computed(() => !!toValue(q).site && toValue(enabled)),
  })
}

/** "≈ N Besucher · letzte 5 Min.": visitors of the last 5 minutes, polled every 30 s as the API suggests. */
export function useRealtime(site: MaybeRefOrGetter<string>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => websiteKeys.realtime(toValue(site))),
    queryFn: () => unwrap(api.GET('/websites/{website}/realtime', { params: { path: { website: toValue(site) } } })),
    refetchInterval: 30_000,
    retry: noRetry,
    enabled: whileOn(() => !!toValue(site) && toValue(enabled)),
  })
}

/**
 * "Bot-Clients" (D36 amendment): distinct clients of bots and tools in the newest finished 10-minute
 * bucket of this website (MetricBucket sites[].clients.bots). null when the gateway does not send it
 * (buckets written before the amendment) or the website has no numbers.
 */
export function useBotClients(site: MaybeRefOrGetter<string>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => websiteKeys.botClients(toValue(site))),
    queryFn: async () => {
      const page = await unwrap(api.GET('/monitoring/buckets', { params: { query: { resolution: '10m', from: isoS(Date.now() - 30 * 60_000), limit: 3 } } }))
      const s = toValue(site)
      for (const b of [...page.items].reverse()) {
        const own = b.sites?.find(x => x.site === s)
        const n = own?.clients?.bots
        if (typeof n === 'number') return { bots: n, t: b.t }
      }
      return null
    },
    refetchInterval: 300_000,
    retry: noRetry,
    enabled: whileOn(() => !!toValue(site) && toValue(enabled)),
  })
}

/** Dimensions listAlerts accepts as its one filter. */
export const ALERT_FILTER_DIMENSIONS = ['path', 'country', 'net_class', 'asn', 'rule', 'bot_category'] as const

/** "Letzte Alarme": newest first, at most 50, polled every 10 s (live enough without a second stream). */
export function useAlerts(q: MaybeRefOrGetter<{ site: string, range: WebsiteRangeKey, filter?: string }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return websiteKeys.alerts(v.site, v.range, v.filter) }),
    queryFn: () => {
      const v = toValue(q)
      return unwrap(api.GET('/websites/{website}/alerts', {
        params: { path: { website: v.site }, query: { ...windowOf(WEBSITE_RANGES[v.range]), limit: 50, ...(v.filter ? { filter: [v.filter] } : {}) } },
      }))
    },
    refetchInterval: 10_000,
    placeholderData: keepPreviousData,
    retry: noRetry,
    enabled: computed(() => !!toValue(q).site && toValue(enabled)),
  })
}

export interface WebsiteBreakdownQuery extends OverviewQuery {
  by: BreakdownDimension
  top?: number
}

export function useWebsiteBreakdown(q: MaybeRefOrGetter<WebsiteBreakdownQuery>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return websiteKeys.breakdown(v.site, v.by, v.range, v.filters, v.top ?? 8) }),
    queryFn: () => {
      const v = toValue(q)
      return unwrap(api.GET('/monitoring/traffic/breakdown', {
        params: { query: { by: v.by, ...windowOf(WEBSITE_RANGES[v.range]), site: v.site, top: v.top ?? 8, ...(v.filters.length ? { filter: v.filters } : {}) } },
      }))
    },
    refetchInterval: computed(() => Math.max(60_000, WEBSITE_RANGES[toValue(q).range].refetchMs)),
    placeholderData: keepPreviousData,
    retry: noRetry,
    enabled: whileOn(() => !!toValue(q).site && toValue(enabled)),
  })
}

/**
 * Whether the request ring (MVP-22) runs on this gateway. Without it the gateway answers one filter from
 * the per-website lists of the rings (KPIs requests, stopped, would_block and their series), never a
 * breakdown under a filter or two filters at once (409). GET /requests answers 409 requests_off when the
 * ring is off. One probe per session, only while monitoring runs; until it
 * answers, assume no ring.
 */
export function useRequestRing() {
  return useQuery({
    // The ring is part of monitoring: with monitoring off there is nothing to ask.
    enabled: whileOn(true),
    queryKey: ['requests', 'ring'] as const,
    queryFn: async () => {
      const now = Date.now()
      try {
        const page = await unwrap(api.GET('/requests', { params: { query: { from: isoS(now - 60_000), to: isoS(now) } } }))
        ringWindowS.value = (page.keep_hours ?? 48) * 3600
        ringKeptFrom.value = page.kept_from ? Date.parse(page.kept_from) : null
        return true
      }
      catch (e) {
        if (problemOf(e)?.code === 'requests_off' || statusOf(e) === 409) return false
        throw e
      }
    },
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
    retry: false,
    refetchOnWindowFocus: false,
  })
}

// ------------------------------------------------------------------ attacks and exceptions

/** listIncidents for one website (or all with ''), the last `days` days (at most 31). */
export function useIncidents(site: MaybeRefOrGetter<string>, days: MaybeRefOrGetter<number> = 7) {
  return useQuery({
    queryKey: computed(() => websiteKeys.incidents(toValue(site), toValue(days))),
    queryFn: () => {
      const now = Date.now()
      const s = toValue(site)
      return unwrap(api.GET('/incidents', {
        params: { query: { from: isoS(now - toValue(days) * 86400_000), to: isoS(now), limit: 100, ...(s ? { site: s } : {}) } },
      }))
    },
    refetchInterval: 60_000,
    placeholderData: keepPreviousData,
  })
}

/** "Möglicher Fehlalarm" (MVP-22 request ring): rule and page pairs with an exception scoped to the website. */
export function useFalsePositiveHints(site: MaybeRefOrGetter<string>, enabled: MaybeRefOrGetter<boolean> = true) {
  // The hints come from the request ring: without it the API answers 409 (D36 re-measurement D).
  const ring = useRequestRing()
  return useQuery({
    queryKey: computed(() => websiteKeys.hints(toValue(site))),
    queryFn: () => {
      const s = toValue(site)
      return unwrap(api.GET('/requests/alerts/hints', { params: { query: s ? { site: s } : {} } }))
    },
    refetchInterval: 300_000,
    retry: false,
    enabled: computed(() => toValue(enabled) && ring.data.value === true),
  })
}
