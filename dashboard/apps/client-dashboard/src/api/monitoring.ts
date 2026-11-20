/**
 * Queries of the "monitoring" tag (contracts v0.4, MVP-21, D33): what the server does right now,
 * time series from the three rings, traffic breakdowns, the host snapshot and the live tick stream.
 * Nothing here polls faster than every 10 s; the live numbers come from the SSE stream.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useQuery } from '@tanstack/vue-query'
import { computed, ref, toValue } from 'vue'
import { api, problemOf } from './client'

type S = components['schemas']
export type MonitoringNow = S['MonitoringNow']
export type TrafficNow = S['TrafficNow']
export type ServerNow = S['ServerNow']
export type HealthHint = S['HealthHint']
export type HealthHintCode = S['HealthHintCode']
export type LiveTick = S['LiveTick']
export type TrafficCounters = S['TrafficCounters']
export type SeriesResult = S['SeriesResult']
export type MetricSeries = S['MetricSeries']
export type Resolution = S['Resolution']
export type TrafficBreakdown = S['TrafficBreakdown']
export type BreakdownDimension = S['BreakdownDimension']
export type TopEntry = S['TopEntry']
export type ServerSnapshot = S['ServerSnapshot']
export type MetricCatalogue = S['MetricCatalogue']
export type SiteNow = S['SiteNow']

/** Time ranges of the Traffic and Server pages (kept in the URL as `time`). */
export type RangeKey = '1h' | '6h' | '48h' | '14d'
export interface RangeDef {
  key: RangeKey
  label: string
  /** Length in seconds. */
  seconds: number
  /** The ring the charts read (explicit, so every range yields at most 1000 points per request). */
  resolution: Resolution
  stepS: number
  /** How often the charts refresh (never faster than 10 s). */
  refetchMs: number
}
export const RANGES: Record<RangeKey, RangeDef> = {
  '1h': { key: '1h', label: '1 Stunde', seconds: 3600, resolution: '10s', stepS: 10, refetchMs: 10_000 },
  '6h': { key: '6h', label: '6 Stunden', seconds: 6 * 3600, resolution: '1m', stepS: 60, refetchMs: 60_000 },
  '48h': { key: '48h', label: '48 Stunden', seconds: 48 * 3600, resolution: '10m', stepS: 600, refetchMs: 120_000 },
  '14d': { key: '14d', label: '14 Tage', seconds: 14 * 86400, resolution: '10m', stepS: 600, refetchMs: 300_000 },
}
export const RANGE_KEYS = Object.keys(RANGES) as RangeKey[]
export function rangeOf(v: unknown): RangeDef {
  return typeof v === 'string' && v in RANGES ? RANGES[v as RangeKey] : RANGES['6h']
}

/** The API answers 409 monitoring_off when monitoring.enabled is false. */
export function isMonitoringOff(err: unknown): boolean {
  return problemOf(err)?.code === 'monitoring_off'
}

/**
 * Set as soon as any monitoring request answers 409 monitoring_off. Then every monitoring query stops
 * polling and the pages show the "ausgeschaltet" state; a reload of the page asks again (MVP-21 measurement:
 * the pages kept polling every 10-30 s and collected 409s).
 */
export const monitoringOff = ref(false)

/** Remembers monitoring_off (or its end) from the answer of a monitoring request. */
function watchOff<T>(p: Promise<T>): Promise<T> {
  return p.then((v) => {
    monitoringOff.value = false
    return v
  }, (err: unknown) => {
    if (isMonitoringOff(err)) monitoringOff.value = true
    throw err
  })
}

/**
 * Whether monitoring runs, known once per session (D36 fix round 2, re-measurement D: with monitoring off
 * every overview load sent 12 requests that all answered 409, because they started before the first 409
 * came back). One probe (GET /monitoring/now) answers it; every monitoring and website-number query waits
 * for it and is only sent while monitoring is on. A later 409 monitoring_off switches it off again.
 */
export const monitoringState = ref<'unknown' | 'on' | 'off'>('unknown')
let probe: Promise<void> | null = null
export function probeMonitoring(): void {
  if (probe) return
  probe = unwrap(api.GET('/monitoring/now', { params: { query: {} } })).then(() => {
    monitoringState.value = 'on'
    monitoringOff.value = false
  }, (err: unknown) => {
    const off = isMonitoringOff(err)
    monitoringState.value = off ? 'off' : 'on' // another error: the queries try and show it
    monitoringOff.value = off
    if (!off) probe = null
  })
}
/** Tests: forget the probe. */
export function resetMonitoringProbe(state: 'unknown' | 'on' | 'off' = 'unknown'): void {
  probe = state === 'unknown' ? null : Promise.resolve()
  monitoringState.value = state
  monitoringOff.value = state === 'off'
}
/** True once the probe said monitoring runs (and no later answer said off). */
export const monitoringOn = computed(() => monitoringState.value === 'on' && !monitoringOff.value)

/** Poll interval that stops while monitoring is off. */
const pollEvery = (ms: MaybeRefOrGetter<number>) => computed(() => monitoringOff.value ? false as const : toValue(ms))
/** A query runs only once monitoring is known to be on. */
export function whileOn(enabled: MaybeRefOrGetter<boolean>) {
  probeMonitoring()
  return computed(() => toValue(enabled) && monitoringOn.value)
}

export const monitoringKeys = {
  now: (site: string) => ['monitoring', 'now', site] as const,
  series: (q: SeriesQuery) => ['monitoring', 'series', q] as const,
  breakdown: (q: BreakdownQuery) => ['monitoring', 'breakdown', q] as const,
  server: ['monitoring', 'server'] as const,
}

const noRetryWhenOff = (count: number, err: unknown) => !isMonitoringOff(err) && count < 2

export function useMonitoringNow(site: MaybeRefOrGetter<string | undefined>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => monitoringKeys.now(toValue(site) ?? '')),
    queryFn: () => {
      const s = toValue(site)
      return watchOff(unwrap(api.GET('/monitoring/now', { params: { query: s ? { site: s } : {} } })))
    },
    refetchInterval: pollEvery(30_000),
    retry: noRetryWhenOff,
    placeholderData: keepPreviousData,
    enabled: whileOn(enabled),
  })
}

export function useServerSnapshot(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: monitoringKeys.server,
    queryFn: () => watchOff(unwrap(api.GET('/monitoring/server'))),
    refetchInterval: pollEvery(10_000),
    retry: noRetryWhenOff,
    enabled: whileOn(enabled),
  })
}

// ------------------------------------------------------------------ series

export interface SeriesQuery {
  /** `<metric id>[:<stat>]`, at most 16. */
  metrics: string[]
  range: RangeKey
  site?: string
  object?: string
}

/** One merged result over the whole range (several requests when it has more than 1000 steps). */
export interface MergedSeries {
  from: number
  stepS: number
  points: number
  series: MetricSeries[]
  restarts: number[]
}

/** Key of a series in a result: metric, stat and object. */
export const seriesKey = (s: Pick<MetricSeries, 'metric' | 'stat' | 'object'>) => `${s.metric}:${s.stat}${s.object ? `@${s.object}` : ''}`

const MAX_POINTS = 1000

/** Fetch a range in chunks of at most 1000 steps and join them. */
export async function fetchSeries(q: SeriesQuery, nowMs = Date.now()): Promise<MergedSeries> {
  const r = RANGES[q.range]
  const step = r.stepS * 1000
  const from = Math.floor((nowMs - r.seconds * 1000) / step) * step + step
  const to = nowMs
  const total = Math.max(1, Math.ceil((to - from) / step))
  const chunks: [number, number][] = []
  for (let a = from; a < to; a += MAX_POINTS * step) chunks.push([a, Math.min(to, a + MAX_POINTS * step)])
  const parts = await Promise.all(chunks.map(([a, b]) => unwrap(api.GET('/monitoring/series', {
    params: {
      query: {
        metric: q.metrics,
        from: new Date(a).toISOString().replace(/\.\d{3}Z$/, 'Z'),
        to: new Date(b).toISOString().replace(/\.\d{3}Z$/, 'Z'),
        resolution: r.resolution,
        ...(q.site ? { site: q.site } : {}),
        ...(q.object ? { object: q.object } : {}),
      },
    },
  }))))
  const byKey = new Map<string, MetricSeries>()
  const restarts: number[] = []
  parts.forEach((p, k) => {
    const want = Math.min(MAX_POINTS, Math.ceil((chunks[k]![1] - chunks[k]![0]) / step))
    for (const s of p.series) {
      const key = seriesKey(s)
      const prev = byKey.get(key)
      const vals = s.values.slice(0, want)
      while (vals.length < want) vals.push(null)
      if (!prev) {
        // A series first seen in a later chunk gets gaps for the chunks before it.
        const lead: (number | null)[] = Array.from({ length: k * MAX_POINTS }, () => null)
        byKey.set(key, { ...s, values: [...lead, ...vals] })
      }
      else {
        prev.values.push(...vals)
      }
    }
    for (const t of p.restarts) restarts.push(Date.parse(t))
  })
  const series = [...byKey.values()].map(s => ({ ...s, values: s.values.slice(0, total) }))
  return { from, stepS: r.stepS, points: total, series, restarts: [...new Set(restarts)].sort((a, b) => a - b) }
}

export function useMetricSeries(q: MaybeRefOrGetter<SeriesQuery>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => monitoringKeys.series(toValue(q))),
    queryFn: () => watchOff(fetchSeries(toValue(q))),
    refetchInterval: pollEvery(() => RANGES[toValue(q).range].refetchMs),
    retry: noRetryWhenOff,
    placeholderData: keepPreviousData,
    enabled: whileOn(() => toValue(enabled) && toValue(q).metrics.length > 0),
  })
}

/** Values of one series by metric (and stat/object) from a merged result. */
export function valuesOf(r: MergedSeries | undefined, metric: string, stat?: string, object?: string): (number | null)[] {
  if (!r) return []
  const s = r.series.find(x => x.metric === metric && (!stat || x.stat === stat) && (object === undefined || x.object === object))
  return s ? s.values : Array.from({ length: r.points }, () => null)
}

// ------------------------------------------------------------------ breakdown

export interface BreakdownQuery {
  by: BreakdownDimension
  range: RangeKey
  site?: string
  top?: number
}

export function useBreakdown(q: MaybeRefOrGetter<BreakdownQuery>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => monitoringKeys.breakdown(toValue(q))),
    queryFn: () => {
      const v = toValue(q)
      const r = RANGES[v.range]
      const now = Date.now()
      return watchOff(unwrap(api.GET('/monitoring/traffic/breakdown', {
        params: {
          query: {
            by: v.by,
            from: new Date(now - r.seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
            to: new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z'),
            top: v.top ?? 10,
            ...(v.site ? { site: v.site } : {}),
          },
        },
      })))
    },
    refetchInterval: pollEvery(() => Math.max(60_000, RANGES[toValue(q).range].refetchMs)),
    retry: noRetryWhenOff,
    placeholderData: keepPreviousData,
    enabled: whileOn(enabled),
  })
}
