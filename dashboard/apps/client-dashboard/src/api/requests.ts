/**
 * Queries of the "requests" tag (contracts v0.5, MVP-22, D35): single requests from the 48 h request ring
 * ("Anfragen"), the Kontext of an event, the bot overview and the alert rates per rule and per page. The
 * ring answers one query at a time per gateway (429 rate_limited), so nothing here polls faster than every
 * 60 s and the list loads only on demand.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components } from './generated/schema'
import type { WebsiteRangeKey } from './websites'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, problemOf, statusOf } from './client'
import { whileOn } from './monitoring'
import { ringCovers, ringRange, WEBSITE_RANGES, windowOf } from './websites'

type S = components['schemas']
export type RequestRecord = S['RequestRecord']
export type RequestPage = S['RequestPage']
export type RequestOutcome = S['RequestOutcome']
export type RequestContext = S['RequestContext']
export type SiteStripPoint = S['SiteStripPoint']
export type VisitorPattern = S['VisitorPattern']
export type BotOverview = S['BotOverview']
export type BotVerification = S['BotVerification']
export type BotCategory = S['BotCategory']
export type RuleAlerts = S['RuleAlerts']
export type RuleAlert = S['RuleAlert']
export type PageAlerts = S['PageAlerts']
export type PageAlert = S['PageAlert']
export type GeoDb = NonNullable<S['Overview']['geo_db']>

const isoS = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')

/** 409 requests_off: the request ring is switched off. */
export function isRequestsOff(err: unknown): boolean {
  return problemOf(err)?.code === 'requests_off'
}
/** 429 rate_limited: another ring query is running on this gateway. */
export function isRingBusy(err: unknown): boolean {
  return problemOf(err)?.code === 'rate_limited' || statusOf(err) === 429
}
const retry = (count: number, err: unknown) => !isRequestsOff(err) && statusOf(err) !== 400 && statusOf(err) !== 404 && statusOf(err) !== 409 && count < 2
const retryDelay = (attempt: number, err: unknown) => isRingBusy(err) ? 2000 * (attempt + 1) : Math.min(1000 * 2 ** attempt, 8000)

export const requestKeys = {
  list: (q: object) => ['requests', 'list', q] as const,
  context: (id: string) => ['requests', 'context', id] as const,
  bots: (site: string, range: string) => ['requests', 'bots', site, range] as const,
  rules: (site: string, range: string, top: number) => ['requests', 'rules', site, range, top] as const,
  pages: (site: string, range: string, top: number) => ['requests', 'pages', site, range, top] as const,
}

// ------------------------------------------------------------------ Anfragen

/** Filters of queryRequests: exact values, no free text. */
export interface RequestFilters {
  path?: string
  rule?: string
  outcome?: RequestOutcome
  status_class?: '1xx' | '2xx' | '3xx' | '4xx' | '5xx'
  country?: string
  bot_category?: BotCategory
  bot?: string
  verification?: BotVerification
  visitor?: string
  ip?: string
  user_agent?: string
}

function listQuery(q: { site: string, from: string, to: string, filters: RequestFilters }) {
  const f = Object.fromEntries(Object.entries(q.filters).filter(([, v]) => v !== undefined && v !== '')) as RequestFilters
  return { from: q.from, to: q.to, ...(q.site ? { site: q.site } : {}), ...f }
}

/** [from, to) of the list: `seconds` long, ending `endHoursAgo` hours before now (inside the 48 h ring). */
export function listWindow(seconds: number, endHoursAgo: number, nowMs = Date.now()): { from: string, to: string } {
  // Whole minutes, so the query key stays stable while the page is open; the running minute counts.
  const to = Math.ceil((nowMs - endHoursAgo * 3600_000) / 60_000) * 60_000
  return { from: isoS(to - seconds * 1000), to: isoS(to) }
}

/** queryRequests with cursor paging (DataTable cursor mode: "N geladen · Mehr laden"). */
export function useRequestList(q: MaybeRefOrGetter<{ site: string, from: string, to: string, filters: RequestFilters }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useInfiniteQuery({
    queryKey: computed(() => requestKeys.list(listQuery(toValue(q)))),
    queryFn: ({ pageParam }) => unwrap(api.GET('/requests', { params: { query: { ...listQuery(toValue(q)), limit: 100, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: RequestPage) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
    retry,
    retryDelay,
    enabled: whileOn(() => toValue(enabled)),
  })
}

// ------------------------------------------------------------------ Kontext

export function useRequestContext(eventId: MaybeRefOrGetter<string | null>) {
  return useQuery({
    queryKey: computed(() => requestKeys.context(toValue(eventId) ?? '')),
    queryFn: () => unwrap(api.GET('/requests/context/{event_id}', { params: { path: { event_id: toValue(eventId)! } } })),
    // The window is fixed (event ± 5 min); it only changes while the event is younger than 5 minutes.
    staleTime: 60_000,
    retry,
    retryDelay,
    enabled: computed(() => !!toValue(eventId)),
  })
}

// ------------------------------------------------------------------ bots and alert rates

/** Ranges longer than the ring (D66: RequestPage.keep_hours) are clamped to its longest range for ring-only views. */
export function ringWindow(range: WebsiteRangeKey, nowMs = Date.now()): { from: string, to: string, clamped: boolean } {
  const r = WEBSITE_RANGES[range]
  const clamped = !ringCovers(range)
  const w = windowOf(clamped ? WEBSITE_RANGES[ringRange()] : r, nowMs)
  return { ...w, clamped }
}

export function useBotOverview(q: MaybeRefOrGetter<{ site: string, range: WebsiteRangeKey }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return requestKeys.bots(v.site, v.range) }),
    queryFn: () => {
      const v = toValue(q)
      const { from, to } = ringWindow(v.range)
      return unwrap(api.GET('/requests/bots', { params: { query: { from, to, ...(v.site ? { site: v.site } : {}) } } }))
    },
    refetchInterval: 120_000,
    placeholderData: keepPreviousData,
    retry,
    retryDelay,
    enabled: whileOn(() => toValue(enabled)),
  })
}

/** getRuleAlerts: detections per rule over the whole range (rings), pages and clients inside the ring. */
export function useRuleAlerts(q: MaybeRefOrGetter<{ site: string, range: WebsiteRangeKey, top?: number }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return requestKeys.rules(v.site, v.range, v.top ?? 20) }),
    queryFn: () => {
      const v = toValue(q)
      return unwrap(api.GET('/requests/alerts/rules', { params: { query: { ...windowOf(WEBSITE_RANGES[v.range]), top: v.top ?? 20, ...(v.site ? { site: v.site } : {}) } } }))
    },
    refetchInterval: 120_000,
    placeholderData: keepPreviousData,
    retry,
    retryDelay,
    enabled: whileOn(() => toValue(enabled)),
  })
}

/** getPageAlerts: alert rate next to traffic per path template, status and p95 inside the ring. */
export function usePageAlerts(q: MaybeRefOrGetter<{ site: string, range: WebsiteRangeKey, top?: number }>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => { const v = toValue(q); return requestKeys.pages(v.site, v.range, v.top ?? 20) }),
    queryFn: () => {
      const v = toValue(q)
      return unwrap(api.GET('/requests/alerts/pages', { params: { query: { ...windowOf(WEBSITE_RANGES[v.range]), top: v.top ?? 20, ...(v.site ? { site: v.site } : {}) } } }))
    },
    refetchInterval: 120_000,
    placeholderData: keepPreviousData,
    retry,
    retryDelay,
    enabled: whileOn(() => toValue(enabled)),
  })
}
