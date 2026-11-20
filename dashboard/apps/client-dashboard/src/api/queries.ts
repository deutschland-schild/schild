import type { MaybeRefOrGetter } from 'vue'
import type { paths } from './generated/schema'
import type {
  AllowlistEntry,
  AllowlistInput,
  AllowlistPage,
  EventPage,
  Incident,
  Settings,
  SettingsPatch,
  Ttl,
  UnblockRequest,
} from './types'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf } from './client'

/** Nothing polls faster than every 10 s (MVP-09). */
export const REFRESH_MS = 30_000

export type EventQuery = NonNullable<paths['/events']['get']['parameters']['query']>

export const keys = {
  overview: ['overview'] as const,
  events: (q: EventQuery) => ['events', q] as const,
  event: (id: string) => ['event', id] as const,
  incident: (n: string) => ['incident', n] as const,
  allowlist: ['allowlist'] as const,
  myip: ['myip'] as const,
  settings: ['settings'] as const,
  privacy: (ip: string) => ['privacy', ip] as const,
}

export function useOverview(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: keys.overview,
    queryFn: () => unwrap(api.GET('/overview')),
    refetchInterval: REFRESH_MS,
    enabled: computed(() => toValue(enabled)),
  })
}

const PAGE = 100

export function useEvents(query: MaybeRefOrGetter<EventQuery>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useInfiniteQuery({
    queryKey: computed(() => keys.events(toValue(query))),
    queryFn: ({ pageParam }) => unwrap(api.GET('/events', { params: { query: { ...toValue(query), limit: PAGE, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: EventPage) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
    enabled: computed(() => toValue(enabled)),
  })
}

export function useEvent(id: MaybeRefOrGetter<string | null | undefined>) {
  return useQuery({
    queryKey: computed(() => keys.event(toValue(id) ?? '')),
    queryFn: () => unwrap(api.GET('/events/{id}', { params: { path: { id: toValue(id)! } } })),
    enabled: computed(() => !!toValue(id)),
  })
}

export function useIncident(n: MaybeRefOrGetter<string | null | undefined>) {
  return useQuery({
    queryKey: computed(() => keys.incident(toValue(n) ?? '')),
    queryFn: () => unwrap(api.GET('/incidents/{incident}', { params: { path: { incident: toValue(n)! } } })),
    enabled: computed(() => !!toValue(n)),
    retry: false,
  })
}

export function useAllowlist() {
  return useInfiniteQuery({
    queryKey: keys.allowlist,
    queryFn: ({ pageParam }) => unwrap(api.GET('/allowlist', { params: { query: { limit: 500, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: AllowlistPage) => last.next_cursor ?? undefined,
  })
}

export function useMyIp(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({ queryKey: keys.myip, queryFn: () => unwrap(api.GET('/allowlist/mine')), enabled: computed(() => toValue(enabled)) })
}

export function useSettings(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({ queryKey: keys.settings, queryFn: () => unwrap(api.GET('/settings')), enabled: computed(() => toValue(enabled)) })
}

export function usePrivacySearch(ip: MaybeRefOrGetter<string | null>) {
  return useQuery({
    queryKey: computed(() => keys.privacy(toValue(ip) ?? '')),
    queryFn: () => unwrap(api.GET('/privacy/search', { params: { query: { ip: toValue(ip)! } } })),
    enabled: computed(() => !!toValue(ip)),
    retry: false,
  })
}

// ---------------------------------------------------------------- mutations

/** "Meine IP freischalten": adds the caller's IP. */
export function useAllowMyIp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { label: string, ttl: Ttl }) => unwrap(api.POST('/allowlist/mine', { params: { header: csrf() }, body })),
    onSuccess: (entry: AllowlistEntry) => {
      qc.setQueryData(keys.myip, (old: { ip: string, attribution: 'tcp_peer' | 'trusted_proxy' | 'localhost', allowlisted: boolean } | undefined) => old ? { ...old, allowlisted: true } : old)
      addToAllowlistCache(qc, entry)
      void qc.invalidateQueries({ queryKey: keys.allowlist })
    },
  })
}

export function useAddAllowlist() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: AllowlistInput) => unwrap(api.POST('/allowlist', { params: { header: csrf() }, body })),
    onSuccess: (entry: AllowlistEntry) => {
      addToAllowlistCache(qc, entry)
      void qc.invalidateQueries({ queryKey: keys.allowlist })
      void qc.invalidateQueries({ queryKey: keys.myip })
    },
  })
}

type QC = ReturnType<typeof useQueryClient>
interface InfiniteData<T> { pages: T[], pageParams: unknown[] }

function addToAllowlistCache(qc: QC, entry: AllowlistEntry) {
  qc.setQueryData<InfiniteData<AllowlistPage>>(keys.allowlist, (old) => {
    if (!old?.pages.length) return old
    const [first, ...rest] = old.pages
    if (first!.items.some(i => i.id === entry.id)) return old
    return { ...old, pages: [{ ...first!, items: [entry, ...first!.items] }, ...rest] }
  })
}

/** Remove an allowlist entry from the cache (optimistic) and return a restore function. */
export function hideAllowlistEntry(qc: QC, id: string): () => void {
  const prev = qc.getQueryData<InfiniteData<AllowlistPage>>(keys.allowlist)
  qc.setQueryData<InfiniteData<AllowlistPage>>(keys.allowlist, old => old && ({
    ...old,
    pages: old.pages.map(p => ({ ...p, items: p.items.filter(i => i.id !== id) })),
  }))
  return () => qc.setQueryData(keys.allowlist, prev)
}

export async function deleteAllowlistEntry(id: string) {
  const res = await api.DELETE('/allowlist/{id}', { params: { header: csrf(), path: { id } } })
  if (!res.response.ok && res.response.status !== 404) await unwrap(Promise.resolve(res))
}

export function useUnblock() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ incident, body }: { incident: string, body: UnblockRequest }) =>
      unwrap(api.POST('/incidents/{incident}/unblock', { params: { header: csrf(), path: { incident } }, body })),
    onSuccess: (inc: Incident) => {
      qc.setQueryData(keys.incident(inc.incident), inc)
      void qc.invalidateQueries({ queryKey: ['events'] })
      void qc.invalidateQueries({ queryKey: ['event'] })
      void qc.invalidateQueries({ queryKey: keys.allowlist })
      void qc.invalidateQueries({ queryKey: keys.overview })
    },
  })
}

export function useUpdateSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (patch: SettingsPatch) => unwrap(api.PATCH('/settings', { params: { header: csrf() }, body: patch })),
    onSuccess: (s: Settings) => {
      qc.setQueryData(keys.settings, s)
      void qc.invalidateQueries({ queryKey: keys.overview })
    },
  })
}
