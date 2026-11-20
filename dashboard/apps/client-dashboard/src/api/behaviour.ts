/**
 * Types, queries and mutations of "Verhalten & Limits" (contracts v0.4, MVP-17): hits of the fixed
 * behaviour scenarios and rate limits, per-scenario modes, rate limit CRUD with a Probelauf and the
 * release of a client. Everything stays on this server.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components, paths } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf } from './client'
import { keys as baseKeys, REFRESH_MS } from './queries'

type S = components['schemas']
export type ScenarioId = S['ScenarioId']
export type BehaviourMode = S['BehaviourMode']
export type BehaviourPreset = S['BehaviourPreset']
export type BehaviourReason = S['BehaviourReason']
export type LimitMode = S['LimitMode']
export type BehaviourHit = S['BehaviourHit']
export type BehaviourHitPage = S['BehaviourHitPage']
export type BehaviourBlock = S['BehaviourBlock']
export type BehaviourHitDetail = S['BehaviourHitDetail']
export type ScenarioThresholds = S['ScenarioThresholds']
export type ScenarioSetting = S['ScenarioSetting']
export type BehaviourSettings = S['BehaviourSettings']
export type BehaviourSettingsPatch = S['BehaviourSettingsPatch']
export type ScenarioThresholdsPatch = S['ScenarioThresholdsPatch']
export type RateLimitDraft = S['RateLimitDraft']
export type RateLimitInput = S['RateLimitInput']
export type RateLimitDryRun = S['RateLimitDryRun']
export type RateLimit = S['RateLimit']
export type ReleaseRequest = S['ReleaseRequest']
export type HitQuery = NonNullable<paths['/behaviour/hits']['get']['parameters']['query']>
export type HttpMethod = NonNullable<RateLimitDraft['methods']>[number]

export const behaviourKeys = {
  hits: (q: HitQuery) => ['behaviour-hits', q] as const,
  hit: (id: string) => ['behaviour-hit', id] as const,
  settings: ['behaviour-settings'] as const,
  limits: ['rate-limits'] as const,
}

export function useBehaviourHits(query: MaybeRefOrGetter<HitQuery>) {
  return useInfiniteQuery({
    queryKey: computed(() => behaviourKeys.hits(toValue(query))),
    queryFn: ({ pageParam }) => unwrap(api.GET('/behaviour/hits', { params: { query: { ...toValue(query), limit: 100, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: BehaviourHitPage) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
    refetchInterval: REFRESH_MS,
  })
}

export function useBehaviourHit(id: MaybeRefOrGetter<string | null | undefined>) {
  return useQuery({
    queryKey: computed(() => behaviourKeys.hit(toValue(id) ?? '')),
    queryFn: () => unwrap(api.GET('/behaviour/hits/{id}', { params: { path: { id: toValue(id)! } } })),
    enabled: computed(() => !!toValue(id)),
    retry: false,
  })
}

export function useBehaviourSettings() {
  return useQuery({
    queryKey: behaviourKeys.settings,
    queryFn: () => unwrap(api.GET('/behaviour/settings')),
    refetchInterval: REFRESH_MS,
  })
}

export function useRateLimits() {
  return useQuery({
    queryKey: behaviourKeys.limits,
    // Presets, schild.yaml and a few own limits: one page of 500 is all of them in practice.
    queryFn: () => unwrap(api.GET('/behaviour/rate-limits', { params: { query: { limit: 500 } } })),
    refetchInterval: REFRESH_MS,
  })
}

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: ['behaviour-hits'] })
  void qc.invalidateQueries({ queryKey: ['behaviour-hit'] })
  void qc.invalidateQueries({ queryKey: behaviourKeys.settings })
  void qc.invalidateQueries({ queryKey: behaviourKeys.limits })
}

export function useUpdateBehaviourSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: BehaviourSettingsPatch) => unwrap(api.PATCH('/behaviour/settings', { params: { header: csrf() }, body })),
    onSuccess: (data) => {
      qc.setQueryData(behaviourKeys.settings, data)
      void qc.invalidateQueries({ queryKey: behaviourKeys.limits })
    },
  })
}

export function useSaveRateLimit() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id?: string, body: RateLimitInput }) => id
      ? unwrap(api.PATCH('/behaviour/rate-limits/{limit_id}', { params: { header: csrf(), path: { limit_id: id } }, body }))
      : unwrap(api.POST('/behaviour/rate-limits', { params: { header: csrf() }, body })),
    onSuccess: () => invalidateAll(qc),
  })
}

export function useDeleteRateLimit() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id }: { id: string }) =>
      unwrap(api.DELETE('/behaviour/rate-limits/{limit_id}', { params: { header: csrf(), path: { limit_id: id } } })),
    onSuccess: () => invalidateAll(qc),
  })
}

export function useDryRunRateLimit() {
  return useMutation({
    mutationFn: (body: RateLimitDraft) => unwrap(api.POST('/behaviour/rate-limits/dry-run', { params: { header: csrf() }, body })),
  })
}

export function useReleaseClient() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: ReleaseRequest) => unwrap(api.POST('/behaviour/release', { params: { header: csrf() }, body })),
    onSuccess: (res) => {
      invalidateAll(qc)
      if (res.allowlist_entry) {
        void qc.invalidateQueries({ queryKey: baseKeys.allowlist })
        void qc.invalidateQueries({ queryKey: baseKeys.myip })
      }
    },
  })
}
