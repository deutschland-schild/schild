/**
 * Types, queries and mutations of the "Wellen" tab in "Verhalten & Limits" (contracts v0.4, MVP-18):
 * distributed attacks detected by target, fingerprint and request shape, per-detector switches and
 * ending a running response early. Address-free and local only.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components, paths } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf } from './client'
import { REFRESH_MS } from './queries'

type S = components['schemas']
export type DetectorId = S['DetectorId']
export type DistributedMode = S['DistributedMode']
export type Wave = S['Wave']
export type WavePage = S['WavePage']
export type WaveDetail = S['WaveDetail']
export type DetectorThresholds = S['DetectorThresholds']
export type DetectorSetting = S['DetectorSetting']
export type DistributedSettings = S['DistributedSettings']
export type DistributedSettingsPatch = S['DistributedSettingsPatch']
export type WaveQuery = NonNullable<paths['/distributed/waves']['get']['parameters']['query']>

export const distributedKeys = {
  waves: (q: WaveQuery) => ['distributed-waves', q] as const,
  wave: (id: string) => ['distributed-wave', id] as const,
  settings: ['distributed-settings'] as const,
}

export function useWaves(query: MaybeRefOrGetter<WaveQuery>) {
  return useInfiniteQuery({
    queryKey: computed(() => distributedKeys.waves(toValue(query))),
    queryFn: ({ pageParam }) => unwrap(api.GET('/distributed/waves', { params: { query: { ...toValue(query), limit: 100, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: WavePage) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
    refetchInterval: REFRESH_MS,
  })
}

export function useWave(id: MaybeRefOrGetter<string | null | undefined>) {
  return useQuery({
    queryKey: computed(() => distributedKeys.wave(toValue(id) ?? '')),
    queryFn: () => unwrap(api.GET('/distributed/waves/{wave_id}', { params: { path: { wave_id: toValue(id)! } } })),
    enabled: computed(() => !!toValue(id)),
    retry: false,
  })
}

export function useDistributedSettings() {
  return useQuery({
    queryKey: distributedKeys.settings,
    queryFn: () => unwrap(api.GET('/distributed/settings')),
    refetchInterval: REFRESH_MS,
  })
}

export function useUpdateDistributedSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: DistributedSettingsPatch) => unwrap(api.PATCH('/distributed/settings', { params: { header: csrf() }, body })),
    onSuccess: (data) => {
      qc.setQueryData(distributedKeys.settings, data)
    },
  })
}

export function useEndWave() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id }: { id: string }) =>
      unwrap(api.POST('/distributed/waves/{wave_id}/end', { params: { header: csrf(), path: { wave_id: id } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['distributed-waves'] })
      void qc.invalidateQueries({ queryKey: ['distributed-wave'] })
    },
  })
}
