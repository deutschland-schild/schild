/**
 * Browser verification ("Kurze Prüfung") and Under Attack mode of a website
 * (MVP-12 v1_cut): local SHA-256 proof-of-work + accessible no-JS button.
 */
import type { MaybeRefOrGetter } from 'vue'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { csrf } from './client'
import { apiPrefix } from './generated/operations'

export type HumanCheckMode = 'off' | 'findings' | 'always'
export type UnderAttackScope = 'off' | 'admin' | 'all'

export interface UnderAttack {
  scope: UnderAttackScope
  until?: string
}

export interface HumanCheckPolicyView {
  mode: HumanCheckMode
  under_attack: UnderAttack
  under_attack_active: boolean
  except?: string[]
  clearance_ttl_s: number
  difficulty: number
  updated_at?: string
  actor?: string
}

export interface HumanCheckCounters {
  served: number
  passed: number
  nojs: number
  invalid: number
}

export interface HumanCheckState {
  website: string
  policy: HumanCheckPolicyView
  counts: HumanCheckCounters
}

export interface HumanCheckInput {
  mode: HumanCheckMode
  under_attack?: UnderAttack
  except?: string[]
  clearance_ttl_s?: number
  difficulty?: number
}

export const humanCheckKey = (site: string) => ['human-check', site] as const

async function requestJSON<T>(url: string, init: RequestInit = {}): Promise<T> {
  const res = await globalThis.fetch(url, { credentials: 'same-origin', ...init })
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const body = await res.json() as { detail?: string, title?: string }
      msg = body.detail || body.title || msg
    }
    catch {
      // ignore non-JSON error body
    }
    throw new Error(msg)
  }
  return await res.json() as T
}

export function useHumanCheck(site: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => humanCheckKey(toValue(site))),
    queryFn: () => requestJSON<HumanCheckState>(`${apiPrefix}/websites/${encodeURIComponent(toValue(site))}/human-check`),
    enabled: computed(() => !!toValue(site)),
    refetchInterval: 60_000,
  })
}

export function useSetHumanCheck(site: MaybeRefOrGetter<string>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: HumanCheckInput) =>
      requestJSON<HumanCheckState>(`${apiPrefix}/websites/${encodeURIComponent(toValue(site))}/human-check`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...csrf() },
        body: JSON.stringify(body),
      }),
    onSuccess: st => qc.setQueryData(humanCheckKey(st.website), st),
  })
}

export function useRemoveHumanCheck(site: MaybeRefOrGetter<string>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      requestJSON<HumanCheckState>(`${apiPrefix}/websites/${encodeURIComponent(toValue(site))}/human-check`, {
        method: 'DELETE',
        headers: { ...csrf() },
      }),
    onSuccess: st => qc.setQueryData(humanCheckKey(st.website), st),
  })
}
