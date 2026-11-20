/**
 * Zugriffsschutz of a website (D56, MVP-14 step 1): the whole website or only some paths,
 * ways in: a shared password, addresses of this protection, the own networks of Eigene IPs. The password is
 * never read back, only whether one is set.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf } from './client'

type S = components['schemas']
export type AccessProtection = S['AccessProtection']
export type AccessProtectionState = S['AccessProtectionState']
export type AccessProtectionInput = S['AccessProtectionInput']
export type MaintenanceMode = S['MaintenanceMode']
export type MaintenanceInput = S['MaintenanceInput']

export const accessKey = (site: string) => ['access', site] as const

export function useAccessProtection(site: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => accessKey(toValue(site))),
    queryFn: () => unwrap(api.GET('/websites/{website}/access', { params: { path: { website: toValue(site) } } })),
    enabled: computed(() => !!toValue(site)),
    refetchInterval: 60_000,
  })
}

export function useSetAccessProtection(site: MaybeRefOrGetter<string>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: AccessProtectionInput) =>
      unwrap(api.PUT('/websites/{website}/access', { params: { path: { website: toValue(site) }, header: csrf() }, body })),
    onSuccess: st => qc.setQueryData(accessKey(st.website), st),
  })
}

export function useRemoveAccessProtection(site: MaybeRefOrGetter<string>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => unwrap(api.DELETE('/websites/{website}/access', { params: { path: { website: toValue(site) }, header: csrf() } })),
    // The maintenance mode is a switch of its own (D98): removing the protection leaves it as it is.
    onSuccess: () => qc.setQueryData<AccessProtectionState>(accessKey(toValue(site)), old => ({ website: toValue(site), protection: null, maintenance: old?.maintenance ?? { on: false, message: '' } })),
  })
}

/** Switch the maintenance mode of a website on (or change its text) or off (D98). */
export function useSetMaintenance(site: MaybeRefOrGetter<string>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: MaintenanceInput) =>
      unwrap(api.PUT('/websites/{website}/maintenance', { params: { path: { website: toValue(site) }, header: csrf() }, body })),
    onSuccess: st => qc.setQueryData(accessKey(st.website), st),
  })
}
