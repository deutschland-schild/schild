/** The group of gateways this gateway belongs to (contracts/cluster.md, D105): mode, members, what is shared. */
import type { MaybeRefOrGetter } from 'vue'
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { useQuery } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api } from './client'

type S = components['schemas']
export type GroupStatus = S['GroupStatus']
export type GroupMember = S['GroupMember']
export type GroupState = NonNullable<GroupStatus['state']>

export const groupKeys = { status: ['group'] as const }

/** Polled like the block list: the state of a group changes within seconds. */
export function useGroupStatus(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: groupKeys.status,
    queryFn: () => unwrap(api.GET('/group')),
    refetchInterval: 15_000,
    enabled: computed(() => toValue(enabled)),
  })
}
