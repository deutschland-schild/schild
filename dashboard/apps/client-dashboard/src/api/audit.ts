/**
 * The audit log (MVP-36, contracts/audit.md): who changed what, when, through which way, and what it was
 * before. One operation, listAudit, newest first with a cursor. The same call with a filter and a small
 * limit answers who changed a thing last.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components, paths } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api } from './client'

type S = components['schemas']
export type AuditEntry = S['audit-entry.schema']
export type AuditPage = S['AuditPage']
export type AuditActor = AuditEntry['actor']
export type AuditField = NonNullable<AuditEntry['change']>['fields'][number]
export type AuditClass = AuditEntry['class']
export type AuditHidden = NonNullable<AuditField['hidden']>
export type AuditQuery = Omit<NonNullable<paths['/audit']['get']['parameters']['query']>, 'cursor' | 'limit'>
export type AuditWay = NonNullable<AuditQuery['way']>

export const auditKeys = {
  list: (q: AuditQuery) => ['audit', 'list', q] as const,
  last: (q: AuditQuery, limit: number) => ['audit', 'last', q, limit] as const,
}

const PAGE = 100

/** The list of the page Protokoll: every loaded page, more with the cursor. */
export function useAudit(query: MaybeRefOrGetter<AuditQuery>) {
  return useInfiniteQuery({
    queryKey: computed(() => auditKeys.list(toValue(query))),
    queryFn: ({ pageParam }) => unwrap(api.GET('/audit', { params: { query: { ...toValue(query), limit: PAGE, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: AuditPage) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
  })
}

/**
 * The newest entries of a filter, one small page: "Zuletzt geändert von …" at an object or a setting
 * (limit 1), the last changes of a kind of object (one call for a whole list), and what was done because
 * of an event or an incident.
 */
export function useAuditLast(query: MaybeRefOrGetter<AuditQuery>, limit = 1, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => auditKeys.last(toValue(query), limit)),
    queryFn: () => unwrap(api.GET('/audit', { params: { query: { ...toValue(query), limit } } })),
    enabled: computed(() => toValue(enabled)),
  })
}
