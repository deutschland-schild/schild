/**
 * Types, queries and mutations of the "Server" section (contracts v0.3, MVP-11):
 * hosts with their read-only host reports, "Jetzt prüfen" for the local host, agent enrolment.
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf } from './client'
import { keys as baseKeys } from './queries'

type S = components['schemas']
export type Severity = S['Severity']
export type SeverityCounts = S['SeverityCounts']
export type ServersSummary = S['ServersSummary']
export type HostSummary = S['HostSummary']
export type HostDetail = S['HostDetail']
/** The stored host report (schild.host_report/0.1); the generator adds the schema's `$defs` as a field, left out here. */
export type HostReport = Omit<NonNullable<HostDetail['report']>, '$defs'>
export type HostFinding = HostReport['findings'][number]
export type InventoryItem = HostReport['inventory'][number]
/** Gateway-side text of one agent finding (catalogue title/explanation, verified fix). */
export type FindingAnnotation = S['FindingAnnotation']
/** A finding the admin marked as accepted (D102); `active` says whether it covers the newest report. */
export type AcceptedFinding = S['AcceptedFinding']
export type Agent = S['Agent']
export type Enrolment = S['Enrolment']
export type EnrolmentInput = S['EnrolmentInput']

/** Host reports change daily; the list refreshes calmly. */
export const HOSTS_REFRESH_MS = 60_000

export const hostKeys = {
  hosts: ['hosts'] as const,
  host: (id: string) => ['host', id] as const,
  agents: ['agents'] as const,
}

export function useHosts(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: hostKeys.hosts,
    // The gateway plus a handful of agents: one page of 500 is every host in practice.
    queryFn: () => unwrap(api.GET('/hosts', { params: { query: { limit: 500 } } })),
    refetchInterval: HOSTS_REFRESH_MS,
    enabled: computed(() => toValue(enabled)),
  })
}

export function useHost(id: MaybeRefOrGetter<string | null | undefined>, refetchInterval: MaybeRefOrGetter<number | false> = HOSTS_REFRESH_MS) {
  return useQuery({
    queryKey: computed(() => hostKeys.host(toValue(id) ?? '')),
    queryFn: () => unwrap(api.GET('/hosts/{host_id}', { params: { path: { host_id: toValue(id)! } } })),
    enabled: computed(() => !!toValue(id)),
    refetchInterval: computed(() => toValue(refetchInterval)),
    retry: false,
  })
}

export function useAgents(refetchInterval: MaybeRefOrGetter<number | false> = HOSTS_REFRESH_MS) {
  return useQuery({
    queryKey: hostKeys.agents,
    queryFn: () => unwrap(api.GET('/agents', { params: { query: { limit: 500 } } })),
    refetchInterval: computed(() => toValue(refetchInterval)),
  })
}

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  void qc.invalidateQueries({ queryKey: hostKeys.hosts })
  void qc.invalidateQueries({ queryKey: hostKeys.agents })
  void qc.invalidateQueries({ queryKey: ['host'] })
  void qc.invalidateQueries({ queryKey: baseKeys.overview })
}

/** "Jetzt prüfen": ask for a run of the local check (202). The gateway never sends agents commands. */
export function useRunLocalCheck() {
  return useMutation({
    mutationFn: () => unwrap(api.POST('/hosts/local/check', { params: { header: csrf() } })),
  })
}

/**
 * Mark an open finding as accepted, or take that back (D102). Both answer with the host as it is
 * now, which replaces the cached detail; list and overview count again.
 */
export function useAcceptFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ host, id, subject, note }: { host: string, id: string, subject?: string | null, note?: string }) =>
      unwrap(api.POST('/hosts/{host_id}/findings/accept', { params: { header: csrf(), path: { host_id: host } }, body: { id, ...(subject ? { subject } : {}), ...(note ? { note } : {}) } })),
    onSuccess: (d, v) => {
      qc.setQueryData(hostKeys.host(v.host), d)
      invalidateAll(qc)
    },
  })
}

export function useReopenFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ host, id, subject }: { host: string, id: string, subject?: string | null }) =>
      unwrap(api.POST('/hosts/{host_id}/findings/reopen', { params: { header: csrf(), path: { host_id: host } }, body: { id, ...(subject ? { subject } : {}) } })),
    onSuccess: (d, v) => {
      qc.setQueryData(hostKeys.host(v.host), d)
      invalidateAll(qc)
    },
  })
}

export function useCreateEnrolment() {
  return useMutation({
    mutationFn: (body: EnrolmentInput) => unwrap(api.POST('/agents/enrolments', { params: { header: csrf() }, body })),
  })
}

export function useConfirmAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, fingerprint, label }: { id: string, fingerprint: string, label?: string }) =>
      unwrap(api.POST('/agents/{agent_id}/confirm', { params: { header: csrf(), path: { agent_id: id } }, body: { fingerprint, ...(label ? { label } : {}) } })),
    onSuccess: () => invalidateAll(qc),
  })
}

export function useRevokeAgent() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, note }: { id: string, note?: string }) =>
      unwrap(api.POST('/agents/{agent_id}/revoke', { params: { header: csrf(), path: { agent_id: id } }, body: { ...(note ? { note } : {}) } })),
    onSuccess: () => invalidateAll(qc),
  })
}
