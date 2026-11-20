import type { MaybeRefOrGetter } from 'vue'
import type {
  ApproveProposal,
  AssembleBundle,
  Confirm,
  CursorPage,
  EmergencyStopInput,
  EvidenceInput,
  LabSettingsPatch,
  LogEntry,
  LogKind,
  LogPage,
  PatternStatus,
  ProposalInput,
  ProposalStatus,
  WithdrawalInput,
} from './types'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { pollInterval } from '@/lib/live'
import { csrf } from './auth-state'
import { api } from './client'

/** Query keys, grouped by topic so live events can invalidate a whole topic. */
export const keys = {
  session: ['session'] as const,
  health: ['health'] as const,
  patterns: (p?: unknown) => (p === undefined ? ['patterns'] as const : ['patterns', p] as const),
  pattern: (id: string) => ['patterns', 'detail', id] as const,
  signals: (p?: unknown) => (p === undefined ? ['signals'] as const : ['signals', p] as const),
  proposals: (p?: unknown) => (p === undefined ? ['proposals'] as const : ['proposals', p] as const),
  proposal: (id: string) => ['proposals', 'detail', id] as const,
  bundles: ['bundles'] as const,
  bundle: (v: number) => ['bundles', 'detail', v] as const,
  withdrawals: ['withdrawals'] as const,
  relays: ['network', 'relays'] as const,
  peers: ['network', 'peers'] as const,
  log: (kind?: string) => (kind === undefined ? ['log'] as const : ['log', kind] as const),
  logEntry: (i: number) => ['log', 'entry', i] as const,
  issuers: ['issuers'] as const,
  clients: (issuer?: string) => (issuer === undefined ? ['clients'] as const : ['clients', issuer] as const),
  settings: ['settings'] as const,
}

const PAGE = 100

function flatten<T>(pages: CursorPage<T>[] | undefined): T[] {
  return pages?.flatMap(p => p.items) ?? []
}

/** Drop empty filter values so they neither reach the URL nor the API. */
export function cleanParams<T extends Record<string, unknown>>(p: T): Partial<T> {
  return Object.fromEntries(Object.entries(p).filter(([, v]) => v !== undefined && v !== null && v !== '')) as Partial<T>
}

// ---------- health ----------

export function useHealth() {
  return useQuery({
    queryKey: keys.health,
    queryFn: () => unwrap(api.GET('/health')),
    refetchInterval: pollInterval(5_000),
  })
}

// ---------- patterns and signals ----------

export interface PatternFilter {
  q?: string
  category?: string
  country?: string
  asn?: number
  min_issuers?: number
  status?: PatternStatus
  sort?: 'last_seen' | 'signals' | 'issuers' | 'first_seen'
  from?: string
  to?: string
}

export function usePatterns(filter: MaybeRefOrGetter<PatternFilter>) {
  const params = computed(() => cleanParams({ ...toValue(filter) }))
  const q = useInfiniteQuery({
    queryKey: computed(() => keys.patterns(params.value)),
    queryFn: ({ pageParam }) => unwrap(api.GET('/patterns', { params: { query: { ...params.value, limit: PAGE, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
    refetchInterval: pollInterval(30_000),
  })
  return Object.assign(q, { items: computed(() => flatten(q.data.value?.pages)) })
}

export function usePattern(id: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => keys.pattern(toValue(id))),
    queryFn: () => unwrap(api.GET('/patterns/{pattern_id}', { params: { path: { pattern_id: toValue(id) } } })),
    enabled: computed(() => !!toValue(id)),
    refetchInterval: pollInterval(30_000),
  })
}

export function useSignals(filter: MaybeRefOrGetter<{ pattern_id?: string, issuer?: string }>) {
  const params = computed(() => cleanParams({ ...toValue(filter) }))
  const q = useInfiniteQuery({
    queryKey: computed(() => keys.signals(params.value)),
    queryFn: ({ pageParam }) => unwrap(api.GET('/signals', { params: { query: { ...params.value, limit: PAGE, cursor: pageParam } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
  })
  return Object.assign(q, { items: computed(() => flatten(q.data.value?.pages)) })
}

// ---------- proposals ----------

export function useProposals(status: MaybeRefOrGetter<ProposalStatus | undefined>) {
  const q = useInfiniteQuery({
    queryKey: computed(() => keys.proposals(toValue(status) ?? 'all')),
    queryFn: ({ pageParam }) => unwrap(api.GET('/proposals', { params: { query: cleanParams({ status: toValue(status), limit: PAGE, cursor: pageParam }) } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
    refetchInterval: pollInterval(30_000),
  })
  return Object.assign(q, { items: computed(() => flatten(q.data.value?.pages)) })
}

export function useProposal(id: MaybeRefOrGetter<string | undefined>) {
  return useQuery({
    queryKey: computed(() => keys.proposal(toValue(id) ?? '')),
    queryFn: () => unwrap(api.GET('/proposals/{id}', { params: { path: { id: toValue(id)! } } })),
    enabled: computed(() => !!toValue(id)),
  })
}

function useInvalidate() {
  const qc = useQueryClient()
  return (...topics: readonly (readonly unknown[])[]) => Promise.all(topics.map(k => qc.invalidateQueries({ queryKey: k })))
}

export function useCreateProposal() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (body: ProposalInput) => unwrap(api.POST('/proposals', { params: { header: csrf() }, body })),
    onSuccess: () => invalidate(keys.proposals(), keys.patterns(), keys.log()),
  })
}

export function useUpdateProposal() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, body }: { id: string, body: ProposalInput }) => unwrap(api.PATCH('/proposals/{id}', { params: { path: { id }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.proposals()),
  })
}

export function useAddEvidence() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, body }: { id: string, body: EvidenceInput }) => unwrap(api.POST('/proposals/{id}/evidence', { params: { path: { id }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.proposals(), keys.log()),
  })
}

export function useApproveProposal() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, body }: { id: string, body: ApproveProposal }) => unwrap(api.POST('/proposals/{id}/approve', { params: { path: { id }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.proposals(), keys.log()),
  })
}

export function useRejectProposal() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, reason }: { id: string, reason: string }) => unwrap(api.POST('/proposals/{id}/reject', { params: { path: { id }, header: csrf() }, body: { reason } })),
    onSuccess: () => invalidate(keys.proposals(), keys.patterns(), keys.log()),
  })
}

// ---------- bundles ----------

export function useBundles() {
  const q = useInfiniteQuery({
    queryKey: keys.bundles,
    queryFn: ({ pageParam }) => unwrap(api.GET('/bundles', { params: { query: cleanParams({ limit: PAGE, cursor: pageParam }) } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
    refetchInterval: pollInterval(30_000),
  })
  return Object.assign(q, { items: computed(() => flatten(q.data.value?.pages)) })
}

export function useBundle(version: MaybeRefOrGetter<number | undefined>) {
  return useQuery({
    queryKey: computed(() => keys.bundle(toValue(version) ?? 0)),
    queryFn: () => unwrap(api.GET('/bundles/{version}', { params: { path: { version: toValue(version)! } } })),
    enabled: computed(() => !!toValue(version)),
  })
}

export function useAssembleBundle() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (body: AssembleBundle) => unwrap(api.POST('/bundles', { params: { header: csrf() }, body })),
    onSuccess: () => invalidate(keys.bundles, keys.proposals(), keys.log(), keys.health),
  })
}

// ---------- withdrawals and emergency stop ----------

export function useWithdrawals() {
  const q = useInfiniteQuery({
    queryKey: keys.withdrawals,
    queryFn: ({ pageParam }) => unwrap(api.GET('/withdrawals', { params: { query: cleanParams({ limit: PAGE, cursor: pageParam }) } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
    refetchInterval: pollInterval(10_000),
  })
  return Object.assign(q, { items: computed(() => flatten(q.data.value?.pages)) })
}

export function useCreateWithdrawal() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (body: WithdrawalInput) => unwrap(api.POST('/withdrawals', { params: { header: csrf() }, body })),
    onSuccess: () => invalidate(keys.withdrawals, keys.log(), keys.health),
  })
}

export function useEmergencyStop() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: (body: EmergencyStopInput) => unwrap(api.POST('/emergency-stop', { params: { header: csrf() }, body })),
    onSuccess: () => invalidate(keys.withdrawals, keys.log(), keys.health),
  })
}

/** Co-sign a bundle another lab proposed (contracts v0.1, POST /bundles/{version}/cosign). */
export function useCosignBundle() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ version, body }: { version: number, body: Confirm }) => unwrap(api.POST('/bundles/{version}/cosign', { params: { path: { version }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.bundles, keys.log()),
  })
}

export function useCosignWithdrawal() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ seq, body }: { seq: number, body: Confirm }) => unwrap(api.POST('/withdrawals/{seq}/cosign', { params: { path: { seq }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.withdrawals, keys.log()),
  })
}

// ---------- network ----------

export function useRelays() {
  return useQuery({ queryKey: keys.relays, queryFn: () => unwrap(api.GET('/relays')), refetchInterval: pollInterval(10_000) })
}

export function usePeers() {
  return useQuery({ queryKey: keys.peers, queryFn: () => unwrap(api.GET('/peers')), refetchInterval: pollInterval(30_000) })
}

// ---------- public log ----------

export function useLog(kind: MaybeRefOrGetter<LogKind | undefined>) {
  const q = useInfiniteQuery({
    queryKey: computed(() => keys.log(toValue(kind) ?? 'all')),
    queryFn: ({ pageParam }) => unwrap(api.GET('/log', { params: { query: cleanParams({ kind: toValue(kind), limit: PAGE, cursor: pageParam }) } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
  })
  return Object.assign(q, {
    items: computed(() => flatten(q.data.value?.pages)),
    head: computed(() => q.data.value?.pages[0]?.head),
  })
}

/**
 * Every log entry (newest first) with the head of the first page, for the RFC 6962 root
 * check. Pages are taken with cursors below the first head, so later entries never mix in.
 */
export async function fetchWholeLog(maxEntries = 50_000): Promise<{ head: LogPage['head'], items: LogEntry[] }> {
  let cursor: string | undefined
  let head: LogPage['head'] | undefined
  const items: LogEntry[] = []
  do {
    const page = await unwrap(api.GET('/log', { params: { query: cleanParams({ limit: 500, cursor }) } }))
    head ??= page.head
    items.push(...page.items)
    cursor = page.next_cursor ?? undefined
  } while (cursor && items.length < maxEntries)
  return { head: head!, items: items.filter(e => e.index < head!.size) }
}

export function fetchLogEntry(index: number) {
  return unwrap(api.GET('/log/{index}', { params: { path: { index } } }))
}

export function useLogEntry(index: MaybeRefOrGetter<number | undefined>) {
  return useQuery({
    queryKey: computed(() => keys.logEntry(toValue(index) ?? -1)),
    queryFn: () => fetchLogEntry(toValue(index)!),
    enabled: computed(() => toValue(index) !== undefined),
  })
}

// ---------- issuers and clients ----------

export function useIssuers() {
  return useQuery({ queryKey: keys.issuers, queryFn: () => unwrap(api.GET('/issuers')), refetchInterval: pollInterval(30_000) })
}

export function useClients(issuer: MaybeRefOrGetter<string | undefined>) {
  const q = useInfiniteQuery({
    queryKey: computed(() => keys.clients(toValue(issuer) ?? 'all')),
    queryFn: ({ pageParam }) => unwrap(api.GET('/clients', { params: { query: cleanParams({ issuer: toValue(issuer), limit: PAGE, cursor: pageParam }) } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: last => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
  })
  return Object.assign(q, { items: computed(() => flatten(q.data.value?.pages)) })
}

export function useUpdateIssuerQuota() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, quota }: { id: string, quota: number }) => unwrap(api.PATCH('/issuers/{id}', { params: { path: { id }, header: csrf() }, body: { quota_per_day: quota } })),
    onSuccess: () => invalidate(keys.issuers),
  })
}

export function useRevokeIssuer() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ id, body }: { id: string, body: Confirm }) => unwrap(api.POST('/issuers/{id}/revoke', { params: { path: { id }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.issuers, keys.clients(), keys.patterns()),
  })
}

export function useUpdateClientQuota() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ keyid, quota }: { keyid: string, quota: number }) => unwrap(api.PATCH('/clients/{keyid}', { params: { path: { keyid }, header: csrf() }, body: { quota_per_day: quota } })),
    onSuccess: () => invalidate(keys.clients()),
  })
}

export function useRevokeClient() {
  const invalidate = useInvalidate()
  return useMutation({
    mutationFn: ({ keyid, body }: { keyid: string, body: Confirm }) => unwrap(api.POST('/clients/{keyid}/revoke', { params: { path: { keyid }, header: csrf() }, body })),
    onSuccess: () => invalidate(keys.clients(), keys.issuers),
  })
}

// ---------- settings ----------

export function useSettings() {
  return useQuery({ queryKey: keys.settings, queryFn: () => unwrap(api.GET('/settings')) })
}

export function useUpdateSettings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: LabSettingsPatch) => unwrap(api.PATCH('/settings', { params: { header: csrf() }, body })),
    onSuccess: data => qc.setQueryData(keys.settings, data),
  })
}
