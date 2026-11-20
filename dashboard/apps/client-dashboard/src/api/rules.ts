/**
 * Rule repositories and their rules (D73, contracts v0.6): OWASP CRS, CrowdSec Hub and the operator's own
 * rules behind one interface. Every write is session and CSRF only, no password (D39 amendment, D73).
 */
import type { MaybeRefOrGetter } from 'vue'
import type { components, paths } from './generated/schema'
import type { RuleDetail, RulePage, RuleRepository, RuleRepositoryId, RuleRepositoryState } from './types'
import { unwrap } from '@schild/app-kit'
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue } from 'vue'
import { api, csrf, errorMessage, problemOf } from './client'
import { keys as baseKeys } from './queries'

/** The problems of the rule API in plain words; everything else as errorMessage says it. */
const RULE_PROBLEMS: Record<string, string> = {
  config_limit: 'Diese Regel ist in schild.yaml ausgeschaltet. Einschalten kannst du sie nur dort.',
  sync_refused: 'Die Dateien in rules.d ließen sich nicht laden. Es laufen weiter die Regeln von vorher.',
  not_update: 'Nur Regeln aus einem Update brauchen eine Freigabe.',
  not_supported: 'Das geht bei dieser Regelquelle nicht.',
}
export function ruleError(err: unknown): string {
  const code = problemOf(err)?.code
  return (code && RULE_PROBLEMS[code]) || errorMessage(err)
}

export type RuleQuery = NonNullable<paths['/rules']['get']['parameters']['query']>

export const ruleKeys = {
  repositories: ['rule-repositories'] as const,
  exceptions: ['rule-exceptions'] as const,
  rules: (q: RuleQuery) => ['rules', q] as const,
  rule: (repository: string, id: string) => ['rule', repository, id] as const,
}

/** Repositories change on their own (hub updates, settling ends): refresh every minute. */
const REPO_REFRESH_MS = 60_000

export function useRuleRepositories(enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: ruleKeys.repositories,
    queryFn: () => unwrap(api.GET('/rule-repositories')),
    refetchInterval: REPO_REFRESH_MS,
    enabled: computed(() => toValue(enabled)),
  })
}

/** The rule exceptions in force (D83), set in the dashboard (D84) or through the agent API. */
export function useRuleExceptions() {
  return useQuery({
    queryKey: ruleKeys.exceptions,
    queryFn: () => unwrap(api.GET('/rule-exceptions')),
    refetchInterval: REPO_REFRESH_MS,
  })
}

export type RuleExceptionInput = components['schemas']['RuleExceptionRequest']

/** The refusals of an exception come worded by the gateway: show its sentence. */
const EXCEPTION_CODES = ['unknown_rule', 'website_without_hosts', 'exception_cap', 'exception_refused', 'not_supported', 'not_found']
export function exceptionError(err: unknown): string {
  const p = problemOf(err)
  return (p?.code && EXCEPTION_CODES.includes(p.code) && p.detail) || errorMessage(err)
}

/** Set an exception (D84): in force when the answer is there. Session and CSRF, no password. */
export function useCreateRuleException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: RuleExceptionInput) => unwrap(api.POST('/rule-exceptions', { params: { header: csrf() }, body })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ruleKeys.exceptions }),
  })
}

/** Take an exception back, whoever set it. The answer is the list that is left. */
export function useRemoveRuleException() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE('/rule-exceptions/{id}', { params: { header: csrf(), path: { id } } })),
    onSuccess: list => qc.setQueryData(ruleKeys.exceptions, list),
    // 404: someone else removed it already.
    onError: () => void qc.invalidateQueries({ queryKey: ruleKeys.exceptions }),
  })
}

/** Take one rule out of an exception (D86): the exception stays for the others, the last rule out removes it. */
export function useRemoveRuleExceptionRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, rule }: { id: number, rule: string }) =>
      unwrap(api.DELETE('/rule-exceptions/{id}/rules/{rule}', { params: { header: csrf(), path: { id, rule } } })),
    onSuccess: list => qc.setQueryData(ruleKeys.exceptions, list),
    onError: () => void qc.invalidateQueries({ queryKey: ruleKeys.exceptions }),
  })
}

/** One repository, read from the list (one request for the page, the sidebar hint and the overview). */
export function useRuleRepository(id: MaybeRefOrGetter<RuleRepositoryId>) {
  const q = useRuleRepositories()
  const repo = computed(() => q.data.value?.items.find(r => r.id === toValue(id)))
  return { ...q, repo }
}

export function useRules(query: MaybeRefOrGetter<RuleQuery> = {}) {
  return useInfiniteQuery({
    queryKey: computed(() => ruleKeys.rules(toValue(query))),
    queryFn: ({ pageParam }) => unwrap(api.GET('/rules', { params: { query: { ...toValue(query), limit: 500, ...(pageParam ? { cursor: pageParam } : {}) } } })),
    initialPageParam: '' as string,
    getNextPageParam: (last: RulePage) => last.next_cursor ?? undefined,
    placeholderData: keepPreviousData,
  })
}

export function useRule(repository: MaybeRefOrGetter<RuleRepositoryId | null | undefined>, id: MaybeRefOrGetter<string | null | undefined>) {
  return useQuery({
    queryKey: computed(() => ruleKeys.rule(toValue(repository) ?? '', toValue(id) ?? '')),
    queryFn: () => unwrap(api.GET('/rules/{repository}/{rule}', { params: { path: { repository: toValue(repository)!, rule: toValue(id)! } } })),
    enabled: computed(() => !!toValue(repository) && !!toValue(id)),
  })
}

type QC = ReturnType<typeof useQueryClient>

function setRepository(qc: QC, repo: RuleRepository) {
  qc.setQueryData<{ items: RuleRepository[] }>(ruleKeys.repositories, old => old && { items: old.items.map(r => r.id === repo.id ? repo : r) })
}

/** A repository changed (state, sync, reset): its rules, the counts of the others and Grundschutz follow. */
function afterRepository(qc: QC, repo: RuleRepository) {
  setRepository(qc, repo)
  void qc.invalidateQueries({ queryKey: ruleKeys.repositories })
  void qc.invalidateQueries({ queryKey: ['rules'] })
  void qc.invalidateQueries({ queryKey: ['rule'] })
  void qc.invalidateQueries({ queryKey: baseKeys.overview })
}

/** Aus, Erkennen, Sperren or back to the value of schild.yaml: one click, no password. */
export function useUpdateRuleRepository() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: RuleRepositoryId, body: { state: RuleRepositoryState } | { reset_state: true } }) =>
      unwrap(api.PATCH('/rule-repositories/{repository}', { params: { header: csrf(), path: { repository: id } }, body })),
    onSuccess: repo => afterRepository(qc, repo),
  })
}

/** crowdsec: check the hub now. local: load rules.d again (409 sync_refused keeps the running rules). */
export function useSyncRuleRepository() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: RuleRepositoryId) => unwrap(api.POST('/rule-repositories/{repository}/sync', { params: { header: csrf(), path: { repository: id } } })),
    onSuccess: repo => afterRepository(qc, repo),
    // A refused reload of rules.d is in the repository's last_error: show it.
    onError: () => void qc.invalidateQueries({ queryKey: ruleKeys.repositories }),
  })
}

/** crowdsec: back to the rules shipped in the image. */
export function useResetRuleRepository() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: RuleRepositoryId) => unwrap(api.POST('/rule-repositories/{repository}/reset', { params: { header: csrf(), path: { repository: id } } })),
    onSuccess: repo => afterRepository(qc, repo),
  })
}

interface InfiniteData<T> { pages: T[], pageParams: unknown[] }

/** One rule changed: the detail, its row in every loaded list, and the counts of its repository. */
function afterRule(qc: QC, rule: RuleDetail) {
  qc.setQueryData(ruleKeys.rule(rule.repository, rule.id), rule)
  qc.setQueriesData<InfiniteData<RulePage>>({ queryKey: ['rules'] }, old => old && ({
    ...old,
    pages: old.pages.map(p => ({
      ...p,
      items: p.items.map((i) => {
        if (i.repository !== rule.repository || i.id !== rule.id) return i
        const { seclang: _s, file: _f, decisions: _d, ...row } = rule
        return row
      }),
    })),
  }))
  void qc.invalidateQueries({ queryKey: ruleKeys.repositories })
  void qc.invalidateQueries({ queryKey: baseKeys.overview })
}

export interface RuleRef { repository: RuleRepositoryId, id: string }

export function useSetRuleDisabled() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ repository, id, disabled, note }: RuleRef & { disabled: boolean, note?: string }) =>
      unwrap(api.PATCH('/rules/{repository}/{rule}', { params: { header: csrf(), path: { repository, rule: id } }, body: { disabled, ...(note ? { note } : {}) } })),
    onSuccess: rule => afterRule(qc, rule),
  })
}
