/**
 * The switch of the agent API (D103): whether its listener is open, where the value comes from, and the
 * tokens as the host stores them. The dashboard opens and closes the listener; tokens are created and
 * revoked on the host only. Session and CSRF, no password.
 */
import type { components } from './generated/schema'
import { unwrap } from '@schild/app-kit'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { api, csrf, errorMessage, problemOf } from './client'

type S = components['schemas']
export type AgentAPIState = S['AgentAPIState']
export type AgentAPIInput = S['AgentAPIInput']
export type AgentTokenInfo = S['AgentTokenInfo']
export type AgentTokenScope = AgentTokenInfo['scope']

export const agentApiKeys = {
  state: ['agent-api'] as const,
  tokens: ['agent-api', 'tokens'] as const,
}

/** Tokens expire and the listener can fail on its own: refresh every minute. */
const REFRESH_MS = 60_000

/**
 * The 409 of the switch comes worded by the gateway (the listener did not open, with its address): show
 * its sentence. Everything else as errorMessage says it.
 */
export function agentApiError(err: unknown): string {
  const p = problemOf(err)
  return (p?.code === 'conflict' && p.detail) || errorMessage(err)
}

export function useAgentAPI() {
  return useQuery({
    queryKey: agentApiKeys.state,
    queryFn: () => unwrap(api.GET('/agent-api')),
    refetchInterval: REFRESH_MS,
  })
}

/** Switch on or off, or give the switch back to schild.yaml. In force when the answer is there. */
export function useSetAgentAPI() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: AgentAPIInput) => unwrap(api.PUT('/agent-api', { params: { header: csrf() }, body })),
    onSuccess: st => qc.setQueryData(agentApiKeys.state, st),
  })
}

/** The tokens of the agent API. They come with the call log; one call is the smallest page it serves. */
export function useAgentTokens() {
  return useQuery({
    queryKey: agentApiKeys.tokens,
    queryFn: async () => (await unwrap(api.GET('/agent-api/calls', { params: { query: { limit: 1 } } }))).tokens,
    refetchInterval: REFRESH_MS,
  })
}
