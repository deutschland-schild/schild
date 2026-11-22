/**
 * Mock of the agent API switch (D103): getAgentAPI, setAgentAPI and the tokens of listAgentCalls. The value
 * of the dashboard wins over the one of schild.yaml until it is reset; a busy port answers 409 `conflict`
 * with the sentence of the gateway and leaves the switch as it was. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { AgentAPIState, AgentTokenInfo } from '@/api/agentapi'
import type { WebsiteHandlerTools } from './websites'
import { http, HttpResponse } from 'msw'

export interface AgentApiMock {
  /** agent_api.enabled of schild.yaml (on by default, D103). */
  configEnabled: boolean
  /** What the dashboard set; null while schild.yaml decides. */
  override: { enabled: boolean, updated_at: string, actor: string } | null
  listen: string
  /** The port of the listener is in use: switching on fails, and an enabled API does not listen. */
  portBusy: boolean
  tokens: AgentTokenInfo[]
}

const isoS = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
const DAY = 86400_000

export function createAgentApiState(scenario: string, t0: number): AgentApiMock {
  const tokens: AgentTokenInfo[] = scenario === 'empty'
    ? []
    : [
        { id: 'tok_000000000001', scope: 'exceptions:write', label: 'coding-agent', created_at: isoS(t0 - 24 * DAY), expires_at: isoS(t0 + 66 * DAY), revoked_at: null, last_used_at: isoS(t0 - 2 * 3600_000) },
        { id: 'tok_000000000003', scope: 'firewall:sync', label: 'firewall', created_at: isoS(t0 - 20 * DAY), expires_at: isoS(t0 + 345 * DAY), revoked_at: null, last_used_at: isoS(t0 - 20_000) },
        { id: 'tok_000000000002', scope: 'export:read', created_at: isoS(t0 - 32 * DAY), expires_at: isoS(t0 + 333 * DAY), revoked_at: isoS(t0 - 25 * DAY), last_used_at: null },
      ]
  return { configEnabled: true, override: null, listen: '127.0.0.1:8789', portBusy: false, tokens }
}

/** enabled false in schild.yaml is final; otherwise the value of the dashboard holds. */
const effective = (m: AgentApiMock) => m.configEnabled && (m.override?.enabled ?? true)

const active = (m: AgentApiMock, now: number) => m.tokens.filter(t => !t.revoked_at && Date.parse(t.expires_at) > now)

export function agentApiView(m: AgentApiMock, now: number): AgentAPIState {
  const enabled = effective(m)
  const dashboard = m.configEnabled && !!m.override
  const valid = active(m, now)
  return {
    enabled,
    config_enabled: m.configEnabled,
    state_source: dashboard ? 'dashboard' : 'config',
    listen: m.listen,
    listening: enabled && !m.portBusy,
    ...(enabled && m.portBusy ? { error: `listen tcp ${m.listen}: bind: address already in use` } : {}),
    active_tokens: valid.length,
    firewall_tokens: valid.filter(t => t.scope === 'firewall:sync').length,
    updated_at: dashboard ? m.override!.updated_at : null,
    actor: dashboard ? m.override!.actor : null,
  }
}

export function agentApiHandlers(t: WebsiteHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const mock = () => t.state().agentApi
  return [
    http.get(`${base}/agent-api`, guard('read', () => json(agentApiView(mock(), t.now())))),
    http.put(`${base}/agent-api`, guard('write', async ({ request }) => {
      const body = await request.json().catch(() => ({})) as Record<string, unknown>
      const keys = Object.keys(body)
      const reset = body.reset === true
      if (keys.length !== 1 || (!reset && typeof body.enabled !== 'boolean'))
        return problem(400, 'invalid', 'Entweder enabled oder reset: true.', [{ pointer: '/enabled', detail: 'genau eines von enabled und reset' }])
      const m = mock()
      if (body.enabled === true && !m.configEnabled)
        return problem(409, 'config_limit', 'Die Agent-API ist in schild.yaml ausgeschaltet (agent_api.enabled: false) und lässt sich nur dort wieder einschalten.')
      const next = reset ? m.configEnabled : body.enabled as boolean
      const was = effective(m)
      if (next && !was && m.portBusy)
        return problem(409, 'conflict', `Die Agent-API ließ sich auf ${m.listen} nicht öffnen. Der Port ist belegt, oder die Adresse ist außerhalb eines Containers nicht erlaubt. Der Schalter bleibt, wie er war.`)
      m.override = reset ? null : { enabled: next, updated_at: isoS(t.now()), actor: t.state().session.user ?? 'admin' }
      return json(agentApiView(m, t.now()))
    })),
    // The call log: the mock keeps no calls, only the tokens.
    http.get(`${base}/agent-api/calls`, guard('read', ({ request }) => {
      const m = mock()
      const token = new URL(request.url).searchParams.get('token')
      if (token && !m.tokens.some(x => x.id === token)) return problem(404, 'not_found', 'Token nicht gefunden')
      return json({ enabled: effective(m), log_days: 30, tokens: m.tokens, items: [], next_cursor: null })
    })),
  ]
}
