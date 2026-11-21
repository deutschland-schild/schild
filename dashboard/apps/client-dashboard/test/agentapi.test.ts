import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import type { AgentAPIState, AgentTokenInfo } from '../src/api/agentapi'
import getFixture from '../../../../contracts/api/fixtures/client/getAgentAPI.json'
import callsFixture from '../../../../contracts/api/fixtures/client/listAgentCalls.json'
import setFixture from '../../../../contracts/api/fixtures/client/setAgentAPI.json'
import {
  AGENT_API_COPY,
  AGENT_API_DOCS,
  agentApiStatus,
  configText,
  isLoopback,
  listenText,
  needsConfirm,
  SCOPE_LABEL,
  scopeLabel,
  sortTokens,
  TOKEN_ADD_COMMAND,
  TOKEN_ADD_COMMAND_DOCKER,
  TOKEN_STATE,
  tokenName,
  tokenState,
} from '../src/lib/agentapi'
import { buildNav } from '../src/lib/nav'
import { agentApiView } from '../src/mock/agentapi'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, waitFor } from './helpers'

const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  mock.reset()
})
afterAll(() => mock.server.close())

const BASE = 'http://dashboard.schild.test/api/v0'
const state = getFixture as AgentAPIState
const tokens = callsFixture.tokens as AgentTokenInfo[]
const NOW = Date.parse('2026-11-21T12:00:00Z')

describe('Agent-API copy and helpers', () => {
  it('names on, off and a listener that did not open', () => {
    expect(agentApiStatus(state)).toEqual({ kind: 'on', tone: 'success', label: 'An' })
    expect(agentApiStatus(setFixture as AgentAPIState)).toEqual({ kind: 'off', tone: 'neutral', label: 'Aus' })
    expect(agentApiStatus({ enabled: true, listening: false })).toEqual({ kind: 'not_open', tone: 'warning', label: AGENT_API_COPY.notOpen })
    // Off wins: a closed listener is what off means.
    expect(agentApiStatus({ enabled: false, listening: false }).kind).toBe('off')
  })

  it('tells a token that is valid from one that expired or was revoked', () => {
    expect(tokenState(tokens[0]!, NOW)).toBe('valid')
    expect(tokenState(tokens[0]!, Date.parse(tokens[0]!.expires_at))).toBe('expired')
    expect(tokenState(tokens[1]!, NOW)).toBe('revoked')
    // Revoked stays revoked after its date.
    expect(tokenState(tokens[1]!, Date.parse(tokens[1]!.expires_at) + 1)).toBe('revoked')
    expect(Object.values(TOKEN_STATE).map(x => x.label)).toEqual(['gültig', 'abgelaufen', 'widerrufen'])
  })

  it('lists valid tokens first, the newest of them on top, without changing the input', () => {
    const list: AgentTokenInfo[] = [
      tokens[1]!,
      { ...tokens[0]!, id: 'tok_00000000000a', created_at: '2026-10-01T10:00:00Z' },
      { ...tokens[0]!, id: 'tok_00000000000b', created_at: '2026-11-01T10:00:00Z' },
      { ...tokens[0]!, id: 'tok_00000000000c', expires_at: '2026-11-01T10:00:00Z', created_at: '2026-11-10T10:00:00Z' },
    ]
    expect(sortTokens(list, NOW).map(t => t.id)).toEqual(['tok_00000000000b', 'tok_00000000000a', 'tok_00000000000c', 'tok_000000000002'])
    expect(list[0]!.id).toBe('tok_000000000002')
  })

  it('names a token by its label, else by its id, and every scope of the contract in words', () => {
    expect(tokenName(tokens[0]!)).toBe('Claude Code Laptop')
    expect(tokenName(tokens[1]!)).toBe('tok_000000000002')
    expect(Object.keys(SCOPE_LABEL).sort()).toEqual(['agent:read', 'blocks:write', 'crawlers:write', 'exceptions:write', 'export:read', 'firewall:sync', 'rules:write'])
    expect(scopeLabel('exceptions:write')).toBe('Ausnahmen setzen')
    expect(scopeLabel('later:scope')).toBe('later:scope')
  })

  it('claims "nur vom Server selbst" for a loopback address only', () => {
    for (const l of ['127.0.0.1:8789', '127.0.0.53:8789', '[::1]:8789', 'localhost:8789']) expect(isLoopback(l), l).toBe(true)
    for (const l of ['0.0.0.0:8789', '[::]:8789', '10.0.0.5:8789', '1127.0.0.1:8789']) expect(isLoopback(l), l).toBe(false)
    expect(listenText('127.0.0.1:8789')).toContain('nur vom Server selbst erreichbar')
    expect(listenText('127.0.0.1:8789')).toContain('SSH-Tunnel')
    expect(listenText('0.0.0.0:8789')).not.toContain('nur vom Server selbst')
    expect(listenText('0.0.0.0:8789')).toContain('0.0.0.0:8789')
  })

  it('asks before the API goes off while the firewall container holds a token', () => {
    const s = { enabled: true, config_enabled: true, firewall_tokens: 1 }
    expect(needsConfirm(s, { enabled: false })).toBe(true)
    expect(needsConfirm({ ...s, firewall_tokens: 0 }, { enabled: false })).toBe(false)
    expect(needsConfirm({ ...s, enabled: false }, { enabled: true })).toBe(false)
    // A reset counts by what schild.yaml gives back.
    expect(needsConfirm(s, { reset: true })).toBe(false)
    expect(needsConfirm({ ...s, config_enabled: false }, { reset: true })).toBe(true)
    expect(needsConfirm({ enabled: false, config_enabled: false, firewall_tokens: 1 }, { reset: true })).toBe(false)
  })

  it('keeps the required wording', () => {
    const all = [...Object.values(AGENT_API_COPY), listenText('127.0.0.1:8789'), listenText('0.0.0.0:8789'), configText(true), configText(false), ...Object.values(SCOPE_LABEL)].join(' ')
    expect(all).not.toMatch(/anonym/i)
    expect(all).not.toMatch(/\b(geschützt|sicher|gefährlich|dringend)\b/i)
    expect(all).not.toMatch(/\bSie\b(?! lauscht)|\bIhr(e|en)?\b/)
    expect(all).not.toMatch(/[—–]/)
    expect(AGENT_API_COPY.reset).toBe('Wert aus schild.yaml einsetzen')
    expect(configText(true)).toBe('In schild.yaml steht an.')
    expect(configText(false)).toBe('In schild.yaml steht aus.')
  })

  it('shows the commands of the docs and links to the setup', () => {
    expect(TOKEN_ADD_COMMAND).toBe('sudo schild token add --scope exceptions:write --label coding-agent')
    expect(TOKEN_ADD_COMMAND_DOCKER).toBe('docker compose exec schild schild token add --scope exceptions:write --label coding-agent')
    expect(AGENT_API_DOCS).toMatch(/\/doku\/gateway\/02-betrieb#agent-api-einrichten$/)
  })

  it('is found under Allgemein in the sidebar search', () => {
    const general = buildNav({ site: '' }).flatMap(g => g.items).find(i => i.to === '/settings')!
    expect(general.keywords).toEqual(expect.arrayContaining(['agent', 'agent-api', 'ki-agent', 'token']))
  })
})

describe('the mock switches the agent API like the gateway', () => {
  const h = () => ({ 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! })
  const put = (body: unknown, headers: Record<string, string> = h()) => fetch(`${BASE}/agent-api`, { method: 'PUT', headers, body: JSON.stringify(body) })

  it('serves the shape of the contract fixtures', async () => {
    const st = await (await fetch(`${BASE}/agent-api`)).json()
    expect(Object.keys(st).sort()).toEqual(Object.keys(getFixture).sort())
    expect(st).toMatchObject({ enabled: true, config_enabled: true, state_source: 'config', listening: true, active_tokens: 2, firewall_tokens: 1, updated_at: null, actor: null })
    const log = await (await fetch(`${BASE}/agent-api/calls?limit=1`)).json()
    expect(Object.keys(log).sort()).toEqual(Object.keys(callsFixture).sort())
    expect(log.tokens).toHaveLength(3)
  })

  it('needs the CSRF token and exactly one of enabled and reset', async () => {
    let res = await put({ enabled: false }, { 'Content-Type': 'application/json' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('csrf')
    for (const body of [{}, { enabled: false, reset: true }, { reset: false }, { enabled: 'no' }]) {
      res = await put(body)
      expect(res.status, JSON.stringify(body)).toBe(400)
    }
    expect(mock.state.agentApi.override).toBeNull()
  })

  it('stores the value of the dashboard and gives the switch back with reset', async () => {
    let st = await (await put({ enabled: false })).json()
    expect(st).toMatchObject({ enabled: false, config_enabled: true, state_source: 'dashboard', listening: false, actor: 'admin' })
    expect(st.updated_at).toMatch(/^20\d\d-/)
    st = await (await put({ reset: true })).json()
    expect(st).toMatchObject({ enabled: true, state_source: 'config', listening: true, updated_at: null, actor: null })
  })

  it('answers 409 conflict when the listener does not open, and leaves the switch as it was', async () => {
    await put({ enabled: false })
    mock.state.agentApi.portBusy = true
    const res = await put({ enabled: true })
    expect(res.status).toBe(409)
    const p = await res.json()
    expect(p.code).toBe('conflict')
    expect(p.detail).toContain('127.0.0.1:8789')
    expect(mock.state.agentApi.override!.enabled).toBe(false)
  })
})

const card = () => byTestId('agent-api')
const openCard = async () => {
  await mountApp('/settings')
  await waitFor(() => !!byTestId('agent-api-switch'))
}

describe('Agent-API card on Einstellungen', () => {
  it('shows that the API is on, where it listens and the tokens, valid ones first', async () => {
    await openCard()
    expect(card()!.id).toBe('agent-api')
    expect(card()!.textContent).toContain(AGENT_API_COPY.lead)
    expect(byTestId('agent-api-status')!.textContent).toContain('An')
    expect(byTestId('agent-api-text')!.textContent).toContain(listenText('127.0.0.1:8789'))
    expect(byTestId('agent-api-text')!.textContent).toContain(AGENT_API_COPY.withoutToken)
    expect(byTestId('agent-api-switch')!.textContent!.trim()).toBe('Ausschalten')
    expect(byTestId('agent-api-switch')!.getAttribute('aria-label')).toBe(AGENT_API_COPY.switchOffLabel)
    expect(byTestId('agent-api-reset')).toBeNull()
    expect(byTestId('agent-api-no-token')).toBeNull()
    expect(byTestId('agent-api-docs')!.getAttribute('href')).toBe(AGENT_API_DOCS)

    await waitFor(() => !!byTestId('agent-api-tokens'))
    const rows = [...byTestId('agent-api-tokens')!.querySelectorAll('li')]
    expect(rows.map(r => r.dataset.tokenState)).toEqual(['valid', 'valid', 'revoked'])
    expect(rows[0]!.textContent).toContain('firewall')
    expect(rows[1]!.textContent).toContain('coding-agent')
    expect(rows[1]!.textContent).toContain('Ausnahmen setzen')
    expect(rows[1]!.textContent).toContain('gültig')
    // No label: the id stands in.
    expect(rows[2]!.textContent).toContain('tok_000000000002')
    expect(rows[2]!.textContent).toContain('widerrufen')
    expect(rows[2]!.textContent).toContain(AGENT_API_COPY.neverUsed)
    expect(byTestId('agent-api-tokens-managed')!.textContent).toContain('schild token revoke')
  })

  it('asks before switching off while the firewall container holds a token', async () => {
    await openCard()
    await click(byTestId('agent-api-switch'))
    expect(bodyText()).toContain(AGENT_API_COPY.confirmTitle)
    expect(bodyText()).toContain(AGENT_API_COPY.confirmText)
    expect(mock.state.agentApi.override).toBeNull()

    await click(byTestId('confirm-action'))
    await waitFor(() => mock.state.agentApi.override?.enabled === false)
    await waitFor(() => byTestId('agent-api-status')!.textContent!.includes('Aus'))
    expect(byTestId('agent-api-text')!.textContent).toContain(AGENT_API_COPY.offText)
    expect(byTestId('agent-api-switch')!.textContent!.trim()).toBe('Einschalten')
    expect(bodyText()).toContain(AGENT_API_COPY.savedOff)
  })

  it('switches off straight away without a firewall token, and offers the value of schild.yaml after', async () => {
    mock.state.agentApi.tokens = mock.state.agentApi.tokens.filter(t => t.scope !== 'firewall:sync')
    await openCard()
    await click(byTestId('agent-api-switch'))
    await waitFor(() => mock.state.agentApi.override?.enabled === false)
    expect(bodyText()).not.toContain(AGENT_API_COPY.confirmTitle)

    await waitFor(() => !!byTestId('agent-api-reset'))
    expect(byTestId('agent-api-reset')!.textContent!.trim()).toBe(AGENT_API_COPY.reset)
    expect(byTestId('agent-api-source')!.textContent).toContain('Im Dashboard eingestellt')
    expect(byTestId('agent-api-source')!.textContent).toContain('von admin')
    expect(byTestId('agent-api-source')!.textContent).toContain('In schild.yaml steht an.')

    await click(byTestId('agent-api-reset'))
    await waitFor(() => mock.state.agentApi.override === null)
    await waitFor(() => !byTestId('agent-api-reset'))
    expect(byTestId('agent-api-status')!.textContent).toContain('An')
    expect(bodyText()).toContain(AGENT_API_COPY.savedReset)
  })

  it('shows the command for a first token while there is none', async () => {
    mock.state.agentApi.tokens = []
    await openCard()
    const hint = byTestId('agent-api-no-token')!
    expect(hint.textContent).toContain(AGENT_API_COPY.noToken)
    expect(hint.textContent).toContain(TOKEN_ADD_COMMAND)
    expect(hint.textContent).toContain(TOKEN_ADD_COMMAND_DOCKER)
    expect(byTestId('agent-api-tokens')).toBeNull()
    expect(byTestId('agent-api-tokens-managed')).toBeNull()
  })

  it('says when the listener is not open, and shows the sentence of the gateway when switching on fails', async () => {
    mock.state.agentApi.portBusy = true
    await openCard()
    expect(byTestId('agent-api-status')!.textContent).toContain(AGENT_API_COPY.notOpen)
    expect(byTestId('agent-api-text')!.textContent).toContain(AGENT_API_COPY.notOpenText)
    expect(byTestId('agent-api-error')!.textContent).toContain('address already in use')

    mock.state.agentApi.override = { enabled: false, updated_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), actor: 'admin' }
    cleanup()
    await openCard()
    expect(byTestId('agent-api-switch')!.textContent!.trim()).toBe('Einschalten')
    await click(byTestId('agent-api-switch'))
    await waitFor(() => bodyText().includes(AGENT_API_COPY.failed))
    expect(bodyText()).toContain('Die Agent-API ließ sich auf 127.0.0.1:8789 nicht öffnen.')
    expect(mock.state.agentApi.override!.enabled).toBe(false)
  })

  it('offers no switch when schild.yaml has the agent API off', () => {
    const view = agentApiView({ configEnabled: false, override: { enabled: true, updated_at: '2026-11-21T10:00:00Z', actor: 'admin' }, listen: '127.0.0.1:8789', portBusy: false, tokens: [] }, Date.now())
    expect(view).toMatchObject({ enabled: false, config_enabled: false, state_source: 'config', updated_at: null, listening: false })
    expect(AGENT_API_COPY.lockedText).toContain('agent_api.enabled: false')
  })
})
