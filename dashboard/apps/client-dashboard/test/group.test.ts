import type { GroupStatus } from '../src/api/group'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { blockNodeText, configHint, erasureNodesText, modeView, stateView } from '../src/lib/group'
import groupFixture from '../../../../contracts/api/fixtures/client/getGroupStatus.json'
import noGroupFixture from '../../../../contracts/api/fixtures/client/getGroupStatus.no-group.json'
import pausedFixture from '../../../../contracts/api/fixtures/client/getGroupStatus.paused.json'
import { bodyText, byTestId, cleanup, mockServer, mountApp, waitFor } from './helpers'

const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

const all = <T extends Element = HTMLElement>(sel: string) => [...document.querySelectorAll<T>(sel)]
const group = groupFixture as GroupStatus
const withState = (state: GroupStatus['state']): GroupStatus => ({ ...group, state })

describe('words for the mode and the group (MVP-27)', () => {
  it('names the mode: alone, or a group with its number of gateways', () => {
    expect(modeView({ mode: 'single' })).toMatchObject({ label: 'Einzelner Server', short: 'Einzeln', tone: 'neutral' })
    // Edges and removed members are no servers of the group.
    expect(modeView(group)).toMatchObject({ label: 'Gruppe · 3 Server', short: 'Gruppe · 3', tone: 'warning' })
    expect(modeView(withState('active'))).toMatchObject({ label: 'Gruppe · 3 Server', tone: 'success' })
    // cluster.enabled without a group: it runs alone, and the indicator says that something is off.
    expect(modeView(noGroupFixture as GroupStatus)).toMatchObject({ label: 'Einzelner Server', tone: 'warning' })
  })

  it('says the state of the sync in calm words', () => {
    expect(stateView(withState('active'))).toMatchObject({ label: 'Abgleich aktiv', tone: 'success' })
    expect(stateView(group)).toMatchObject({ label: 'Abgleich eingeschränkt' })
    expect(stateView(group).text).toContain('web-3 ist gerade nicht erreichbar')
    const cut = stateView(withState('interrupted'))
    expect(`${cut.label}. ${cut.text}`).toBe('Abgleich unterbrochen. Dieser Server arbeitet mit dem letzten Stand weiter.')
    expect(stateView(pausedFixture as GroupStatus).text).toContain('schild cluster resume')
    expect(stateView(withState('removed')).label).toBe('Aus der Gruppe entfernt')
    expect(stateView(withState('syncing')).text).toContain('holt gerade den Stand')
    expect(stateView(noGroupFixture as GroupStatus).text).toContain('gehört zu keiner Gruppe')
    // No fear and no promise in any of it.
    for (const s of ['no_group', 'syncing', 'active', 'degraded', 'interrupted', 'paused', 'removed'] as const)
      expect(`${stateView(withState(s)).label} ${stateView(withState(s)).text}`).not.toMatch(/sicher|geschützt|Gefahr|Achtung|!/i)
  })

  it('hints at config drift, names where a block was decided and how far an erasure got', () => {
    expect(configHint(group)).toContain('Die Konfiguration von web-2 weicht von diesem Server ab')
    expect(configHint({ ...group, config: { version: '5d41402abc4b', differing: [] } })).toBeNull()
    expect(configHint({ mode: 'single' })).toBeNull()
    expect(blockNodeText({ node: 'web-2', node_self: false })).toBe('Von web-2 entschieden')
    expect(blockNodeText({ node: 'web-1', node_self: true })).toBe('Auf diesem Server entschieden')
    expect(blockNodeText({})).toBe('')
    expect(erasureNodesText({ reached: ['web-1', 'web-2'], open: [] })).toBe('Gelöscht auf web-1 und web-2.')
    expect(erasureNodesText({ reached: ['web-1'], open: ['web-3'] })).toContain('Noch offen: web-3.')
    expect(erasureNodesText(undefined)).toBe('')
  })
})

describe('a single gateway', () => {
  it('shows "Einzelner Server" on every page and on the server page', async () => {
    await mountApp('/')
    await waitFor(() => !!byTestId('group-mode'))
    expect(byTestId('group-mode')!.dataset.mode).toBe('single')
    expect(byTestId('group-mode')!.textContent).toContain('Einzelner Server')
    cleanup()
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-single'))
    expect(byTestId('group-card')!.dataset.mode).toBe('single')
    expect(byTestId('group-single')!.textContent).toContain('Dieses Gateway läuft allein')
    expect(byTestId('group-members')).toBeNull()
    expect(byTestId('group-state')).toBeNull()
  })

  it('says so when a group is switched on in schild.yaml but the server belongs to none', async () => {
    mock.state.group = noGroupFixture as GroupStatus
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-mode')!.textContent).toContain('Einzelner Server')
    expect(byTestId('group-state')!.textContent).toContain('gehört zu keiner Gruppe')
    expect(byTestId('group-members')).toBeNull()
  })

  it('names no node on blocks and erasures', async () => {
    const h = { 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! }
    const blocks = await (await fetch(`${BASE}/blocks`)).json() as { items: { node?: string }[] }
    expect(blocks.items.length).toBeGreaterThan(0)
    expect(blocks.items.every(b => b.node === undefined)).toBe(true)
    const res = await (await fetch(`${BASE}/privacy/delete`, { method: 'POST', headers: h, body: JSON.stringify({ ip: '203.0.113.42', confirm: true }) })).json()
    expect(res.nodes).toBeUndefined()
    expect(await (await fetch(`${BASE}/group`)).json()).toEqual({ mode: 'single' })
  })
})

describe('a node of a group', () => {
  it('shows the group in the top bar and the members on the server page, this server marked, edges apart', async () => {
    mock.reset({ scenario: 'group' })
    await mountApp('/server')
    await waitFor(() => all('[data-testid="group-member"]').length === 3)
    expect(byTestId('group-mode')!.dataset.mode).toBe('group')
    expect(byTestId('group-mode')!.textContent).toContain('Gruppe · 3 Server')
    expect(byTestId('group-state')!.textContent).toContain('Abgleich eingeschränkt')
    const rows = all('[data-testid="group-member"]')
    expect(rows.map(r => [r.dataset.name, r.dataset.state])).toEqual([['web-1', 'self'], ['web-2', 'ok'], ['web-3', 'unreachable']])
    expect(rows[0]!.querySelector('[data-testid="group-self"]')!.textContent).toContain('dieser Server')
    expect(rows[1]!.textContent).toContain('Erreichbar')
    expect(rows[1]!.textContent).toContain('0.1.0-alpha.4')
    expect(rows[1]!.textContent).toContain('weicht ab')
    expect(rows[2]!.textContent).toContain('Nicht erreichbar')
    expect(rows[2]!.textContent).toContain('connection refused')
    expect(byTestId('group-config-hint')!.textContent).toContain('web-2')
    expect(all('[data-testid="group-edge"]').map(e => e.dataset.state)).toEqual(['ok', 'asks_elsewhere'])
    expect(byTestId('group-edges')!.textContent).toContain('2 Adressen in der Firewall')
    expect(byTestId('group-removed')!.textContent).toContain('web-0')
    expect(byTestId('group-shared')!.textContent).toContain('2 laufende Sperren')
    expect(byTestId('group-counters')!.textContent).toContain('1.284 Änderungen übernommen')
  })

  it('says when the sync is interrupted, paused or the server was removed', async () => {
    mock.reset({ scenario: 'group' })
    mock.state.group = { ...mock.state.group, state: 'interrupted' }
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-state')!.textContent).toContain('Abgleich unterbrochen')
    expect(byTestId('group-state')!.textContent).toContain('Dieser Server arbeitet mit dem letzten Stand weiter.')
    expect(byTestId('group-mode')!.dataset.state).toBe('interrupted')
    cleanup()
    mock.state.group = pausedFixture as GroupStatus
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-state')!.textContent).toContain('Abgleich pausiert')
    expect(byTestId('group-counters')!.textContent).toContain('2 eigene Werte')
    cleanup()
    mock.state.group = { ...mock.state.group, state: 'removed' }
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-state')!.textContent).toContain('Aus der Gruppe entfernt')
  })

  it('shows on the list of blocks which node decided', async () => {
    mock.reset({ scenario: 'group' })
    await mountApp('/blocks')
    await waitFor(() => all('[data-testid="block-node"]').length > 0, 5000)
    const texts = all('[data-testid="block-node"]').map(n => n.textContent!.trim())
    expect(texts[0]).toBe('Von web-2 entschieden')
    expect(texts.slice(1).every(t => t === 'Auf diesem Server entschieden')).toBe(true)
    expect(bodyText()).toContain('Gruppe · 3 Server')
  })

  it('names the nodes an erasure reached and the ones still open', async () => {
    mock.reset({ scenario: 'group' })
    const h = { 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! }
    const res = await (await fetch(`${BASE}/privacy/delete`, { method: 'POST', headers: h, body: JSON.stringify({ ip: '203.0.113.42', confirm: true }) })).json()
    expect(res.nodes).toEqual({ reached: ['web-1', 'web-2'], open: ['web-3'] })
  })
})
