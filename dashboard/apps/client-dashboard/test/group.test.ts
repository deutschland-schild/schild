import type { GroupStatus } from '../src/api/group'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { blockNodeText, clockText, configHint, stateText, erasureNodesText, groupTotals, loadTone, modeView, nodeView, stateView } from '../src/lib/group'
import groupFixture from '../../../../contracts/api/fixtures/client/getGroupStatus.json'
import noGroupFixture from '../../../../contracts/api/fixtures/client/getGroupStatus.no-group.json'
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

describe('the servers of a group on the page Cluster (MVP-27)', () => {
  const byName = (name: string) => group.members!.find(m => m.name === name)!
  it('says whether a server takes traffic: what this server reaches first, then what the server said', () => {
    expect(nodeView(byName('web-1'))).toMatchObject({ tone: 'success', label: 'Nimmt Anfragen an' })
    expect(nodeView(byName('web-3'))).toMatchObject({ tone: 'warning', label: 'Nicht erreichbar' })
    // Old vitals of a server that is no longer reached say nothing about now.
    expect(nodeView({ ...byName('web-2'), state: 'unreachable' }).label).toBe('Nicht erreichbar')
    expect(nodeView({ ...byName('web-2'), vitals: { ...byName('web-2').vitals!, service: 'draining' } })).toMatchObject({ tone: 'warning', label: 'Wird angehalten' })
    expect(nodeView({ ...byName('web-2'), vitals: { ...byName('web-2').vitals!, service: 'not_ready' } })).toMatchObject({ tone: 'warning', label: 'Noch nicht bereit' })
    // A server of an older build tells no vitals: reachable, nothing more is claimed.
    expect(nodeView({ ...byName('web-2'), vitals: undefined })).toMatchObject({ tone: 'neutral', label: 'Erreichbar' })
  })
  it('adds up what the reached servers told and never counts removed members', () => {
    const t = groupTotals(group)
    expect(t).toMatchObject({ gateways: 3, ready: 2, away: 1, reporting: 2 })
    expect(t.requestsPerS).toBeCloseTo(80.5)
    expect(groupTotals({ mode: 'group', members: [{ ...byName('web-1'), vitals: undefined }] }).requestsPerS).toBeNull()
  })
  it('names a clock that is off, and calls one within two seconds the same', () => {
    expect([undefined, 420, -1500, 42_000, -90_000, 3 * 3600_000].map(clockText)).toEqual(['', 'gleich', 'gleich', '42 Sekunden vor', '90 Sekunden nach', '3 Stunden vor'])
  })
  it('says whether the state of a server is the same, and names the areas that differ', () => {
    const same = { blocks: 'same', settings: 'same', access: 'same', logins: 'same' } as const
    expect(stateText(undefined)).toEqual({ text: '', differs: false })
    expect(stateText(same)).toEqual({ text: 'gleich', differs: false })
    expect(stateText({ ...same, logins: 'unknown' })).toEqual({ text: 'unbekannt', differs: false })
    expect(stateText({ ...same, settings: 'differs', logins: 'differs' })).toEqual({ text: 'weicht ab: Einstellungen und Logins', differs: true })
    expect(stateText(byName('web-2').shared_state).differs).toBe(true)
  })
  it('colours a load bar calm up to 80 %, then a warning, red from 95 %', () => {
    expect([null, 0.5, 0.8, 0.95].map(loadTone)).toEqual(['neutral', 'success', 'warning', 'danger'])
  })
})

describe('words for the mode and the group (MVP-27)', () => {
  it('names the group with its number of gateways, and nothing for a gateway that runs alone', () => {
    expect(modeView({ mode: 'single' })).toBeNull()
    // Removed members are no servers of the group.
    expect(modeView(group)).toMatchObject({ label: 'Cluster · 3 Server', short: 'Cluster · 3', tone: 'warning' })
    expect(modeView(withState('active'))).toMatchObject({ label: 'Cluster · 3 Server', tone: 'success' })
    // cluster.enabled without a group: it runs alone, and the indicator says that something is off.
    expect(modeView(noGroupFixture as GroupStatus)).toMatchObject({ label: 'Kein Cluster', tone: 'warning' })
  })

  it('says the state of the sync in calm words', () => {
    expect(stateView(withState('active'))).toMatchObject({ label: 'Abgleich aktiv', tone: 'success' })
    expect(stateView(group)).toMatchObject({ label: 'Abgleich eingeschränkt' })
    expect(stateView(group).text).toContain('web-3 ist gerade nicht erreichbar')
    // Active means every other gateway is reached, not that all hold the same state.
    expect(stateView(withState('active')).text).toBe('Dieser Server erreicht alle 2 anderen Gateways.')
    expect(stateView(withState('active')).text).not.toContain('Stand')
    const two = { ...group, state: 'active' as const, members: group.members!.filter(m => m.name !== 'web-3') }
    expect(stateView(two).text).toBe('Dieser Server erreicht das andere Gateway.')
    // Degraded while the list names nobody away (a member not yet listed): a whole sentence all the same.
    const noneAway = { ...group, members: group.members!.filter(m => m.name !== 'web-3') }
    expect(stateView(noneAway).text).toBe('Mindestens ein Gateway ist gerade nicht erreichbar. Mit den übrigen läuft der Abgleich weiter.')
    const cut = stateView(withState('interrupted'))
    expect(`${cut.label}. ${cut.text}`).toBe('Abgleich unterbrochen. Dieser Server arbeitet mit dem letzten Stand weiter.')
    expect(stateView(withState('removed')).label).toBe('Aus dem Cluster entfernt')
    expect(stateView(withState('syncing')).text).toContain('holt gerade den Stand')
    expect(stateView(noGroupFixture as GroupStatus).text).toContain('gehört zu keinem Cluster')
    // No fear and no promise in any of it.
    for (const s of ['no_group', 'syncing', 'active', 'degraded', 'interrupted', 'removed'] as const)
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
  it('shows no mode in the top bar and says on the server page that it runs alone', async () => {
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-single'))
    expect(byTestId('group-mode')).toBeNull()
    expect(byTestId('group-card')!.dataset.mode).toBe('single')
    expect(byTestId('group-single')!.textContent).toContain('Dieses Gateway läuft allein')
    expect(byTestId('group-members')).toBeNull()
    expect(byTestId('group-state')).toBeNull()
  })

  it('says so when a group is switched on in schild.yaml but the server belongs to none', async () => {
    mock.state.group = noGroupFixture as GroupStatus
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-mode')!.textContent).toContain('Kein Cluster')
    expect(byTestId('group-state')!.textContent).toContain('gehört zu keinem Cluster')
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
  it('shows the group in the top bar and the members on the server page, this server marked', async () => {
    mock.reset({ scenario: 'group' })
    await mountApp('/server')
    await waitFor(() => all('[data-testid="group-member"]').length === 3)
    expect(byTestId('group-mode')!.dataset.mode).toBe('group')
    expect(byTestId('group-mode')!.textContent).toContain('Cluster · 3 Server')
    expect(byTestId('group-state')!.textContent).toContain('Abgleich eingeschränkt')
    const rows = all('[data-testid="group-member"]')
    expect(rows.map(r => [r.dataset.name, r.dataset.state])).toEqual([['web-1', 'self'], ['web-2', 'ok'], ['web-3', 'unreachable']])
    expect(rows[0]!.querySelector('[data-testid="group-self"]')!.textContent).toContain('dieser Server')
    expect(rows[1]!.textContent).toContain('Erreichbar')
    expect(rows[1]!.textContent).toContain('0.1.0-alpha.6')
    expect(rows[1]!.textContent).toContain('weicht ab')
    // This server is what the others are compared with; its hash stands in the tooltip, not as a value.
    const selfConfig = rows[0]!.querySelector('[data-config]')!
    expect(selfConfig.textContent!.trim()).toBe('Referenz')
    expect(selfConfig.getAttribute('title')).toContain('5d41402abc4b')
    expect(rows[2]!.textContent).toContain('Nicht erreichbar')
    expect(rows[2]!.textContent).toContain('connection refused')
    expect(byTestId('group-config-hint')!.textContent).toContain('web-2')
    expect(byTestId('group-removed')!.textContent).toContain('web-0')
    expect(byTestId('group-shared')!.textContent).toContain('2 laufende Sperren')
    expect(byTestId('group-counters')!.textContent).toContain('1.284 Änderungen übernommen')
  })

  it('says when the sync is interrupted or the server was removed', async () => {
    mock.reset({ scenario: 'group' })
    mock.state.group = { ...mock.state.group, state: 'interrupted' }
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-state')!.textContent).toContain('Abgleich unterbrochen')
    expect(byTestId('group-state')!.textContent).toContain('Dieser Server arbeitet mit dem letzten Stand weiter.')
    expect(byTestId('group-mode')!.dataset.state).toBe('interrupted')
    cleanup()
    mock.state.group = { ...mock.state.group, state: 'removed', replaced: 2 }
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-state'))
    expect(byTestId('group-state')!.textContent).toContain('Aus dem Cluster entfernt')
    expect(byTestId('group-counters')!.textContent).toContain('2 eigene Werte durch die des Clusters ersetzt. Die eigenen sind')
    cleanup()
    mock.state.group = { ...mock.state.group, replaced: 1 }
    await mountApp('/server')
    await waitFor(() => !!byTestId('group-counters'))
    expect(byTestId('group-counters')!.textContent).toContain('1 eigenen Wert durch den des Clusters ersetzt. Der eigene ist auf dem Server aufbewahrt.')
  })

  it('shows on the list of blocks which node decided', async () => {
    mock.reset({ scenario: 'group' })
    await mountApp('/blocks')
    await waitFor(() => all('[data-testid="block-node"]').length > 0, 5000)
    const texts = all('[data-testid="block-node"]').map(n => n.textContent!.trim())
    expect(texts[0]).toBe('Von web-2 entschieden')
    expect(texts.slice(1).every(t => t === 'Auf diesem Server entschieden')).toBe(true)
    expect(bodyText()).toContain('Cluster · 3 Server')
  })

  it('names the nodes an erasure reached and the ones still open', async () => {
    mock.reset({ scenario: 'group' })
    const h = { 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! }
    const res = await (await fetch(`${BASE}/privacy/delete`, { method: 'POST', headers: h, body: JSON.stringify({ ip: '203.0.113.42', confirm: true }) })).json()
    expect(res.nodes).toEqual({ reached: ['web-1', 'web-2'], open: ['web-3'] })
  })

  it('adjusts the privacy page wording for cluster mode while keeping single-server wording', async () => {
    // Single mode: keeps single-server statements.
    await mountApp('/privacy?ip=203.0.113.42')
    await waitFor(() => !!byTestId('privacy-result') && bodyText().includes('IP-Adressen verlassen den Server nicht.'))
    expect(bodyText()).toContain('Alles bleibt auf deinem Server.')
    cleanup()

    // Cluster mode: addresses travel to other servers of the operator's cluster, not third parties.
    mock.reset({ scenario: 'group' })
    await mountApp('/privacy?ip=203.0.113.42')
    await waitFor(() => !!byTestId('privacy-result') && byTestId('group-mode')?.dataset.mode === 'group')
    expect(bodyText()).not.toContain('IP-Adressen verlassen den Server nicht.')
    expect(bodyText()).not.toContain('Alles bleibt auf deinem Server.')
    expect(bodyText()).toContain('Nur im Cluster')
    expect(bodyText()).toContain('IP-Adressen gehen nur an die anderen Server deines Clusters, nicht an Dritte.')
    expect(bodyText()).toContain('Alles bleibt auf den Servern deines Clusters.')
    cleanup()

    // The mode is not known (the answer is missing): nothing is claimed.
    const real = globalThis.fetch
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : String(input), BASE)
      return url.pathname.endsWith('/group') ? new Response('{}', { status: 500, headers: { 'content-type': 'application/json' } }) : real(input, init)
    })
    try {
      await mountApp('/privacy?ip=203.0.113.42')
      await waitFor(() => !!byTestId('privacy-result'))
      expect(bodyText()).not.toContain('IP-Adressen verlassen den Server nicht.')
      expect(bodyText()).not.toContain('IP-Adressen gehen nur an')
      expect(bodyText()).not.toContain('Alles bleibt auf')
    }
    finally {
      spy.mockRestore()
    }
  })
})
