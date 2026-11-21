import type { HostFinding, HostSummary, InventoryItem } from '../src/api/hosts'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { countsText, eolState, evidenceItems, FEATURES, fixConfigApply, groupFingerprint, hostStatusText, normalizeFingerprint, sortInventory, toApiFingerprint } from '../src/lib/hosts'
import { serversSummary } from '../src/mock/hosts'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, type, waitFor } from './helpers'

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
/** Open the detail of every line of the findings list. */
const expandAll = () => click(byTestId('expand-all'))
const rowsOf = (area: string) => all(`[data-testid="finding-row"][data-area="${area}"]`)
const button = (label: string) => all<HTMLButtonElement>('button').find(b => b.textContent?.trim() === label) ?? null

describe('server helpers', () => {
  it('formats typed evidence without free text', () => {
    const f = { id: 'ports.public_service', area: 'ports', severity: 'high', status: 'finding', title: 't', explanation: 'e', fix_command: null, evidence: { source: 'ss', port: 6379, protocol: 'tcp', address: '203.0.113.10', process: 'redis-server' } } as HostFinding
    const text = evidenceItems(f).map(i => typeof i === 'string' ? i : i.text)
    expect(text).toEqual(['Port 6379/tcp auf 203.0.113.10', 'redis-server', 'Quelle: ss'])
  })

  it('formats log evidence (v0.5, D38): size, growth and share of the file system', () => {
    const f = { id: 'logs.large_file', area: 'logs', severity: 'medium', status: 'finding', title: 't', explanation: 'e', fix_command: null, evidence: { source: 'stat', path: '/srv/app/storage/logs/laravel.log', size_bytes: 6_549_825_126, growth_bytes_per_day: 398_458_880, fs_percent: 16, mount: '/' } } as HostFinding
    const text = evidenceItems(f).map(i => typeof i === 'string' ? i : i.text)
    expect(text).toEqual(['Größe 6,5 GB', 'wächst um 398,5 MB pro Tag', '16 % von /', '/srv/app/storage/logs/laravel.log', 'Quelle: Dateigröße'])
  })

  it('says how a fix_config takes effect', () => {
    const fc = { path: '/etc/logrotate.d/schild-laravel', content: 'x\n' }
    expect(fixConfigApply({ id: 'logs.large_file', fix_command: null }, fc)).toContain('sudo logrotate -d /etc/logrotate.d/schild-laravel')
    expect(fixConfigApply({ id: 'logs.docker_unbounded', fix_command: null }, fc)).toContain('neu erstellte Container')
    expect(fixConfigApply({ id: 'logs.journald_size', fix_command: 'sudo systemctl restart systemd-journald' }, fc)).toContain('Befehl darunter')
  })

  it('normalises and groups fingerprints for comparison', () => {
    const hex = 'ab'.repeat(32)
    expect(normalizeFingerprint(` SHA256:${hex.toUpperCase().match(/.{4}/g)!.join(' ')} `)).toBe(hex)
    expect(toApiFingerprint(hex)).toBe(`sha256:${hex}`)
    expect(toApiFingerprint('abc')).toBeNull()
    expect(groupFingerprint(`sha256:${hex}`).split(' ')).toHaveLength(16)
  })

  it('knows ended, ending and later support and sorts ended software first, plugins after their app', () => {
    const now = Date.parse('2026-10-27T00:00:00Z')
    expect(eolState('2026-01-01', now)).toBe('past')
    expect(eolState('2027-01-01', now)).toBe('soon')
    expect(eolState('2030-01-01', now)).toBe('ok')
    expect(eolState(null, now)).toBe('unknown')
    const inv: InventoryItem[] = [
      { kind: 'app', name: 'contact-form-7', version: '5.9', eol: null, source: 'app_path', parent: 'wordpress', path: '/var/www/shop/wp-content/plugins/contact-form-7' },
      { kind: 'server', name: 'nginx', version: '1.24', eol: null, source: 'dpkg' },
      { kind: 'app', name: 'wordpress', version: '6.4.3', eol: null, source: 'app_path', path: '/var/www/shop' },
      { kind: 'runtime', name: 'php7.3', version: '7.3', eol: '2021-12-06', source: 'dpkg' },
    ]
    expect(sortInventory(inv, now).map(i => i.name)).toEqual(['php7.3', 'nginx', 'wordpress', 'contact-form-7'])
  })

  it('says "meldet sich nicht" before any count', () => {
    const h = { silent: true, status: 'silent', counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } } as HostSummary
    expect(hostStatusText(h)).toBe('meldet sich nicht')
    expect(countsText({ critical: 1, high: 0, medium: 2, low: 0, info: 3 })).toBe('1 dringend, 2 mittel')
  })
})

describe('mock backend: hosts and agents', () => {
  const h = () => ({ 'Content-Type': 'application/json', 'X-CSRF-Token': mock.state.session.csrf_token! })

  it('lists the gateway first, includes an EOL host and a silent agent, and the overview summary matches', async () => {
    const page = await (await fetch(`${BASE}/hosts`)).json() as { items: HostSummary[] }
    expect(page.items[0]!.id).toBe('local')
    expect(page.items.find(x => x.id === 'app-2')!.silent).toBe(true)
    expect(page.items.find(x => x.id === 'verein-alt')!.os!.eol).toBe('2022-09-10')
    const names = new Set(page.items.map(x => x.os?.name.split(' ')[0]).filter(Boolean))
    expect(names.size).toBeGreaterThanOrEqual(3)
    const ov = await (await fetch(`${BASE}/overview`)).json()
    expect(ov.servers).toEqual(serversSummary(mock.state.hosts, mock.state.now()))
    expect(ov.servers.silent).toBe(1)
  })

  it('runs the local check once at a time and only for the gateway', async () => {
    mock.state.hosts.checkRunMs = 0
    let res = await fetch(`${BASE}/hosts/local/check`, { method: 'POST', headers: h() })
    expect(res.status).toBe(202)
    mock.state.hosts.checkRunMs = 60_000
    res = await fetch(`${BASE}/hosts/local/check`, { method: 'POST', headers: h() })
    expect(res.status).toBe(202)
    res = await fetch(`${BASE}/hosts/local/check`, { method: 'POST', headers: h() })
    expect((await res.json()).code).toBe('check_running')
    mock.state.hosts.checkUnavailable = true
    mock.state.hosts.localRun = null
    res = await fetch(`${BASE}/hosts/local/check`, { method: 'POST', headers: h() })
    expect((await res.json()).code).toBe('check_unavailable')
  })

  it('enrols with a one-time code, rejects a wrong fingerprint and refuses to revoke config agents', async () => {
    mock.state.hosts.enrolDelayMs = 0
    const res = await fetch(`${BASE}/agents/enrolments`, { method: 'POST', headers: h(), body: JSON.stringify({ label: 'Wiki' }) })
    expect(res.status).toBe(201)
    const e = await res.json()
    expect(e.code).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/)
    expect(e.command).toContain(`--code ${e.code}`)
    expect(e.command).toContain(`--gateway-name ${e.gateway_name}`)
    const agents = (await (await fetch(`${BASE}/agents`)).json()).items as { id: string, status: string, fingerprint: string }[]
    const wiki = agents.find(a => a.id === 'wiki')!
    expect(wiki.status).toBe('pending')
    let r = await fetch(`${BASE}/agents/wiki/confirm`, { method: 'POST', headers: h(), body: JSON.stringify({ fingerprint: `sha256:${'0'.repeat(64)}` }) })
    expect((await r.json()).code).toBe('fingerprint_mismatch')
    r = await fetch(`${BASE}/agents/wiki/confirm`, { method: 'POST', headers: h(), body: JSON.stringify({ fingerprint: wiki.fingerprint }) })
    expect((await r.json()).status).toBe('enrolled')
    expect(mock.state.hosts.hosts.get('wiki')!.report).toBeNull()
    r = await fetch(`${BASE}/agents/app-2/revoke`, { method: 'POST', headers: h(), body: '{}' })
    expect((await r.json()).code).toBe('config_agent')
  })
})

describe('Server section without agents (2026-11-02, the default)', () => {
  it('shows the gateway only: no agent in the switcher, no "Server hinzufügen", no Agenten tab, ?server= ignored', async () => {
    const { wrapper } = await mountApp('/server/check?server=app-2&view=agents')
    await waitFor(() => !!byTestId('host-detail'))
    expect(document.querySelector('h1')!.textContent).toContain('web-1')
    expect(byTestId('add-server')).toBeNull()
    expect(byTestId('tab-agents')).toBeNull()
    expect(byTestId('check-now')).not.toBeNull()
    await click(byTestId('website-switcher')!)
    await waitFor(() => all('[data-testid="server-item"]').length > 0)
    expect(all('[data-testid="server-item"]')).toHaveLength(1)
    expect(byTestId('server-add')).toBeNull()
    wrapper.unmount()
  })
})

describe('Server section', () => {
  beforeAll(() => { FEATURES.hostAgents = true })
  afterAll(() => { FEATURES.hostAgents = false })
  it('shows the gateway first with its findings as one list, copyable fixes and the inventory', async () => {
    const { wrapper } = await mountApp('/server/check')
    await waitFor(() => !!byTestId('host-detail'))
    // Only the server the sidebar holds (2026-11-02): the gateway, no list of every server.
    expect(all('[data-testid="host-item"]')).toHaveLength(0)
    expect(byTestId('servers-meta')!.textContent).toContain('Gateway')
    expect(byTestId('servers-meta')!.textContent).not.toContain('meldet sich nicht')
    const areas = [...byTestId('filter-area')!.querySelectorAll('option')].slice(1).map(o => o.textContent!.trim())
    expect(areas).toEqual(['Distribution & Kernel', 'Updates', 'Offene Ports', 'Firewall', 'SSH', 'TLS', 'Logs'])
    expect(byTestId('inventory-section')!.querySelector('h3')!.textContent).toContain('Installierte Software')
    // One line per check, open findings first; the detail opens on click.
    const states = all('[data-testid="finding-row"]').map(x => x.getAttribute('data-state'))
    expect(states.length).toBeGreaterThan(5)
    expect(states).toEqual([...states].sort((a, b) => ['open', 'unreadable', 'accepted', 'ok'].indexOf(a!) - ['open', 'unreadable', 'accepted', 'ok'].indexOf(b!)))
    expect(byTestId('command-text')).toBeNull()
    const updates = rowsOf('updates').find(x => x.getAttribute('data-state') === 'open')!
    await click(updates.querySelector('[data-testid="finding-toggle"]'))
    expect(updates.querySelector('[data-testid="command-text"]')!.textContent).toBe('sudo apt-get update && sudo apt-get upgrade')
    expect(byTestId('inventory')!.querySelector('[data-eol="past"]')!.textContent).toContain('redis')
    expect(byTestId('check-now')).not.toBeNull()
    expect(bodyText()).not.toMatch(/geschützt|anonym|sicher\b/)
    wrapper.unmount()
  })

  it('shows an agent alone: its name, its state, only its own agent entry', async () => {
    const { wrapper } = await mountApp('/server/check?server=app-2')
    await waitFor(() => !!byTestId('host-detail'))
    expect(document.querySelector('h1')!.textContent).toContain('app-2')
    expect(byTestId('servers-meta')!.textContent).toContain('meldet sich nicht')
    expect(byTestId('add-server')).toBeNull()
    expect(byTestId('check-now')).toBeNull()
    wrapper.unmount()
    cleanup()
    await mountApp('/server/check?server=app-2&view=agents')
    await waitFor(() => all('[data-testid="agent-row"]').length > 0)
    expect(all('[data-testid="agent-row"]').map(r => r.getAttribute('data-agent'))).toEqual(['app-2'])
  })

  it('shows the logs area with config file fixes: path, content, copy button and how it applies (D38)', async () => {
    const { wrapper } = await mountApp('/server/check')
    await waitFor(() => rowsOf('logs').length > 0)
    const before = all('[data-testid="finding-row"]').length
    await type(byTestId('findings')!.querySelector('input[type="search"]'), 'journal')
    const total = before
    // The search looks at title, explanation and evidence, not only at what the line shows.
    await waitFor(() => all('[data-testid="finding-row"]').length > 0 && all('[data-testid="finding-row"]').length < total)
    expect(rowsOf('logs').length).toBeGreaterThan(0)
    expect(byTestId('finding-count')!.textContent).toMatch(/^\s*\d+ von \d+ Prüfungen/)
    await click(byTestId('filter-reset'))
    await expandAll()
    const area = byTestId('finding-list')!
    const fixes = all('[data-testid="finding-row"][data-area="logs"] [data-testid="fix-config"]')
    expect(fixes.length).toBeGreaterThanOrEqual(3)
    const paths = fixes.map(x => x.querySelector('[data-testid="fix-config-path"]')!.textContent!.trim())
    expect(paths).toContain('/etc/systemd/journald.conf.d/50-schild-size.conf')
    const journal = fixes[paths.indexOf('/etc/systemd/journald.conf.d/50-schild-size.conf')]!
    expect(journal.querySelector('[data-testid="command-text"]')!.textContent).toContain('SystemMaxUse=1024M')
    expect(journal.querySelector('[data-testid="command-copy"]')).not.toBeNull()
    // The restart command follows the file as "Danach ausführen".
    const card = journal.closest('[data-testid="finding-row"]')!
    expect(card.textContent).toContain('Danach ausführen')
    expect([...card.querySelectorAll('[data-testid="command-text"]')].map(c => c.textContent)).toContain('sudo systemctl restart systemd-journald')
    expect(area.textContent).toContain('Größe')
    expect(bodyText()).not.toMatch(/geschützt|anonym|sicher\b/)
    wrapper.unmount()
  })

  it('shows "nicht lesbar" with the reason, the silent banner and no "Jetzt prüfen" for agents', async () => {
    const { wrapper } = await mountApp('/server/check?server=app-1')
    await waitFor(() => all('[data-testid="finding-row"][data-state="unreadable"]').length > 0)
    await expandAll()
    expect(byTestId('unreadable-reason')!.textContent).toContain('Nicht lesbar: keine Leserechte, braucht CAP_NET_ADMIN')
    expect(byTestId('last-rejected')!.textContent).toContain('zu alt')
    expect(byTestId('check-now')).toBeNull()
    wrapper.unmount()
    const second = await mountApp('/server/check?server=app-2')
    await waitFor(() => !!byTestId('silent-banner'))
    expect(byTestId('silent-banner')!.textContent).toContain('Das ändert nichts am Grundschutz')
    second.wrapper.unmount()
  })

  it('shows agent findings with the catalogue text of the gateway and no copy for unverified commands', async () => {
    const { wrapper } = await mountApp('/server/check?server=app-1')
    await waitFor(() => !!byTestId('finding-row'))
    await expandAll()
    // The fixture's agent sends commands the gateway's own check does not produce.
    const unverified = all('[data-testid="unverified-fix"]')
    expect(unverified.length).toBeGreaterThan(0)
    for (const u of unverified) {
      expect(u.textContent).toContain('nicht geprüft')
      expect(u.querySelector('button')).toBeNull()
    }
    expect(all('[data-testid="command-text"]').map(c => c.textContent)).not.toContain('sudo apt-get update && sudo apt-get upgrade')
    // Free text of the agent is marked as such; the heading is the gateway's.
    expect(all('[data-testid="agent-text"]').some(p => p.textContent!.startsWith('Vom Agent gemeldet: '))).toBe(true)
    expect(bodyText()).toContain('Ausstehende Sicherheitsupdates')
    wrapper.unmount()
  })

  it('highlights the end-of-life host', async () => {
    const { wrapper } = await mountApp('/server/check?server=verein-alt')
    await waitFor(() => !!byTestId('os-support'))
    expect(byTestId('os-support')!.textContent).toContain('keine Sicherheitsupdates mehr')
    expect(all('[data-testid="finding-row"][data-severity="critical"]')).toHaveLength(2)
    expect(all('#main [data-eol="past"]').length).toBeGreaterThanOrEqual(3)
    wrapper.unmount()
  })

  it('"Jetzt prüfen" requests a run and shows the new report', async () => {
    mock.state.hosts.checkRunMs = 50
    const before = mock.state.hosts.hosts.get('local')!.report!.report_id
    const { wrapper } = await mountApp('/server/check')
    await waitFor(() => !!byTestId('check-now'))
    await click(byTestId('check-now'))
    expect(byTestId('check-now')!.textContent).toContain('Prüfung läuft')
    await waitFor(() => bodyText().includes('Prüfung fertig'), 6000)
    expect(mock.state.hosts.hosts.get('local')!.report!.report_id).not.toBe(before)
    expect(byTestId('check-now')!.textContent).toContain('Jetzt prüfen')
    wrapper.unmount()
  })

  it('enrols a new app server: command, wait, compare fingerprint, confirm', async () => {
    mock.state.hosts.enrolDelayMs = 0
    const { wrapper, router } = await mountApp('/server/check')
    await waitFor(() => !!byTestId('add-server'))
    await click(byTestId('add-server'))
    await type(byTestId('enrol-label'), 'Wiki')
    expect(router.currentRoute.value.name).toBe('server-check')
    await click(byTestId('enrol-create'))
    await waitFor(() => !!byTestId('enrol-command'))
    expect(byTestId('enrol-command')!.textContent).toMatch(/sudo schild-agent enrol --gateway https:\/\/gw-1\.example:8790 --gateway-name gw-1 --pin sha256:[0-9a-f]{64} --code /)
    await waitFor(() => !!byTestId('enrol-fingerprint'), 6000)
    const fp = mock.state.hosts.agents.find(a => a.id === 'wiki')!.fingerprint
    await type(byTestId('enrol-fingerprint-input'), `sha256:${'1'.repeat(64)}`)
    expect(byTestId('enrol-match')!.textContent).toContain('Stimmt nicht überein')
    expect(byTestId<HTMLButtonElement>('enrol-confirm')!.disabled).toBe(true)
    await type(byTestId('enrol-fingerprint-input'), fp.toUpperCase())
    expect(byTestId('enrol-match')!.textContent).toContain('Stimmt überein')
    await click(byTestId('enrol-confirm'))
    await waitFor(() => mock.state.hosts.agents.find(a => a.id === 'wiki')!.status === 'enrolled')
    await waitFor(() => router.currentRoute.value.query.server === 'wiki')
    await waitFor(() => !!byTestId('waiting-banner'))
    wrapper.unmount()
  })

  it('confirms a pending agent from the list', async () => {
    const { wrapper } = await mountApp('/server/check?view=agents')
    await waitFor(() => !!byTestId('agents-list'))
    const row = all('[data-testid="agent-row"]').find(r => r.getAttribute('data-agent') === 'app-4')!
    await click(row.querySelector('[data-testid="agent-confirm"]'))
    await waitFor(() => !!byTestId('enrol-fingerprint-input'))
    const fp = mock.state.hosts.agents.find(a => a.id === 'app-4')!.fingerprint
    await type(byTestId('enrol-fingerprint-input'), fp)
    await click(byTestId('enrol-confirm'))
    await waitFor(() => mock.state.hosts.agents.find(a => a.id === 'app-4')!.status === 'enrolled')
    wrapper.unmount()
  })

  it('revokes an agent after asking', async () => {
    const { wrapper } = await mountApp('/server/check?view=agents')
    await waitFor(() => !!byTestId('agents-list'))
    const row = all('[data-testid="agent-row"]').find(r => r.getAttribute('data-agent') === 'app-1')!
    await click(row.querySelector('[data-testid="agent-revoke"]'))
    expect(mock.state.hosts.agents.find(a => a.id === 'app-1')!.status).toBe('enrolled')
    await click(byTestId('confirm-submit'))
    await waitFor(() => mock.state.hosts.agents.find(a => a.id === 'app-1')!.status === 'revoked')
    // Agents from schild.yaml cannot be revoked here.
    const cfg = all('[data-testid="agent-row"]').find(r => r.getAttribute('data-agent') === 'app-2')!
    expect(cfg.querySelector('[data-testid="agent-revoke"]')).toBeNull()
    expect(cfg.textContent).toContain('Steht in schild.yaml')
    wrapper.unmount()
  })

  it('marks a finding as accepted with a note and opens it again (D102)', async () => {
    const { wrapper } = await mountApp('/server/check')
    const open = () => all('[data-testid="finding-row"][data-state="open"]')
    const acceptedRows = () => all('[data-testid="finding-row"][data-state="accepted"]')
    await waitFor(() => !!byTestId('host-detail') && open().length > 0)
    const local = () => mock.state.hosts.hosts.get('local')!
    const openBefore = open().length
    expect(acceptedRows()).toHaveLength(0)
    const first = open()[0]!
    await click(first.querySelector('[data-testid="finding-toggle"]'))
    const title = first.querySelector('[data-testid="finding"]')!.getAttribute('aria-label')!
    await click(first.querySelector('[data-testid="accept-open"]'))
    await waitFor(() => !!byTestId('accept-form'))
    // Nothing is accepted before the form is sent.
    expect(local().accepted).toHaveLength(0)
    await type(byTestId('accept-note'), 'Firewall des Hosters davor')
    await click(byTestId('accept-confirm'))
    await waitFor(() => local().accepted.length === 1 && acceptedRows().length === 1)
    expect(local().accepted[0]!.note).toBe('Firewall des Hosters davor')
    expect(open()).toHaveLength(openBefore - 1)
    // The line stays open under its new state, with the note and the way back.
    const accepted = acceptedRows()[0]!
    expect(accepted.textContent).toContain(title)
    expect(accepted.textContent).toContain('Akzeptiert')
    await waitFor(() => !!byTestId('accepted-note'))
    expect(byTestId('accepted-note')!.textContent).toContain('Firewall des Hosters davor')
    expect(byTestId('host-summary')!.textContent).toContain('1 Befund akzeptiert')
    // The state filter narrows the list to it.
    const select = byTestId('filter-state') as HTMLSelectElement
    select.value = 'accepted'
    select.dispatchEvent(new Event('change', { bubbles: true }))
    await waitFor(() => all('[data-testid="finding-row"]').length === 1)
    await click(byTestId('filter-reset'))
    await click(acceptedRows()[0]!.querySelector('[data-testid="reopen"]'))
    await waitFor(() => local().accepted.length === 0 && open().length === openBefore)
    expect(byTestId('finding-accepted')).toBeNull()
    wrapper.unmount()
  })

  it('explains agents when there are none yet', async () => {
    mock.reset({ scenario: 'empty' })
    const { wrapper } = await mountApp('/server/check')
    await waitFor(() => !!byTestId('waiting-banner'))
    expect(byTestId('waiting-banner')!.textContent).toContain('Noch kein Bericht')
    wrapper.unmount()
    const second = await mountApp('/server/check?view=agents')
    await waitFor(() => !!byTestId('agents-empty'))
    expect(byTestId('agents-empty')!.textContent).toContain('nur liest')
    expect(byTestId('agents-empty')!.textContent).toContain('bleibt auf deinen Servern')
    second.wrapper.unmount()
  })

  it('shows an error with retry and the not-configured state', async () => {
    mock.reset({ scenario: 'error' })
    const { wrapper } = await mountApp('/server/check')
    await waitFor(() => bodyText().includes('Die Server lassen sich gerade nicht laden'), 4000)
    expect(button('Erneut versuchen')).not.toBeNull()
    wrapper.unmount()
    mock.reset({})
    mock.state.hosts.configured = false
    const second = await mountApp('/server/check')
    await waitFor(() => !!byTestId('hostcheck-off'))
    second.wrapper.unmount()
  })

  it('puts a compact Server card on Allgemein', async () => {
    const { wrapper } = await mountApp('/settings')
    await waitFor(() => !!byTestId('servers-card'))
    expect(byTestId('servers-sentence')!.textContent).toMatch(/^5 Server im Blick, \d+ offene Befunde/)
    expect(byTestId('servers-silent')!.textContent).toContain('1 meldet sich nicht')
    wrapper.unmount()
  })
})
