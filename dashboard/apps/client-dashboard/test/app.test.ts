import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import type { HostSummary } from '../src/api/hosts'
import { FEATURES } from '../src/lib/hosts'
import { buildNav, serverEntries, serverPages, serverWarning } from '../src/lib/nav'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, settle, type, waitFor } from './helpers'

const SERVER = { node: 'web-1', this: true, status: 'ok' as const, baseline_protection: 'active' as const, hints: [] }
const base = {}
const host = (id: string, status: HostSummary['status'], high = 0) => ({ id, hostname: id, role: 'agent', status, silent: false, counts: { critical: 0, high, medium: 0, low: 0, info: 0 } }) as HostSummary
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  mock.reset({})
})
afterAll(() => mock.server.close())

describe('client dashboard shell', () => {
  it('builds the sidebar: pages of the held website, Schutz, Einstellungen, no servers (D36, 2026-11-01)', () => {
    const nav = buildNav({ ...base, site: '' })
    // "Alle Websites" holds no website: no website pages, only the events of every website (D68).
    expect(nav.map(g => g.label)).toEqual([undefined, 'Schutz · alle Websites', 'Einstellungen'])
    expect(nav[0]!.items.map(i => [i.label, i.to])).toEqual([['Ereignisse', '/events']])
    expect(nav[1]!.items.map(i => i.label)).toEqual(['Regeln', 'Sperren', 'Eigene IPs'])
    expect(nav[2]!.items.map(i => i.label)).toEqual(['Allgemein', 'Datenschutz'])
    expect(nav.flatMap(g => g.items.map(i => i.to))).not.toContain('/server')
  })

  it('lists the gateway, then the agents by name, without withdrawn ones', () => {
    expect(serverEntries('web-1', SERVER, [host('db-2', 'findings', 1)]).map(s => s.label)).toEqual(['web-1'])
    FEATURES.hostAgents = true
    const list = serverEntries('web-1', SERVER, [host('local', 'ok'), host('db-2', 'findings', 1), host('app-1', 'ok'), host('old-1', 'revoked')].map((h, i) => i ? h : { ...h, role: 'gateway' as const }))
    expect(list.map(s => [s.label, s.to])).toEqual([
      ['web-1', '/server'],
      ['app-1', '/server/check?server=app-1'],
      ['db-2', '/server/check?server=db-2'],
    ])
    expect(serverWarning(list)).toEqual({ tone: 'danger', label: '1 Server braucht einen Blick' })
    expect(serverWarning(list.slice(0, 2))).toBeNull()
    expect(serverEntries('', undefined)).toEqual([{ id: 'local', label: 'Server', to: '/server' }])
    FEATURES.hostAgents = false
  })

  it('lists the pages of a server instead of a website (2026-11-02)', () => {
    const nav = buildNav({ ...base, site: 'app-b.example', server: 'local' })
    expect(nav[0]!.items.map(i => [i.label, i.to])).toEqual([['Überblick', '/server'], ['Auslastung', '/server/load'], ['Server-Check', '/server/check']])
    expect(serverPages('db-2').map(i => [i.label, i.to])).toEqual([['Server-Check', '/server/check?server=db-2']])
  })

  it('switches to a server in the sidebar switcher; no server menu at the top right', async () => {
    const { router } = await mountApp('/w/shop.example')
    await waitFor(() => byTestId('switcher-title')?.textContent === 'shop.example')
    expect(byTestId('server-switcher')).toBeNull()
    await click(byTestId('website-switcher')!)
    await waitFor(() => document.querySelectorAll('[data-testid="server-item"]').length === 1)
    await click(document.querySelector('[data-testid="server-item"]')!)
    await waitFor(() => router.currentRoute.value.path === '/server')
    await waitFor(() => byTestId('switcher-title')?.textContent !== 'shop.example')
    expect(document.querySelector('[data-nav-item="/server/load"]')).not.toBeNull()
    expect(document.querySelector('[data-nav-item="/w/shop.example/events"]')).toBeNull()
    // Back to a website: its pages return.
    await click(byTestId('website-switcher')!)
    await waitFor(() => document.querySelectorAll('[data-testid="switcher-item"]').length > 1)
    const shop = [...document.querySelectorAll('[data-testid="switcher-item"]')].find(a => a.textContent?.includes('shop.example'))!
    await click(shop as HTMLElement)
    await waitFor(() => byTestId('switcher-title')?.textContent === 'shop.example')
    expect(document.querySelector('[data-nav-item="/server/load"]')).toBeNull()
  })

  it('lists the pages of one website, then its settings (D68)', () => {
    const nav = buildNav({ ...base, site: 'app-b.example' })
    expect(nav[0]!.items.map(i => [i.label, i.to])).toEqual([
      ['Zugriffe', '/w/app-b.example'],
      ['Ereignisse', '/w/app-b.example/events'],
      ['Zugriffsschutz', '/w/app-b.example/access'],
      ['KI-Crawler', '/w/app-b.example/ai-crawlers'],
    ])
    // Zugriffe is the start page: active only on /w/<id> itself; ⌘K finds it under the old names too.
    expect(nav[0]!.items[0]!.exact).toBe(true)
    expect(nav[0]!.items[0]!.keywords).toEqual(expect.arrayContaining(['überblick', 'anfragen']))
    expect(nav[0]!.items[1]!.keywords).toEqual(expect.arrayContaining(['alarme', 'vorfälle']))
  })

  it('never lists the styleguide (hidden page, reachable by URL only)', () => {
    expect(buildNav({ ...base, site: '' }).flatMap(g => g.items.map(i => i.to))).not.toContain('/styleguide')
  })

  it('holds one website in the switcher and keeps the sub-page when switching', async () => {
    const { router } = await mountApp('/')
    await waitFor(() => byTestId('switcher-title')?.textContent === 'Alle Websites')
    await waitFor(() => !!byTestId('switcher-others'))
    expect([...document.querySelectorAll('nav a')].map(a => a.textContent?.trim())).not.toContain('Zugriffe')
    expect(document.querySelector('[data-nav-item="/events"]')).not.toBeNull()
    await router.push('/w/verein.example/events')
    await waitFor(() => byTestId('switcher-title')?.textContent === 'verein.example')
    expect(document.querySelector('[data-nav-item="/w/verein.example/events"] a')?.getAttribute('aria-current')).toBe('page')
    expect(document.querySelector('[data-nav-item="/w/verein.example"] a')?.getAttribute('aria-current')).toBeNull()
    expect(document.querySelector('[data-nav-item="/events"]')).toBeNull()
    await click(byTestId('website-switcher')!)
    await waitFor(() => document.querySelectorAll('[data-testid="switcher-item"]').length === 4)
    expect(byTestId('switcher-filter')).toBeNull()
    const shop = [...document.querySelectorAll('[data-testid="switcher-item"]')].find(a => a.textContent?.includes('shop.example'))!
    expect(shop.getAttribute('href')).toMatch(/\/w\/shop\.example\/events$/)
    await click(shop)
    await waitFor(() => router.currentRoute.value.path === '/w/shop.example/events')
    // On a page of the server the switcher holds the server and the sidebar its pages (2026-11-02).
    await router.push('/server/load')
    await settle()
    expect(byTestId('switcher-title')?.textContent).toBe('web-1')
    expect(document.querySelector('[data-nav-item="/w/shop.example/events"]')).toBeNull()
    expect(document.querySelector('[data-nav-item="/behaviour"]')).toBeNull()
    // A website lists only its own pages; what holds for all websites stands under "Alle Websites" (2026-11-15).
    await router.push('/w/shop.example/events')
    await settle()
    for (const global of ['/blocks', '/own-ips', '/settings', '/settings/rules'])
      expect(document.querySelector(`[data-nav-item="${global}"]`)).toBeNull()
    await router.push('/own-ips')
    await settle()
    expect(byTestId('switcher-title')?.textContent).toBe('Alle Websites')
    expect(document.querySelector('[data-nav-item="/w/shop.example/events"]')).toBeNull()
    for (const global of ['/events', '/blocks', '/own-ips', '/settings'])
      expect(document.querySelector(`[data-nav-item="${global}"]`)).not.toBeNull()
  })

  it('opens the events of one website on its own page (D68)', async () => {
    const { router } = await mountApp('/events?website=blog.example&outcome=blocked')
    await waitFor(() => router.currentRoute.value.path === '/w/blog.example/events')
    expect(router.currentRoute.value.query).toEqual({ outcome: 'blocked' })
    await router.push('/events?outcome=blocked')
    await settle()
    expect(router.currentRoute.value.path).toBe('/events')
  })

  it('shows "Alle Websites" with its Ereignisse entry on the events of all websites (D68)', async () => {
    const { router } = await mountApp('/w/shop.example')
    await waitFor(() => byTestId('switcher-title')?.textContent === 'shop.example')
    expect([...document.querySelectorAll('[data-nav-item^="/w/shop.example"] a')].slice(0, 2).map(a => a.textContent?.trim())).toEqual(['Zugriffe', 'Ereignisse'])
    expect(document.querySelector('[data-nav-item="/w/shop.example"] a')?.getAttribute('aria-current')).toBe('page')
    await router.push('/events')
    await waitFor(() => byTestId('switcher-title')?.textContent === 'Alle Websites')
    expect(document.querySelector('[data-nav-item="/events"] a')?.getAttribute('aria-current')).toBe('page')
    expect(document.querySelector('[data-nav-item^="/w/"]')).toBeNull()
  })

  it('renders the shell without a mode and navigates', async () => {
    const { wrapper, router } = await mountApp('/incidents')
    // The list of incidents is the tab Gestoppte Anfragen of Sperren (2026-11-18).
    expect(wrapper.get('h1').text()).toBe('Sperren')
    expect(router.currentRoute.value.fullPath).toBe('/blocks?view=requests')
    await router.push('/own-ips')
    await settle()
    expect(wrapper.get('a[aria-current="page"]').text()).toContain('Eigene IPs')
    // D89: no mode in the header, and no test profile banner outside the test profile.
    expect(document.querySelector('[data-testid="mode-indicator"], [data-testid="test-profile-banner"]')).toBeNull()
    // The running version at the foot of the sidebar, without the leading "schild".
    expect(byTestId('sidebar-version')!.textContent!.trim()).toBe('Version 0.1.0-alpha')
    await router.push('/gibt-es-nicht')
    await settle()
    expect(wrapper.get('h1').text()).toBe('Seite nicht gefunden')
    wrapper.unmount()
  })

  it('renders the styleguide', async () => {
    const { wrapper } = await mountApp('/styleguide')
    expect(wrapper.get('h1').text()).toBe('Styleguide')
    expect(wrapper.text()).toContain('Grundschutz aktiv')
    wrapper.unmount()
  })
})

describe('auth', () => {
  it('sends first-run to the setup wizard and completes it', async () => {
    mock.reset({ scenario: 'first-run' })
    const { wrapper, router } = await mountApp('/events')
    expect(router.currentRoute.value.name).toBe('setup')
    await type(byTestId('setup-code'), 'K7QM4XWD')
    await type(byTestId('setup-password'), 'kurz')
    await type(byTestId('setup-repeat'), 'kurz')
    wrapper.get('form').trigger('submit')
    await settle()
    expect(bodyText()).toContain('Mindestens 12 Zeichen')
    await type(byTestId('setup-password'), 'ein langes passwort 42')
    await type(byTestId('setup-repeat'), 'ein langes passwort 42')
    wrapper.get('form').trigger('submit')
    // D89: no mode to choose; step 2 is the own IP, allowed by default.
    await waitFor(() => bodyText().includes('Nicht selbst aussperren'))
    expect(mock.state.session.authenticated).toBe(true)
    expect(bodyText()).not.toMatch(/Modus|Wie soll Schild arbeiten/)
    expect(byTestId<HTMLButtonElement>('setup-finish')!.disabled).toBe(false)
    await click(byTestId('setup-finish'))
    await waitFor(() => router.currentRoute.value.name === 'websites')
    expect(mock.state.myIp.allowlisted).toBe(true)
    wrapper.unmount()
  })

  it('redirects to login, shows a calm error and returns to the page', async () => {
    mock.reset({ scenario: 'login' })
    const { wrapper, router } = await mountApp('/privacy')
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.next).toBe('/privacy')
    await type(byTestId('login-password'), 'falsch')
    wrapper.get('form').trigger('submit')
    await waitFor(() => bodyText().includes('Das Passwort stimmt nicht'))
    await type(byTestId('login-password'), 'mock-passwort-123')
    wrapper.get('form').trigger('submit')
    await waitFor(() => router.currentRoute.value.path === '/privacy')
    wrapper.unmount()
  })
})
