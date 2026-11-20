import type { BotOverview, PageAlerts, RequestContext, RequestPage, RuleAlerts } from '../src/api/requests'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { resetMonitoringProbe } from '../src/api/monitoring'
import {
  contextIdOf,
  geoDbText,
  mapSteps,
  offsetText,
  pathText,
  REQUEST_OUTCOMES,
  requestTabOf,
  robotsText,
  verificationLabel,
} from '../src/lib/requests'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, waitFor } from './helpers'

/** MVP-22 "Zugriffe": request ring wording, the mock against the contract, the page and the Kontext drawer. */
const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer({ requestRing: true })
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
beforeEach(() => resetMonitoringProbe())
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({ requestRing: true })
  resetMonitoringProbe()
})
afterAll(() => mock.server.close())

const get = async <T>(path: string) => {
  const res = await fetch(`${BASE}${path}`)
  return { status: res.status, body: await res.json() as T }
}
const isoAgo = (ms: number) => new Date(Date.now() - ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
const fpEvent = () => mock.state.events.find(e => e.summary.path === '/mitglied-werden' && e.summary.rules?.includes('942100'))!.summary
const scanEvent = () => mock.state.events.find(e => e.summary.incident && e.summary.geo?.net_class === 'hosting' && Date.now() - Date.parse(e.summary.time) < 47 * 3600_000)!.summary

describe('wording (lib/requests)', () => {
  it('says Erkannt and Gesperrt, and names a bot that pretends to be another', () => {
    expect(REQUEST_OUTCOMES.would_block.label).toBe('Erkannt')
    expect(REQUEST_OUTCOMES.blocked_waf.label).toBe('Gesperrt')
    expect(REQUEST_OUTCOMES.blocked_behaviour.label).toBe('Gesperrt')
    expect(verificationLabel('mismatch', 'Googlebot')).toBe('gibt sich als Googlebot aus')
    expect(verificationLabel('verified')).toBe('bestätigt')
    expect(verificationLabel('claimed')).toBe('nicht prüfbar')
    expect(verificationLabel('unknown_stale')).toBe('Prüfliste veraltet')
    expect(robotsText({ respects: 'no', disallowed_requests: 3 })).toBe('nein, 3 Anfragen auf gesperrte Pfade')
    expect(robotsText({ respects: 'yes', disallowed_requests: 0 })).toBe('ja')
    expect(robotsText({ respects: 'unclear', disallowed_requests: 0 })).toBe('unklar')
  })

  it('formats offsets, tabs, ids, map steps and the geo database', () => {
    expect(offsetText('2026-10-29T10:00:00Z', '2026-10-29T10:02:15Z')).toBe('−2:15')
    expect(offsetText('2026-10-29T10:00:40Z', '2026-10-29T10:00:00Z')).toBe('+0:40')
    expect(requestTabOf('bots')).toBe('bots')
    expect(requestTabOf('nonsense')).toBe('overview')
    expect(contextIdOf('6F1C2A9E-3B7D-4C55-9A10-2E8F4D6B7C31')).toBe('6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c31')
    expect(contextIdOf('../etc')).toBeNull()
    const s = mapSteps([1, 10, 100, 1000, 100000])
    expect(s.stepOf(0)).toBe(-1)
    expect(s.stepOf(1)).toBe(0)
    expect(s.stepOf(100000)).toBe(4)
    expect(s.labels[0]).toBe('ab 1')
    expect(geoDbText({ provider: 'ipinfo', databases: ['ipinfo_lite'], built_at: '2026-10-01T00:00:00Z' })!.line).toBe('Geo-Daten: IPinfo, Stand 01.10.2026')
    expect(geoDbText({ provider: 'ipinfo', databases: [], built_at: '2026-10-01T00:00:00Z' })!.line).toBe('Geo-Daten: DB-IP Lite (mitgeliefert), Stand 01.10.2026; IPinfo ist noch nicht geladen')
    expect(geoDbText({ source: 'dbip-country-asn-lite-2026-10', built_at: '2026-10-01T00:00:00Z' })!.line).toBe('Geo-Daten: DB-IP Lite, Stand 01.10.2026')
    expect(geoDbText({ provider: 'maxmind', last_error: 'token_rejected' })!.error).toContain('bisherige Datenbank')
    expect(geoDbText(undefined)).toBeNull()
  })
})

describe('request ring mock follows the contract (MVP-22)', () => {
  it('pages requests by cursor without repeats, filters exactly, also by address', async () => {
    const q = `/requests?from=${isoAgo(3600_000)}&to=${isoAgo(0)}&site=verein.example&limit=40`
    const a = await get<RequestPage>(q)
    expect(a.status).toBe(200)
    expect(a.body.items.length).toBe(40)
    expect(a.body.next_cursor).toBeTruthy()
    expect(a.body.sample_rate).toBe(1)
    const b = await get<RequestPage>(`${q}&cursor=${encodeURIComponent(a.body.next_cursor!)}`)
    const key = (r: RequestPage['items'][number]) => `${r.t}|${r.visitor}|${r.path}`
    expect(b.body.items.some(r => a.body.items.map(key).includes(key(r)))).toBe(false)
    expect(Date.parse(b.body.items[0]!.t)).toBeLessThanOrEqual(Date.parse(a.body.items.at(-1)!.t))
    const ip = a.body.items[0]!.ip!
    const one = await get<RequestPage>(`/requests?from=${isoAgo(40 * 3600_000)}&to=${isoAgo(0)}&ip=${ip}&limit=100`)
    expect(one.body.items.length).toBeGreaterThan(0)
    expect(one.body.items.every(r => r.ip === ip)).toBe(true)
    const bing = await get<RequestPage>(`/requests?from=${isoAgo(40 * 3600_000)}&to=${isoAgo(0)}&user_agent=CHROME&limit=100`)
    expect(bing.body.items.length).toBeGreaterThan(0)
    expect(bing.body.items.every(r => /chrome/i.test(r.user_agent ?? ''))).toBe(true)
    expect(a.body.items.every(r => /^v1-[0-9a-f]{16}$/.test(r.visitor))).toBe(true)
    const bots = await get<RequestPage>(`/requests?from=${isoAgo(6 * 3600_000)}&to=${isoAgo(0)}&site=verein.example&bot=googlebot&verification=mismatch`)
    expect(bots.body.items.every(r => r.bot === 'googlebot' && r.verification === 'mismatch')).toBe(true)
  })

  it('answers 400 beyond 6 hours and 409 requests_off without the ring; the degraded gateway is sampled', async () => {
    expect((await get(`/requests?from=${isoAgo(7 * 3600_000)}&to=${isoAgo(0)}`)).status).toBe(400)
    mock.reset({ requestRing: false })
    const off = await get<{ code: string }>(`/requests?from=${isoAgo(3600_000)}&to=${isoAgo(0)}`)
    expect(off.status).toBe(409)
    expect(off.body.code).toBe('requests_off')
    mock.reset({ requestRing: true, scenario: 'degraded' })
    const s = await get<RequestPage>(`/requests?from=${isoAgo(3600_000)}&to=${isoAgo(0)}&site=verein.example`)
    expect(s.body.sample_rate).toBe(0.5)
  })

  it('gives the Kontext of a false positive (normal session) and of a scanner (alerts only)', async () => {
    const fp = await get<RequestContext>(`/requests/context/${fpEvent().id}`)
    expect(fp.status).toBe(200)
    expect(fp.body.state).toBe('complete')
    expect(fp.body.visitor_summary!.pattern).toBe('in_session')
    expect(fp.body.anchor!.event_id).toBe(fpEvent().id)
    expect(fp.body.site_strip).toHaveLength(61)
    const times = fp.body.visitor_requests.map(r => Date.parse(r.t))
    expect([...times].sort((x, y) => x - y)).toEqual(times)
    const scan = await get<RequestContext>(`/requests/context/${scanEvent().id}`)
    expect(scan.body.visitor_summary!.pattern).toBe('alert_only')
    expect((await get('/requests/context/00000000-0000-4000-8000-000000000000')).status).toBe(404)
  })

  it('has verified, pretending and stale bots, robots.txt behaviour and catalogue ages', async () => {
    const o = await get<BotOverview>(`/requests/bots?from=${isoAgo(86400_000)}&to=${isoAgo(0)}&site=verein.example`)
    expect(o.status).toBe(200)
    const google = o.body.bots.find(b => b.id === 'googlebot')!
    expect(google.verification.mismatch).toBeGreaterThan(0)
    expect(o.body.bots.find(b => b.id === 'amazonbot')!.verification.unknown_stale).toBeGreaterThan(0)
    expect(o.body.bots.find(b => b.id === 'bytespider')!.robots!.respects).toBe('no')
    expect(o.body.ranges.some(r => r.stale)).toBe(true)
    expect(o.body.catalogue_version).toMatch(/^20\d\d-\d\d-\d\d\.\d+$/)
  })

  it('marks the false positive rule and the review page of verein.example', async () => {
    const r = await get<RuleAlerts>(`/requests/alerts/rules?from=${isoAgo(86400_000)}&to=${isoAgo(0)}&site=verein.example`)
    const fp = r.body.items.find(x => x.rule_id === '942100')!
    expect(fp.possible_false_positive).toBe(true)
    expect(fp.clients.in_session).toBeGreaterThan(fp.clients.alert_only)
    expect(r.body.items.filter(x => x.possible_false_positive).map(x => x.rule_id)).toEqual(['942100'])
    const p = await get<PageAlerts>(`/requests/alerts/pages?from=${isoAgo(86400_000)}&to=${isoAgo(0)}&site=verein.example`)
    expect(p.body.items.find(x => x.path === '/mitglied-werden')!.review).toBe(true)
    expect(p.body.items.find(x => x.path === '/')!.review).toBe(false)
  })
})

describe('Zugriffe page', () => {
  it('Überblick shows the KPI row, the main chart, Letzte Alarme, map, donuts and top lists (D68)', async () => {
    const { router } = await mountApp('/w/verein.example')
    await waitFor(() => !!document.querySelector('[data-kpi="requests"] [data-slot="kpi-value"]')?.textContent?.match(/\d/), 4000)
    expect(document.querySelector('[data-tab="overview"]')!.getAttribute('aria-selected')).toBe('true')
    expect(document.querySelector('h1')!.textContent).toBe('Zugriffe')
    await waitFor(() => !!document.querySelector('[data-testid="main-chart"] svg[role="img"]'), 4000)
    await waitFor(() => !!document.querySelector('[data-testid="alerts-card"] [data-alert]'), 4000)
    expect(byTestId('alerts-to-events')!.getAttribute('href')).toBe('/w/verein.example/events')
    expect(document.querySelector('[data-testid="alerts-card"] [data-alert]')!.getAttribute('href')).toMatch(/^\/w\/verein\.example\/events\?event=/)
    // The old Zugriffe KPIs and visitors chart are gone: the KPI row and the main chart cover them.
    expect(byTestId('traffic-kpis')).toBeNull()
    expect(byTestId('visitors-chart')).toBeNull()
    await waitFor(() => !!document.querySelector('[data-testid="overview-countries"] path[data-country="DE"]'), 4000)
    for (const id of ['donut-bots', 'donut-device', 'donut-browser', 'donut-os', 'donut-status', 'donut-new-returning']) {
      await waitFor(() => !!document.querySelector(`[data-testid="${id}"] [data-slot="donut-chart"]`), 4000)
    }
    expect(byTestId('donut-bots')!.textContent).toContain('KI-Crawler')
    await waitFor(() => !!document.querySelector('[data-testid="overview-sources"] [data-row="ai:chatgpt"] [data-slot="bar-tag"]'), 4000)
    expect(byTestId('overview-security')!.querySelector('[data-testid="overview-to-events"]')!.getAttribute('href')).toBe('/w/verein.example/events')
    // Alarme nach Regel lives on Ereignisse.
    expect(document.querySelector('[data-testid="rule-alerts"]')).toBeNull()
    await click(document.querySelector('[data-testid="donut-device"] [data-row="mobile"] button'))
    await waitFor(() => String(router.currentRoute.value.query.filter) === 'device:mobile')
    await click(document.querySelector('[data-testid="donut-bots"] [data-row="ai"] button'))
    await waitFor(() => router.currentRoute.value.query.view === 'bots')
  })

  it('Ereignisse lists the rules with the false-positive exception; a rule opens its requests on Zugriffe', async () => {
    const { router } = await mountApp('/w/verein.example/events')
    await waitFor(() => !!document.querySelector('[data-rule="942100"] button[aria-pressed]'), 4000)
    await click(document.querySelector('[data-rule="942100"] button[aria-pressed]'))
    await waitFor(() => router.currentRoute.value.path === '/w/verein.example')
    expect(router.currentRoute.value.query).toEqual({ view: 'requests', time: '48h', filter: 'rule:942100' })
    cleanup()

    await mountApp('/w/verein.example/events')
    await waitFor(() => !!document.querySelector('[data-rule="942100"] [data-testid="rule-fp"]'), 4000)
    await click(document.querySelector('[data-rule="942100"] [data-testid="rule-fp"]'))
    await waitFor(() => !!byTestId('rule-fp-detail'))
    expect(byTestId('rule-fp-detail')!.textContent).toContain('rules.d/50-exceptions-verein.example.conf')
    expect(byTestId('rule-fp-detail')!.textContent).toContain('Gilt nur für die Adressen dieser Website')
  })

  it('Länder draws the built-in map and a click on a country filters the page', async () => {
    const { router } = await mountApp('/w/verein.example?view=countries')
    await waitFor(() => !!document.querySelector('[data-testid="world-map"] path[data-country="DE"]'), 4000)
    expect(byTestId('geo-db')!.textContent).toContain('Geo-Daten: DB-IP Lite, Stand')
    await click(document.querySelector('[data-testid="countries-tab"] [data-row="NL"] button'))
    await waitFor(() => String(router.currentRoute.value.query.filter) === 'country:NL')
    await waitFor(() => !!document.querySelector('[data-filter="country:NL"]'))
  })

  it('Bots & KI-Crawler names the verification states and the robots.txt verdict', async () => {
    await mountApp('/w/verein.example?view=bots')
    await waitFor(() => !!byTestId('bots-table'), 4000)
    const table = byTestId('bots-table')!.textContent!
    expect(table).toContain('gibt sich als Googlebot aus')
    expect(table).toContain('Prüfliste veraltet')
    expect(table).toContain('nicht prüfbar')
    expect(document.querySelector('[data-bot="bytespider"] [data-robots="no"]')).toBeTruthy()
    expect(byTestId('bots-catalogue')!.textContent).toContain('(veraltet)')
    expect(bodyText()).toContain('legst du unter')
  })

  it('Anfragen lists requests and opens the Kontext of a row with an event', async () => {
    const fp = fpEvent()
    const hoursAgo = Math.floor((Date.now() - Date.parse(fp.time)) / 3600_000 / 6) * 6
    const { router } = await mountApp(`/w/verein.example?view=requests&window=6h&until=${hoursAgo}&filter=path:/mitglied-werden&outcome=would_block`)
    await waitFor(() => (byTestId('request-list')?.querySelectorAll('tbody tr').length ?? 0) > 0, 4000)
    const row = [...byTestId('request-list')!.querySelectorAll<HTMLElement>('tbody tr')].find(r => r.textContent?.includes('Kontext'))!
    expect(row).toBeTruthy()
    await click(row)
    await waitFor(() => typeof router.currentRoute.value.query.context === 'string')
    await waitFor(() => !!byTestId('context-pattern'), 4000)
    expect(byTestId('context-pattern')!.textContent).toContain('Alarm mitten in normaler Nutzung')
  })

  it('a row of Anfragen has the menu of its address, and the menu does not open the row', async () => {
    const { router } = await mountApp('/w/verein.example?view=requests&window=6h')
    await waitFor(() => !!byTestId('row-more'), 4000)
    await click(byTestId('row-more'))
    await waitFor(() => !!byTestId('row-block-ip'))
    expect(byTestId('row-block-ip')!.textContent).toMatch(/IP für (7 Tage|24 Stunden) sperren/)
    expect(byTestId('row-allow-ip')!.textContent).toContain('Zu Eigene IPs hinzufügen')
    expect(router.currentRoute.value.query.context).toBeUndefined()
    await click(byTestId('row-block-other'))
    await waitFor(() => !!byTestId('block-dialog'))
    expect(byTestId<HTMLInputElement>('block-reason')!.value).toContain('Anfrage an')
  })

  it('without the ring explains it calmly and keeps the counted tabs', async () => {
    mock.reset({ requestRing: false })
    await mountApp('/w/verein.example?view=requests')
    await waitFor(() => !!byTestId('ring-off'))
    expect(byTestId('ring-off')!.textContent).toContain('Das Zugriffsprotokoll ist ausgeschaltet')
    expect(byTestId('request-list')).toBeNull()
  })

  it('explains combined filters beyond 48 hours on the timeline', async () => {
    await mountApp('/w/verein.example?time=7d&filter=country:US&filter=net_class:hosting')
    await waitFor(() => !!byTestId('filter-unavailable-page'), 4000)
    cleanup()
    await mountApp('/w/verein.example?view=requests&time=7d&filter=country:US&filter=net_class:hosting')
    await waitFor(() => !!byTestId('timeline-unavailable'), 4000)
    expect(byTestId('timeline-unavailable')!.textContent).toContain('einzelnen Anfragen')
  })
})

describe('Kontext drawer', () => {
  it('opens from ?context on any page with the anchor highlighted and the sites affected', async () => {
    const scan = scanEvent()
    await mountApp(`/incidents?context=${scan.id}`)
    await waitFor(() => !!byTestId('context-pattern'), 4000)
    expect(byTestId('context-pattern')!.textContent).toContain('nur Alarme, wirkt wie ein Scanner')
    expect(document.querySelector('[data-testid="context-requests"] [data-anchor="true"]')!.textContent).toContain('dieses Ereignis')
    expect(byTestId('context-sites')!.textContent).toMatch(/betrifft \d von 4 Websites/)
    expect(byTestId('site-strip')).toBeTruthy()
  })

  it('says when the window is older than 48 hours, and Letzte Alarme offer it', async () => {
    // An event from three days ago: its window has left the 48 h ring.
    const old = mock.state.events.find(e => e.summary.type.startsWith('schild.request.') && !e.summary.incident)!.summary
    old.time = new Date(Date.now() - 3 * 86400_000).toISOString()
    await mountApp(`/events?context=${old.id}`)
    await waitFor(() => !!byTestId('context-state'), 4000)
    expect(byTestId('context-state')!.textContent).toContain('nicht mehr gespeichert')
    cleanup()
    await mountApp('/w/verein.example')
    await waitFor(() => !!byTestId('alert-context'), 4000)
  })

  it('shows Geo-Daten on Allgemein', async () => {
    await mountApp('/settings')
    await waitFor(() => !!byTestId('geo-db'))
    expect(byTestId('geo-db')!.textContent).toContain('Geo-Daten: DB-IP Lite, Stand')
  })
})

describe('pathText (D63)', () => {
  it('decodes letters, keeps what changes the path or the reading order escaped', () => {
    expect(pathText('/%C3%BCber-uns')).toBe('/über-uns')
    expect(pathText('/a%2Fb')).toBe('/a%2Fb')
    expect(pathText('/x%3Fy')).toBe('/x%3Fy')
    expect(pathText('/n%00ul')).toBe('/n%00ul')
    expect(pathText('/%E2%80%AEgnp.exe')).toBe('/%E2%80%AEgnp.exe')
    expect(pathText('/kaputt%E2')).toBe('/kaputt%E2')
    expect(pathText('/blog/{slug}')).toBe('/blog/{slug}')
  })
})
