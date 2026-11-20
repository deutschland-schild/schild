import type { SeriesResult } from '../src/api/monitoring'
import type { AlertFeed, AnnotationList, IncidentPage, WebsiteKpis, WebsiteList } from '../src/api/websites'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { containsIpLiteral } from '../src/lib/ip'
import { subpageOf, websitePath } from '../src/lib/nav'
import { annotationLink, blockWhy, changeText, filterChip, fillQuietBuckets, filtersFromQuery, reasonText, ruleCategoryOf, searchFilter } from '../src/lib/websites'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, waitFor } from './helpers'

const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

const get = async <T>(path: string) => {
  const res = await fetch(`${BASE}${path}`)
  return { status: res.status, body: await res.json() as T }
}
const isoAgo = (ms: number) => new Date(Date.now() - ms).toISOString().replace(/\.\d{3}Z$/, 'Z')

describe('websites mock follows the contract (D36)', () => {
  it('lists four websites on one server with status, reasons and numbers', async () => {
    const r = await get<WebsiteList>('/websites')
    expect(r.status).toBe(200)
    expect(r.body.node).toBe('web-1')
    expect(r.body.websites.map(w => w.id)).toEqual(['verein.example', 'praxis.example', 'shop.example', 'blog.example'])
    const shop = r.body.websites.find(w => w.id === 'shop.example')!
    expect(shop.status).toBe('attention')
    expect(shop.reasons.map(x => x.hint)).toContain('upstream_slow')
    expect(r.body.websites.every(w => w.runs_on[0]!.node === 'web-1' && w.now !== null)).toBe(true)
    expect(r.body.websites.every(w => /\.example$/.test(w.id))).toBe(true)
    expect(containsIpLiteral(r.body)).toBe(false)
  })

  it('marks a degraded website as gestört and server hints at every website', async () => {
    mock.reset({ scenario: 'degraded' })
    const r = await get<WebsiteList>('/websites')
    expect(r.body.websites.find(w => w.id === 'shop.example')!.status).toBe('disrupted')
    expect(r.body.websites.every(w => w.reasons.some(x => x.code === 'server_hint' && x.hint === 'disk_full_soon'))).toBe(true)
  })

  it('answers KPIs with the previous period and 409 filter_unavailable for combined filters beyond 48 h', async () => {
    const k = await get<WebsiteKpis>(`/websites/verein.example/kpis?from=${isoAgo(86400_000)}&to=${isoAgo(0)}`)
    expect(k.status).toBe(200)
    expect(k.body.current.requests.value).toBeGreaterThan(0)
    expect(k.body.previous.requests.value).toBeGreaterThan(0)
    expect(k.body.current.visitors.exact).toBe(false)
    const one = await get<WebsiteKpis>(`/websites/verein.example/kpis?from=${isoAgo(7 * 86400_000)}&to=${isoAgo(0)}&filter=country:US`)
    expect(one.status).toBe(200)
    expect(one.body.current.visitors.unavailable).toBe('filter_needs_requests')
    const two = await get<{ code: string }>(`/websites/verein.example/kpis?from=${isoAgo(7 * 86400_000)}&to=${isoAgo(0)}&filter=country:US&filter=net_class:hosting`)
    expect(two.status).toBe(409)
    expect(two.body.code).toBe('filter_unavailable')
  })

  it('merges 14 days into 30 min points and marks the partial last point', async () => {
    const r = await get<SeriesResult>(`/monitoring/series?metric=traffic.requests&from=${isoAgo(14 * 86400_000)}&resolution=auto&site=verein.example`)
    expect(r.status).toBe(200)
    expect(r.body.step_s).toBe(1800)
    expect(r.body.buckets_per_point).toBe(3)
    expect(r.body.points).toBeLessThanOrEqual(1000)
    expect(r.body.partial?.at(-1)).toBe(true)
  })

  it('has the wave, the 7-day block and gateway-wide markers as annotations', async () => {
    const a = await get<AnnotationList>(`/websites/verein.example/annotations?from=${isoAgo(86400_000)}&to=${isoAgo(0)}`)
    const kinds = a.body.items.map(x => x.kind)
    expect(kinds).toEqual(expect.arrayContaining(['wave_detected', 'block_long', 'wave_ended', 'config_changed']))
    const block = a.body.items.find(x => x.kind === 'block_long')!
    expect(blockWhy(block)).toBe('Rechenzentrum, wiederholt')
    const other = await get<AnnotationList>(`/websites/blog.example/annotations?from=${isoAgo(86400_000)}&to=${isoAgo(0)}`)
    expect(other.body.items.map(x => x.kind)).toEqual(['rule_repository_changed', 'config_changed'])
  })

  it('serves Letzte Alarme of one website with pseudonyms only, and incidents with sites_affected', async () => {
    const r = await get<AlertFeed>(`/websites/verein.example/alerts?from=${isoAgo(86400_000)}&to=${isoAgo(0)}`)
    expect(r.body.items.length).toBeGreaterThan(0)
    expect(r.body.items.every(i => !i.client_pseudonym || /^p1-[0-9a-f]{16}$/.test(i.client_pseudonym))).toBe(true)
    expect(containsIpLiteral(r.body)).toBe(false)
    const inc = await get<IncidentPage>('/incidents?site=verein.example')
    const long = inc.body.items.find(i => i.incident === 'R4ZC-9HTK')!
    expect(long.sites_affected).toEqual({ sites: ['verein.example', 'shop.example', 'blog.example'], count: 3, total: 4 })
    expect(inc.body.items.every(i => i.site === 'verein.example')).toBe(true)
  })
})

describe('website wording and paths', () => {
  it('maps rule ids, changes, reasons, filters and paths', () => {
    expect(ruleCategoryOf('942100')).toBe('sqli')
    expect(ruleCategoryOf('930120')).toBe('lfi')
    expect(ruleCategoryOf('1000010')).toBe('local')
    expect(changeText(112, 100)).toEqual({ text: '+12 %', dir: 'up' })
    expect(changeText(0, 0)).toEqual({ text: 'gleich', dir: 'flat' })
    expect(reasonText({ code: 'server_hint', node: 'web-1', hint: 'disk_full_soon' })).toBe('web-1: Platte fast voll')
    expect(filtersFromQuery(['country:DE', 'bogus', 'country:DE', 'path:/kontakt'])).toEqual(['country:DE', 'path:/kontakt'])
    // D64: address and User-Agent are page filters.
    expect(filtersFromQuery(['ip:192.0.2.10', 'ip:nope', 'user_agent:bingbot'])).toEqual(['ip:192.0.2.10', 'user_agent:bingbot'])
    expect(searchFilter(' 2001:db8::1 ')).toBe('ip:2001:db8::1')
    expect(searchFilter('Bingbot')).toBe('user_agent:Bingbot')
    expect(searchFilter('  ')).toBeNull()
    expect(filterChip('user_agent:bingbot')).toMatchObject({ label: 'User-Agent', value: 'bingbot' })
    expect(websitePath('verein.example', 'events')).toBe('/w/verein.example/events')
    expect(subpageOf('/w/verein.example/events')).toBe('events')
    // A grouped incident marker opens the incidents on the website's Ereignisse, a single one its Vorfall.
    expect(annotationLink({ t: '2026-11-05T10:00:00Z', kind: 'incident', count: 3 }, 'verein.example')).toBe('/w/verein.example/events')
    expect(annotationLink({ t: '2026-11-05T10:00:00Z', kind: 'incident', ref: 'R4ZC-9HTK' }, 'verein.example')).toBe('/incidents/R4ZC-9HTK')
    expect(annotationLink({ t: '2026-11-05T10:00:00Z', kind: 'incident', count: 3 })).toBe('/blocks?view=requests')
    expect(subpageOf('/w/verein.example')).toBe('')
    expect(subpageOf('/')).toBeNull()
    expect(subpageOf('/server')).toBeNull()
    expect(websitePath('')).toBe('/')
  })
})

describe('website pages', () => {
  it('shows the stored 24 hour numbers of a website right after a restart, before its first request', async () => {
    mock.state.monitoring.restarted = true
    await mountApp('/')
    await waitFor(() => document.querySelectorAll('[data-testid="website-card"]').length === 4)
    const shop = document.querySelector('[data-website="shop.example"]')!
    await waitFor(() => /\d/.test(shop.querySelector('[data-testid="card-requests"]')?.textContent ?? ''))
    expect(shop.textContent).not.toContain('Noch keine Messwerte.')
  })

  it('Alle Websites shows one card per website with status and where it runs', async () => {
    await mountApp('/')
    await waitFor(() => document.querySelectorAll('[data-testid="website-card"]').length === 4)
    const shop = document.querySelector('[data-website="shop.example"]')!
    expect(shop.textContent).toContain('bitte ansehen')
    expect(shop.textContent).toContain('läuft auf diesem Server')
    // The numbers are the last 24 hours (a small website's last minute is mostly empty), p95 in words.
    await waitFor(() => /\d/.test(shop.querySelector('[data-testid="card-requests"]')!.textContent!))
    expect(shop.textContent).toContain('Anfragen 24 h')
    expect(shop.textContent).not.toContain('p95')
    expect(document.querySelector('h1')!.textContent).toBe('Alle Websites')
    expect(byTestId('website-switcher')).not.toBeNull()
    // Attacks that reached several websites ("betrifft 3 von 4 Websites").
    await waitFor(() => !!document.querySelector('[data-testid="cross-site"] [data-testid="sites-affected"]'))
    expect(document.querySelector('[data-testid="cross-site"] [data-testid="sites-affected"]')!.textContent).toMatch(/^betrifft \d von \d Websites$/)
    expect(bodyText()).not.toMatch(/geschützt|anonym/)
  })

  it('Zugriffe Überblick: KPIs, main chart with markers, alerts, and click-to-filter with removable chips', async () => {
    const { router } = await mountApp('/w/verein.example')
    await waitFor(() => !!document.querySelector('[data-kpi="requests"] [data-slot="kpi-value"]')?.textContent?.match(/\d/))
    await waitFor(() => !!document.querySelector('[data-testid="main-chart"] svg[role="img"]'))
    await waitFor(() => !!document.querySelector('[data-kinds~="block_long"]'))
    await waitFor(() => !!document.querySelector('[data-testid="alert-feed"] [data-alert]'))
    // Sidebar: the pages of the held website, no old site chips.
    expect([...document.querySelectorAll('[data-nav-item^="/w/verein.example"] a')].map(a => a.textContent?.trim())).toEqual(['Zugriffe', 'Ereignisse', 'Zugriffsschutz', 'KI-Crawler'])
    // "läuft auf diesem Server" is one small line linking to the server view.
    expect(document.querySelector('[data-testid="website-header"] a[data-server="web-1"]')?.getAttribute('href')).toMatch(/#?\/server$/)
    expect(byTestId('now-sites')).toBeNull()
    // A click on a country row filters the page.
    await waitFor(() => !!document.querySelector('[data-testid="overview-countries"] [data-row="US"] button'))
    await click(document.querySelector('[data-testid="overview-countries"] [data-row="US"] button'))
    await waitFor(() => String(router.currentRoute.value.query.filter) === 'country:US')
    await waitFor(() => !!document.querySelector('[data-filter="country:US"]'))
    expect(byTestId('filter-chips')!.textContent).toContain('Vereinigte Staaten')
    await click(document.querySelector('[data-filter="country:US"] button'))
    await waitFor(() => router.currentRoute.value.query.filter === undefined)
    // KPI click makes it the chart metric.
    await click(document.querySelector('[data-kpi="stopped"]'))
    await waitFor(() => router.currentRoute.value.query.metric === 'stopped')
  })

  it('explains combined filters beyond 48 hours calmly (with the request ring)', async () => {
    mock.reset({ requestRing: true })
    await mountApp('/w/verein.example?time=7d&filter=country:US&filter=net_class:hosting')
    await waitFor(() => !!byTestId('filter-unavailable-page'))
    expect(byTestId('filter-unavailable-page')!.textContent).toContain('nur für einen kürzeren Zeitraum')
  })

  it('Ereignisse says blocks apply to every website and shows how many websites a client touched', async () => {
    await mountApp('/w/verein.example/events')
    await waitFor(() => !!document.querySelector('[data-incident="R4ZC-9HTK"]'))
    expect(byTestId('block-scope')!.textContent).toContain('Die Sperre gilt für alle Websites auf diesem Server.')
    const row = document.querySelector('[data-incident="R4ZC-9HTK"]')!
    expect(row.textContent).toContain('betrifft 3 von 4 Websites')
    await waitFor(() => !!row.querySelector('[data-testid="block-duration"]')?.textContent?.includes('7 Tage, weil Rechenzentrum und wiederholt'))
  })

  it('Zugriffe starts with a calm status line that links to Ereignisse (D68)', async () => {
    const hits = await get<{ items: { active: boolean, duration_s?: number, level?: number }[] }>('/behaviour/hits?active=true&kind=scenario')
    const running = hits.body.items.filter(h => h.active && h.duration_s && h.level).length
    await mountApp('/w/verein.example')
    await waitFor(() => !!byTestId('website-status-line'))
    const line = byTestId('website-status-line')!
    expect(byTestId('status-baseline')!.textContent).toContain('Grundschutz aktiv')
    await waitFor(() => !!byTestId('status-to-events')?.textContent?.match(/laufende Sperre|Zu den Ereignissen/))
    expect(byTestId('status-to-events')!.getAttribute('href')).toBe('/w/verein.example/events')
    expect(byTestId('status-to-events')!.textContent!.trim()).toBe(running === 0 ? 'Zu den Ereignissen' : running === 1 ? '1 laufende Sperre' : `${running} laufende Sperren`)
    if (running === 0) expect(line.textContent).toContain('Gerade keine laufende Sperre')
    expect(line.textContent).not.toMatch(/geschützt|anonym|sicher/)
  })

  it('Ereignisse: blocks, incidents, rules and the event list of this website on one page (D68)', async () => {
    const lists: URL[] = []
    const onRequest = ({ request }: { request: Request }) => {
      const u = new URL(request.url)
      if (u.pathname === '/api/v0/events') lists.push(u)
    }
    mock.server.events.on('request:start', onRequest)
    const { router } = await mountApp('/w/verein.example/events?outcome=blocked')
    expect(document.querySelector('h1')!.textContent).toBe('Ereignisse')
    await waitFor(() => !!document.querySelector('[data-testid="incident-list"] [data-incident]'))
    expect(byTestId('events-header')!.textContent).toContain('Alle Ereignisse dieser Website')
    await waitFor(() => document.querySelectorAll('[data-testid="website-events"] table[aria-label="Ereignisse"] tbody tr[data-row]').length > 0)
    mock.server.events.removeListener('request:start', onRequest)
    // The website is fixed: every list call asks for it, and it has no chip of its own.
    expect(lists.length).toBeGreaterThan(0)
    expect(lists.every(u => u.searchParams.get('site') === 'verein.example' && u.searchParams.get('outcome') === 'blocked')).toBe(true)
    expect([...document.querySelectorAll('[data-testid="filter-chip"]')].map(c => c.textContent)).not.toContainEqual(expect.stringContaining('Website'))
    // No detour to the events of all websites.
    expect(document.querySelector('main a[href^="/events"]')).toBeNull()
    // A row opens the detail sheet on this page.
    await click(document.querySelector('[data-testid="website-events"] tbody tr[data-row]'))
    await waitFor(() => typeof router.currentRoute.value.query.event === 'string')
    expect(router.currentRoute.value.path).toBe('/w/verein.example/events')
    await waitFor(() => !!byTestId('event-sheet'))
  })
})

describe('fillQuietBuckets', () => {
  it('connects quiet buckets between values, keeps gaps and the edges', () => {
    const v = [null, 1, null, null, 3, null, 2, null]
    expect(fillQuietBuckets(v)).toEqual([null, 1, 0, 0, 3, 0, 2, null])
    expect(fillQuietBuckets(v, [{ from: 2, until: 3 }])).toEqual([null, 1, null, null, 3, 0, 2, null])
    expect(fillQuietBuckets([null, null])).toEqual([null, null])
  })
})

describe('request ring window (D66)', () => {
  it('follows keep_hours of the gateway', async () => {
    const { ringCovers, ringRange, ringWindowS } = await import('../src/api/websites')
    const { ringWindow } = await import('../src/api/requests')
    const before = ringWindowS.value
    try {
      ringWindowS.value = 48 * 3600
      expect(ringCovers('48h')).toBe(true)
      expect(ringCovers('7d')).toBe(false)
      expect(ringRange()).toBe('48h')
      expect(ringWindow('14d').clamped).toBe(true)
      ringWindowS.value = 14 * 24 * 3600
      expect(ringCovers('14d')).toBe(true)
      expect(ringRange()).toBe('14d')
      expect(ringWindow('14d').clamped).toBe(false)
      ringWindowS.value = 7 * 24 * 3600
      expect(ringRange()).toBe('7d')
    }
    finally {
      ringWindowS.value = before
    }
  })
})
