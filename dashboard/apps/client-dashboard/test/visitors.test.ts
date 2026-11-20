import type { EventPage, Incident } from '../src/api/types'
import type { AlertFeed, IncidentPage } from '../src/api/websites'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { RANGES } from '../src/api/monitoring'
import { liveMatches, parseFilters, toApiQuery } from '../src/composables/useEventFilters'
import { eventsLinkFor } from '../src/lib/monitoring'
import { incidentBlockText, KPIS, WEBSITE_COPY } from '../src/lib/websites'
import { bodyText, byTestId, cleanup, mockServer, mountApp, waitFor } from './helpers'

/**
 * D36 amendment (2026-10-29): visitors are people; Bot-Clients; Incident.block;
 * possible_false_positive; listEvents net_class, method, ua_class; TCPSnapshot.listen null.
 */
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

describe('wording: Besucher ohne erkannte Bots', () => {
  it('explains the visitor KPI and the realtime label without bots', () => {
    expect(KPIS.find(k => k.key === 'visitors')!.hint).toContain('ohne erkannte Bots')
    expect(WEBSITE_COPY.liveNow(12)).toBe('≈ 12 Besucher · letzte 5 Min.')
    expect(WEBSITE_COPY.liveNowTitle).toBe('Verschiedene Besucher der letzten 5 Minuten ohne erkannte Bots (Näherungswert). Klick zeigt die Echtzeit-Ansicht.')
    for (const t of [WEBSITE_COPY.visitorsTitle, WEBSITE_COPY.botClientsTitle, WEBSITE_COPY.liveNowTitle]) expect(t).not.toMatch(/anonym|geschützt|sicher/)
  })

  it('says how long and why a block lasts from Incident.block', () => {
    expect(incidentBlockText({ duration_s: 604800, net_class: 'hosting', level: 4 })).toBe('7 Tage, weil Rechenzentrum und wiederholt')
    expect(incidentBlockText({ duration_s: 900, net_class: 'residential', level: 1 })).toBe('15 Minuten, erster Verstoß')
    expect(incidentBlockText({ duration_s: 3600, net_class: 'residential', level: 2 })).toBe('1 Stunde, weil wiederholt')
    expect(incidentBlockText({ duration_s: 900, net_class: 'hosting', level: 1 })).toBe('15 Minuten, weil Rechenzentrum')
  })
})

describe('breakdown rows link to Ereignisse with the same filter', () => {
  it('builds links for net class, method (OTHER) and UA class', () => {
    expect(eventsLinkFor('net_class', 'hosting', RANGES['6h'])).toBe('/events?time=24h&net=hosting')
    expect(eventsLinkFor('method', 'OTHER', RANGES['1h'])).toBe('/events?time=1h&method=OTHER')
    expect(eventsLinkFor('ua_class', 'tool', RANGES['1h'])).toBe('/events?time=1h&client=tool')
    expect(eventsLinkFor('net_class', 'moon', RANGES['1h'])).toBeNull()
  })

  it('maps the URL to listEvents and keeps them out of the stream', () => {
    const f = parseFilters({ net: 'hosting', method: 'post', client: 'tool', time: '1h' })
    expect(f).toMatchObject({ net: 'hosting', method: 'POST', client: 'tool' })
    expect(toApiQuery(f)).toMatchObject({ net_class: 'hosting', method: 'POST', ua_class: 'tool' })
    expect(parseFilters({ net: 'moon', client: 'robot', method: 'g e t' })).toEqual({ time: '24h' })
    const geo = { country: 'NL', asn: 64500, net_class: 'hosting' as const }
    expect(liveMatches({ method: 'PROPFIND', geo }, { time: '1h', method: 'OTHER', net: 'hosting' })).toBe(true)
    expect(liveMatches({ method: 'GET', geo }, { time: '1h', method: 'OTHER' })).toBe(false)
    expect(liveMatches({ method: 'GET', geo }, { time: '1h', net: 'residential' })).toBe(false)
    expect(liveMatches({ method: 'GET', geo }, { time: '1h', client: 'browser' })).toBe(false)
  })

  it('the mock answers the new filters', async () => {
    const all = await get<EventPage>('/events?limit=500')
    const hosting = await get<EventPage>('/events?limit=500&net_class=hosting')
    expect(hosting.body.items.length).toBeGreaterThan(0)
    expect(hosting.body.items.every(e => e.geo?.net_class === 'hosting')).toBe(true)
    expect(hosting.body.items.length).toBeLessThan(all.body.items.length)
    const post = await get<EventPage>('/events?limit=500&method=POST')
    expect(post.body.items.length).toBeGreaterThan(0)
    expect(post.body.items.every(e => e.method === 'POST')).toBe(true)
    const browsers = await get<EventPage>('/events?limit=500&ua_class=browser')
    expect(browsers.body.items.length).toBeGreaterThan(0)
    expect(browsers.body.items.length).toBeLessThanOrEqual(all.body.items.length)
  })

  it('Ereignisse shows the filters from a breakdown link as chips', async () => {
    await mountApp('/events?net=hosting&method=OTHER&client=tool')
    await waitFor(() => bodyText().includes('Rechenzentren'))
    expect(bodyText()).toContain('Netzart')
    expect(bodyText()).toContain('Methode')
    expect(bodyText()).toContain('Andere')
    expect(bodyText()).toContain('Werkzeug')
  })
})

describe('incidents, alerts and the server', () => {
  it('incidents carry their block and alerts their false-positive mark', async () => {
    const inc = await get<IncidentPage>('/incidents?site=verein.example')
    const long = inc.body.items.find((i: Incident) => i.incident === 'R4ZC-9HTK')!
    expect(long.block).toMatchObject({ level: 4, net_class: 'hosting', duration_s: 604800, persisted: true })
    const alerts = await get<AlertFeed>(`/websites/verein.example/alerts?from=${isoAgo(86400_000)}&to=${isoAgo(0)}`)
    const fp = alerts.body.items.filter(a => a.possible_false_positive)
    expect(fp.length).toBeGreaterThan(0)
    expect(fp.every(a => a.path === '/mitglied-werden' && a.rules?.includes('942100'))).toBe(true)
  })

  it('Überblick: KPI tooltip, realtime label, Bot-Clients and possible false positives', async () => {
    await mountApp('/w/verein.example')
    await waitFor(() => !!document.querySelector('[data-kpi="visitors"] [data-slot="kpi-value"]')?.textContent?.match(/\d/))
    expect(document.querySelector('[data-kpi="visitors"] [title]')?.getAttribute('title')).toContain('ohne erkannte Bots')
    await waitFor(() => !!byTestId('live-now'))
    expect(byTestId('live-now')!.getAttribute('title')).toBe(WEBSITE_COPY.liveNowTitle)
    expect(byTestId('live-now')!.textContent).toMatch(/≈ \d+ Besucher · letzte 5 Min\./)
    await waitFor(() => !!byTestId('bot-clients'))
    expect(byTestId('bot-clients')!.textContent).toMatch(/^\s*Bot-Clients: ≈ [\d.]+ in den letzten 10 Minuten\s*$/)
    expect(byTestId('donut-bots')!.contains(byTestId('bot-clients'))).toBe(true)
    await waitFor(() => !!byTestId('possible-fp'))
  })

  it('Ereignisse reads the block duration from the incident', async () => {
    await mountApp('/w/verein.example/events')
    await waitFor(() => !!document.querySelector('[data-incident="R4ZC-9HTK"] [data-testid="block-duration"]'))
    expect(document.querySelector('[data-incident="R4ZC-9HTK"] [data-testid="block-duration"]')!.textContent).toContain('7 Tage, weil Rechenzentrum und wiederholt')
  })

  it('Server says "unbekannt" for open ports on the sockstat path', async () => {
    mock.reset({ scenario: 'degraded' })
    await mountApp('/server/load')
    await waitFor(() => !!byTestId('tcp-listen'))
    expect(byTestId('tcp-listen')!.textContent?.trim()).toBe('unbekannt')
    mock.reset({})
  })

  it('Server shows the number of open ports when it is known', async () => {
    await mountApp('/server/load')
    await waitFor(() => !!byTestId('tcp-listen'))
    expect(byTestId('tcp-listen')!.textContent?.trim()).toBe('9')
  })
})
