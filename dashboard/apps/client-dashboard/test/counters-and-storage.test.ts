import type { Overview } from '../src/api/types'
import type { AlertFeed, WebsiteDetail, WebsiteList } from '../src/api/websites'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { letThroughText, WOULD_BLOCK_REASON, wouldBlockNote } from '../src/lib/labels'
import { aggregateText } from '../src/lib/incident'
import { partialView } from '../src/lib/summary'
import { hintView } from '../src/lib/monitoring'
import { annotationLabel, blockWhy } from '../src/lib/websites'
import { byTestId, cleanup, mockServer, mountApp, waitFor } from './helpers'

/** Contracts v0.5 UI items: D38 storage bounds and the D36 open items (would_block_reason, partial counters, …). */
const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

const isoAgo = (ms: number) => new Date(Date.now() - ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
const get = async <T>(path: string) => (await fetch(`${BASE}${path}`)).json() as Promise<T>

describe('would_block_reason: "Erkannt, aber durchgelassen: …"', () => {
  it('has a calm German label for every reason of the contract', () => {
    expect(Object.keys(WOULD_BLOCK_REASON).sort()).toEqual(['allowlist', 'gateway_observe', 'learning', 'scenario_observe', 'settling', 'shared_address', 'site_observe', 'source_detect'])
    for (const l of Object.values(WOULD_BLOCK_REASON)) expect(l).not.toMatch(/geschützt|sicher|anonym|Näherungswert/)
    expect(letThroughText('learning')).toBe('Erkannt, aber durchgelassen: Lernphase')
    expect(letThroughText(undefined)).toMatch(/^Erkannt, aber durchgelassen\./)
    expect(wouldBlockNote(true)).toBe('Erkannt, aber durchgelassen: Testprofil')
  })

  it('mock: every would_block event and alert carries a reason, other outcomes none', async () => {
    for (const e of mock.state.events) {
      if (e.summary.outcome === 'would_block') expect(e.summary.would_block_reason).toBeTruthy()
      else expect(e.summary.would_block_reason).toBeUndefined()
    }
    const feed = await get<AlertFeed>(`/websites/verein.example/alerts?from=${isoAgo(86400_000)}&to=${isoAgo(0)}`)
    const would = feed.items.filter(a => a.outcome === 'would_block')
    expect(would.length).toBeGreaterThan(0)
    expect(would.every(a => !!a.would_block_reason)).toBe(true)
    mock.reset({ scenario: 'observe' })
    // A source on Erkennen names itself first (D90), in the test profile too.
    expect(mock.state.events.filter(e => e.summary.outcome === 'would_block').every(e => e.summary.would_block_reason === 'gateway_observe' || e.summary.would_block_reason === 'source_detect')).toBe(true)
  })

  it('event detail says why the request came through', async () => {
    const e = mock.state.events.find(x => x.summary.outcome === 'would_block' && x.summary.would_block_reason === 'allowlist')
      ?? mock.state.events.find(x => x.summary.outcome === 'would_block')!
    const label = WOULD_BLOCK_REASON[e.summary.would_block_reason!]
    await mountApp(`/events?event=${e.summary.id}`)
    await waitFor(() => !!byTestId('event-sentence'))
    expect(byTestId('event-sentence')!.textContent).toContain(`Erkannt, aber durchgelassen: ${label}`)
    expect(document.querySelector(`[data-testid="outcome"][data-reason="${e.summary.would_block_reason}"]`)).not.toBeNull()
  })

  it('alert chips name the reason', async () => {
    await mountApp('/w/verein.example')
    await waitFor(() => !!document.querySelector('[data-testid="alert-reason"]'), 4000)
    expect(document.querySelector('[data-testid="alert-reason"]')!.textContent).toMatch(/^, aber durchgelassen: /)
  })
})

describe('partial 24-hour counters: "seit …" or a gap hint, never "Näherungswert"', () => {
  const now = Date.parse('2026-10-29T18:00:00Z')
  it('formats the start of the window or the gap', () => {
    const p = partialView(true, '2026-10-29T11:12:00Z', now)!
    expect(p.short).toMatch(/^seit \d\d:\d\d$/)
    expect(partialView(true, '2026-10-28T19:05:00Z', now)!.short).toMatch(/^seit (gestern )?\d\d:\d\d$/)
    expect(partialView(true, undefined, now)!.short).toBe('mit Lücke')
    expect(partialView(true, undefined, now, 'events')!.text).toContain('Speichergrenze')
    expect(partialView(false, undefined, now)).toBeNull()
    expect(partialView(undefined, '2026-10-27T10:00:00Z', now)).toBeNull()
    for (const v of [p, partialView(true, undefined, now)!]) expect(`${v.short} ${v.text}`).not.toContain('Näherungswert')
  })

  it('mock and Allgemein: standalone counts since the start, degraded has a gap', async () => {
    mock.reset({ scenario: 'standalone' })
    const o = await get<Overview>('/overview')
    expect(o.counters_24h.partial).toBe(true)
    expect(o.counters_24h.since).toBeTruthy()
    await mountApp('/settings')
    await waitFor(() => !!byTestId('counters-partial'))
    expect(byTestId('counters-partial')!.textContent).toMatch(/· seit (gestern )?\d\d:\d\d/)
    cleanup()
    mock.reset({ scenario: 'degraded' })
    const d = await get<Overview>('/overview')
    expect(d.counters_24h.partial).toBe(true)
    expect(d.counters_24h.since).toBeUndefined()
    await mountApp('/settings')
    await waitFor(() => !!byTestId('counters-partial'))
    expect(byTestId('counters-partial')!.textContent).toContain('mit Lücke')
  })

  it('website: traffic_24h_since in the mock and on the Ereignisse page', async () => {
    mock.reset({ scenario: 'standalone' })
    const w = await get<WebsiteDetail>('/websites/shop.example')
    expect(w.traffic_24h_partial).toBe(true)
    expect(w.traffic_24h_since).toBeTruthy()
    await mountApp('/w/shop.example/events')
    await waitFor(() => !!byTestId('website-24h-partial'))
    expect(byTestId('website-24h-partial')!.textContent).toMatch(/seit (gestern )?\d\d:\d\d/)
    expect(byTestId('website-24h')!.textContent).not.toContain('Näherungswert')
    cleanup()
    mock.reset({})
    const full = await get<WebsiteDetail>('/websites/verein.example')
    expect(full.traffic_24h_partial).toBeUndefined()
  })
})

describe('incident aggregation (D38) and the block ladder (D36 open items)', () => {
  it('describes count, first and last seen only when count > 1', () => {
    expect(aggregateText({ time: '2026-10-29T14:32:05Z' })).toBeNull()
    expect(aggregateText({ time: '2026-10-29T14:32:05Z', count: 1 })).toBeNull()
    expect(aggregateText({ time: '2026-10-29T14:32:05Z', count: 12, first_seen: '2026-10-29T14:32:05Z', last_seen: '2026-10-29T14:32:51Z' }))
      .toMatch(/^12 gesperrte Anfragen von \d\d:\d\d:05 bis \d\d:\d\d:51$/)
    expect(aggregateText({ time: '2026-10-29T14:32:05Z', count: 2 })).toBe('2 gesperrte Anfragen')
  })

  it('"wiederholt" follows the ladder step in count', () => {
    expect(blockWhy({ net_class: 'hosting', count: 1 })).toBe('Rechenzentrum')
    expect(blockWhy({ net_class: 'hosting', count: 2 })).toBe('Rechenzentrum, wiederholt')
    expect(blockWhy({})).toBe('')
    expect(annotationLabel({ t: '2026-10-29T10:00:00Z', kind: 'block_long', net_class: 'hosting', duration_s: 7 * 86400, count: 4 })).toBe('7 Tage gesperrt: Rechenzentrum, wiederholt')
  })

  it('shows count, first and last seen on the incident page and in the list', async () => {
    const inc = [...mock.state.incidents.values()].find(i => (i.count ?? 1) > 1)!
    expect(inc).toBeTruthy()
    await mountApp(`/incidents/${inc.incident}`)
    await waitFor(() => !!byTestId('incident-aggregate'))
    expect(byTestId('incident-aggregate')!.textContent).toContain(`${inc.count} gesperrte Anfragen`)
    cleanup()
    await mountApp(`/w/${inc.site}/events`)
    await waitFor(() => !!document.querySelector('[data-testid="incident-list"] [data-testid="incident-aggregate"]'), 4000)
  })
})

describe('storage hints (D38) and server-only hints', () => {
  const since = new Date().toISOString()
  it('renders the three new hints from the MVP-21 texts with their values', () => {
    const cap = hintView({ code: 'store_cap_unreachable', level: 'warning', since, value: 1_090_000_000, threshold: 1_048_576_000 })
    expect(cap.text).toBe('Der Ereignisspeicher bleibt über der Grenze von 1.000 MB. Die neuesten Einträge löscht Schild nicht.')
    expect(cap.next).toBe('Erhöhe retention.max_size_mb oder sieh nach, was so viel schreibt.')
    const budget = hintView({ code: 'storage_budget', level: 'notice', since, threshold: 1_073_741_824, object: '/var/lib/schild' })
    expect(budget.text).toMatch(/^Wenn alle Speichergrenzen von Schild ausgeschöpft sind, bleibt auf \/var\/lib\/schild weniger als 1,1 GB frei\. Die Reserve sind 5 % der Platte, mindestens 1 GiB und höchstens 20 GiB\.$/)
    expect(budget.next).toBe('Senke retention.max_size_mb oder schaffe Platz.')
    expect(hintView({ code: 'storage_budget', level: 'notice', since, object: '/var/lib/schild' }).text).toContain('weniger frei als die Reserve. Die Reserve sind 5 % der Platte, mindestens 1 GiB und höchstens 20 GiB.')
    // D38: on a 2 TiB disk the reserve stops at 20 GiB (shown in decimal units).
    expect(hintView({ code: 'storage_budget', level: 'notice', since, threshold: 20 * 1_073_741_824, object: '/var/lib/schild' }).text).toContain('weniger als 21,5 GB frei')
    const proj = hintView({ code: 'disk_fill_projection', level: 'notice', since, value: 9, object: '/' })
    expect(proj.text).toBe('/ ist in etwa 9 Tagen voll, wenn es so weitergeht wie in den letzten 7 Tagen.')
    expect(proj.next).toBe('Unter „Server“ siehst du große Logdateien.')
    expect(proj.to).toBe('/server/check')
    expect(hintView({ code: 'disk_fill_projection', level: 'warning', since, value: 1, object: '/' }).text).toContain('in etwa einem Tag')
    expect(hintView({ code: 'disk_fill_projection', level: 'warning', since, value: 0, object: '/' }).text).toContain('in weniger als einem Tag')
    for (const v of [cap, budget, proj]) expect(`${v.text} ${v.next}`).not.toMatch(/geschützt|sicher|anonym|Ein Hinweis zur Auslastung/)
  })

  it('degraded mock: store hints on the server page, not on website cards', async () => {
    mock.reset({ scenario: 'degraded' })
    const list = await get<WebsiteList>('/websites')
    expect(list.server!.hints.map(h => h.code)).toEqual(expect.arrayContaining(['store_cap_unreachable', 'storage_budget', 'disk_fill_projection']))
    for (const w of list.websites) {
      const hints = w.reasons.map(r => r.hint)
      expect(hints).toContain('disk_fill_projection')
      expect(hints).not.toContain('store_cap_unreachable')
      expect(hints).not.toContain('storage_budget')
    }
    await mountApp('/')
    await waitFor(() => document.querySelectorAll('[data-testid="card-reasons"]').length > 0, 4000)
    const cards = [...document.querySelectorAll('[data-testid="website-card"]')].map(c => c.textContent ?? '')
    expect(cards.some(t => t.includes('Platte bald voll') || t.includes('weitere'))).toBe(true)
    expect(cards.every(t => !t.includes('Ereignisspeicher'))).toBe(true)
    // The hints sit in "Gerade jetzt" on the server page.
    cleanup()
    await mountApp('/server')
    await waitFor(() => !!document.querySelector('[data-hint="store_cap_unreachable"]'), 4000)
    expect(document.querySelector('[data-hint="store_cap_unreachable"]')!.textContent).toContain('1.000 MB')
    expect(document.querySelector('[data-hint="disk_fill_projection"]')!.textContent).toContain('in etwa 9 Tagen')
  })
})

describe('settings: what schild keeps on disk (D38)', () => {
  it('shows the event store against its cap and metrics.db', async () => {
    await mountApp('/settings')
    await waitFor(() => !!byTestId('storage-figures'), 4000)
    const t = byTestId('storage-figures')!.textContent!
    expect(t).toMatch(/Ereignisspeicher:\s*210 MB von 1 GB belegt/)
    expect(t).toContain('metrics.db')
    expect(byTestId('storage-over')).toBeNull()
    cleanup()
    mock.reset({ scenario: 'degraded' })
    await mountApp('/settings')
    await waitFor(() => !!byTestId('storage-over'), 4000)
  })
})
