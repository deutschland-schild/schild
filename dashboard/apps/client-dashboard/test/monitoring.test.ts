import type { MonitoringNow, SeriesResult, TrafficBreakdown } from '../src/api/monitoring'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { fetchSeries, monitoringOff } from '../src/api/monitoring'
import { containsIpLiteral } from '../src/lib/ip'
import { COPY, eventsLinkFor, hintView, keyLabel } from '../src/lib/monitoring'
import { RANGES } from '../src/api/monitoring'
import { bodyText, byTestId, cleanup, mockServer, mountApp, settle, waitFor } from './helpers'

const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
  monitoringOff.value = false
})
afterAll(() => mock.server.close())

const get = async <T>(path: string) => {
  const res = await fetch(`${BASE}${path}`)
  return { status: res.status, body: await res.json() as T }
}
const isoAgo = (ms: number) => new Date(Date.now() - ms).toISOString().replace(/\.\d{3}Z$/, 'Z')

describe('monitoring mock follows the contract', () => {
  it('answers series with one value per step, nulls for gaps and too_many_points above 1000', async () => {
    const r = await get<SeriesResult>(`/monitoring/series?metric=traffic.requests&metric=server.disk_used_ratio:max&from=${isoAgo(3600_000)}&resolution=10s`)
    expect(r.status).toBe(200)
    expect(r.body.step_s).toBe(10)
    expect(r.body.points).toBeGreaterThanOrEqual(360)
    const req = r.body.series.find(s => s.metric === 'traffic.requests')!
    expect(req.stat).toBe('rate')
    expect(req.values).toHaveLength(r.body.points)
    // Per-mount metric without object: one series per mount.
    expect(r.body.series.filter(s => s.metric === 'server.disk_used_ratio').length).toBe(3)
    const big = await get<{ code: string }>(`/monitoring/series?metric=traffic.requests&from=${isoAgo(6 * 3600_000)}&resolution=10s`)
    expect(big.status).toBe(400)
    expect(big.body.code).toBe('too_many_points')
    const bad = await get<{ code: string }>(`/monitoring/series?metric=traffic.latency_total:sum&from=${isoAgo(3600_000)}`)
    expect(bad.body.code).toBe('invalid')
  })

  it('joins 14 days of 10 min steps from several requests of at most 1000 points', async () => {
    const r = await fetchSeries({ metrics: ['traffic.requests', 'traffic.stopped'], range: '14d' })
    expect(r.stepS).toBe(600)
    expect(r.points).toBeGreaterThan(2000)
    for (const s of r.series) expect(s.values).toHaveLength(r.points)
    // The restart gap of the model shows up as nulls and as a restart marker.
    expect(r.restarts.length).toBeGreaterThan(0)
    expect(r.series[0]!.values.some(v => v === null)).toBe(true)
  })

  it('keeps the counter invariants in the live numbers and never returns an IP', async () => {
    const now = await get<MonitoringNow>('/monitoring/now')
    expect(now.status).toBe(200)
    expect(now.body.traffic.window_s).toBe(60)
    expect(now.body.sites?.length).toBe(4)
    expect(containsIpLiteral(now.body)).toBe(false)
    const b = await get<TrafficBreakdown>(`/monitoring/traffic/breakdown?by=path&from=${isoAgo(6 * 3600_000)}&top=5`)
    expect(b.body.items).toHaveLength(5)
    expect(b.body.exact).toBe(false)
    const sum = b.body.items.reduce((a, i) => a + i.requests, 0)
    expect(sum + b.body.other.requests).toBe(b.body.total.requests)
    expect(b.body.items.some(i => (i.detections ?? 0) > 0)).toBe(true)
    const bots = await get<TrafficBreakdown>(`/monitoring/traffic/breakdown?by=bot_category&from=${isoAgo(3600_000)}`)
    expect(bots.body.bot_verification).toBe(false)
  })

  it('answers 409 monitoring_off when monitoring is switched off', async () => {
    mock.state.monitoring.enabled = false
    const r = await get<{ code: string }>('/monitoring/now')
    expect(r.status).toBe(409)
    expect(r.body.code).toBe('monitoring_off')
  })
})

describe('monitoring wording', () => {
  it('renders hints as calm sentences with the object and the next step', () => {
    const h = hintView({ code: 'disk_full_soon', level: 'notice', since: new Date().toISOString(), value: 0.91, threshold: 0.9, object: '/var/lib/docker' })
    expect(h.text).toBe('/var/lib/docker ist zu 91 % belegt. Bei 100 % können App und Datenbank nichts mehr schreiben.')
    expect(h.tone).not.toBe('danger')
    const w = hintView({ code: 'waf_saturated', level: 'warning', since: new Date().toISOString(), value: 12 })
    expect(w.text).toContain('12 Anfragen bekamen 503')
    for (const t of [h.text, w.text, COPY.noHints]) expect(t).not.toMatch(/sicher|geschützt|Angriff!|Gefahr/)
  })
  it('labels breakdown keys in German and links to Ereignisse with the same filter', () => {
    expect(keyLabel('country', 'DE')).toBe('Deutschland')
    expect(keyLabel('referrer', 'ai:chatgpt', 'ChatGPT')).toBe('KI-Assistent: ChatGPT')
    expect(keyLabel('referrer', '_direct')).toBe('Direkt (ohne Herkunft)')
    expect(keyLabel('bot_category', 'ai_training')).toBe('KI-Training')
    expect(eventsLinkFor('asn', '24940', RANGES['6h'])).toBe('/events?time=24h&asn=24940')
    expect(eventsLinkFor('path', '/api/termine/{id}', RANGES['1h'])).toBe('/events?time=1h&path=%2Fapi%2Ftermine%2F')
    expect(eventsLinkFor('browser', 'chrome', RANGES['1h'])).toBeNull()
  })
})

describe('monitoring pages', () => {
  it('the server overview starts with "Gerade jetzt": status line, seven tiles, no hints in calm traffic', async () => {
    mock.reset({ scenario: 'standalone' })
    await mountApp('/server')
    await waitFor(() => !!byTestId('now-status')?.textContent?.includes('Anfragen pro Sekunde'))
    const status = byTestId('now-status')!.textContent!
    expect(status).toMatch(/^Grundschutz aktiv · [\d,.]+ Anfragen pro Sekunde · [\d,.]+ % gestoppt · alles im üblichen Rahmen$/)
    for (const t of ['tile-rps', 'tile-stopped', 'tile-latency', 'tile-cpu', 'tile-memory', 'tile-disk', 'tile-network']) expect(byTestId(t)).not.toBeNull()
    expect(byTestId('no-hints')?.textContent).toContain(COPY.noHints)
  })

  it('shows hints with their next step on the server overview', async () => {
    mock.reset({ scenario: 'degraded' })
    await mountApp('/server')
    await waitFor(() => !!byTestId('hints'))
    expect(document.querySelector('[data-hint="disk_full_soon"]')?.textContent).toContain('/var/lib/docker ist zu')
    expect(document.querySelector('[data-hint="cpu_high"]')).not.toBeNull()
    // D36: no website switch or domain chips under "Gerade jetzt" any more.
    expect(byTestId('now-site')).toBeNull()
    expect(byTestId('now-sites')).toBeNull()
    expect(byTestId('now-status')!.textContent).toMatch(/\d Hinweise$/)
  })

  it('Traffic shows the charts and top lists and keeps the range in the URL', async () => {
    const { router } = await mountApp('/w/verein.example/charts?time=1h')
    await waitFor(() => !!document.querySelector('[data-testid="chart-requests"] svg[role="img"]'))
    expect(document.querySelector('[data-testid="chart-requests"] svg')?.getAttribute('aria-label')).toMatch(/^Anfragen pro Sekunde: im Mittel/)
    await waitFor(() => !!document.querySelector('[data-testid="breakdown-path"] table'))
    expect(document.querySelector('[data-testid="breakdown-path"]')?.textContent).toContain('/assets/{file}')
    await waitFor(() => !!byTestId('bots-unverified'))
    expect(bodyText()).toContain('Näherungswert')
    // ±3.3 % is one standard error of the sketch, not a hard bound (MVP-21 measurement).
    expect(document.querySelector('[data-testid="chart-clients"] [data-testid="estimate"]')?.textContent).toContain('meist innerhalb von ±3 %')
    await router.replace({ query: { time: '14d' } })
    await waitFor(() => document.querySelector('[data-testid="chart-requests"] svg') !== null)
    expect(router.currentRoute.value.query.time).toBe('14d')
  })

  it('Auslastung says what is visible; /server opens the overview', async () => {
    const { router } = await mountApp('/server/load')
    await waitFor(() => !!byTestId('visibility'))
    expect(byTestId('visibility')!.textContent).toContain('Schild läuft in einem Container')
    expect(byTestId('card-disks')!.textContent).toContain('/var/lib/docker')
    expect(document.querySelector('[data-nav-item="/server/load"] [aria-current="page"]')).not.toBeNull()
    await router.push('/server')
    await waitFor(() => !!byTestId('now-status'))
    expect(router.currentRoute.value.path).toBe('/server')
  })

  it('explains when monitoring is switched off and stops polling', async () => {
    mock.state.monitoring.enabled = false
    // "/server" says it once in "Gerade jetzt".
    const pages: Array<[string, string]> = [
      ['/w/verein.example/charts', COPY.monitoringOff],
      ['/server', COPY.monitoringOff],
      ['/server/load', COPY.monitoringOff],
    ]
    for (const [path, text] of pages) {
      monitoringOff.value = false
      const { queryClient } = await mountApp(path)
      await waitFor(() => !!byTestId('monitoring-off'))
      expect(byTestId('monitoring-off')!.textContent).toBe(text)
      await settle()
      // MVP-21 measurement: the pages kept polling every 10-30 s and collected 409s.
      const observers = queryClient.getQueryCache().findAll({ queryKey: ['monitoring'] }).flatMap(q => q.observers)
      expect(observers.length).toBeGreaterThan(0)
      for (const o of observers) {
        const { enabled, refetchInterval } = o.options as { enabled?: unknown, refetchInterval?: unknown }
        expect(enabled === false || refetchInterval === false || refetchInterval === undefined, `${path}: ${JSON.stringify(o.options.queryKey)} still polls`).toBe(true)
      }
      cleanup()
      document.body.innerHTML = ''
    }
  })
})
