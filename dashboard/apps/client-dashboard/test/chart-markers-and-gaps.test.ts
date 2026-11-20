import type { WebsiteKpis } from '../src/api/websites'
import type { ChartMarker } from '../src/components/websites/TrafficAttackChart.vue'
import { mount } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import kpisFixture from '../../../../contracts/api/fixtures/client/getWebsiteKpis.json'
import kpisPartialFixture from '../../../../contracts/api/fixtures/client/getWebsiteKpis.partial.json'
import KpiRow from '../src/components/websites/KpiRow.vue'
import TrafficAttackChart from '../src/components/websites/TrafficAttackChart.vue'
import { annotationLabel, combineGapKind, gapCopy, groupMarkers } from '../src/lib/websites'
import { bodyText, byTestId, cleanup, click, mockServer, mountApp, waitFor } from './helpers'

/** D36 fix round 1: findings of the independent measurement (results/MVP-21-D36-messung-2026-10-29.md). */
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
})
afterAll(() => mock.server.close())

describe('chart markers stay inside the chart (D.2)', () => {
  it('groups markers closer than the gap and keeps every group inside the bounds', () => {
    const pts = Array.from({ length: 300 }, (_, i) => ({ x: 40 + (i % 50) * 3, item: i }))
    const groups = groupMarkers(pts, 26, 12, 628)
    expect(groups.reduce((n, g) => n + g.items.length, 0)).toBe(300)
    for (let i = 0; i < groups.length; i++) {
      expect(groups[i]!.x).toBeGreaterThanOrEqual(12)
      expect(groups[i]!.x).toBeLessThanOrEqual(628)
      if (i > 0) expect(groups[i]!.x - groups[i - 1]!.x).toBeGreaterThanOrEqual(26)
    }
    expect(groupMarkers([{ x: 9000, item: 1 }], 26, 12, 628)[0]!.x).toBe(628)
  })

  it('renders 300 incident markers of an attack as a few chips within the width', () => {
    const n = 60
    const markers: ChartMarker[] = Array.from({ length: 300 }, (_, i) => ({ index: 40 + (i % 5), kind: 'incident', label: `Vorfall ${i}`, glyph: 'V', to: '/incidents' }))
    markers.push({ index: 2, kind: 'restart', label: 'Neustart von Schild', glyph: 'N', to: null })
    const w = mount(TrafficAttackChart, {
      props: {
        times: Array.from({ length: n }, (_, i) => i * 60_000),
        labels: Array.from({ length: n }, (_, i) => String(i)),
        longLabels: Array.from({ length: n }, (_, i) => String(i)),
        values: Array.from({ length: n }, () => 1),
        stopped: Array.from({ length: n }, () => 0),
        would: Array.from({ length: n }, () => 0),
        label: 'Anfragen',
        markers,
      },
      global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } },
    })
    const chips = w.findAll('[data-slot="markers"] [data-marker]')
    expect(chips.length).toBeLessThanOrEqual(5)
    for (const c of chips) {
      const left = Number.parseFloat((c.element as HTMLElement).style.left)
      expect(left).toBeGreaterThanOrEqual(0)
      expect(left).toBeLessThanOrEqual(100)
    }
    expect(w.find('[data-marker="restart"]').exists()).toBe(true)
    expect(chips.reduce((n, c) => n + Number(c.attributes('data-count')), 0)).toBe(301)
    expect(chips.some(c => c.text().includes('99+'))).toBe(true)
    w.unmount()
  })
})

describe('block texts (D29, D.4)', () => {
  it('labels a grouped incident marker with its count', () => {
    expect(annotationLabel({ t: '2026-10-29T10:00:00Z', kind: 'incident', count: 120, until: '2026-10-29T10:20:00Z' })).toBe('120 Vorfälle')
  })

  it('shows the hosting ladder on the behaviour page', async () => {
    await mountApp('/behaviour?view=scenarios')
    await waitFor(() => !!byTestId('ladder-hosting'))
    expect(byTestId('ladder')!.textContent).toContain('höchstens 24 Std')
    expect(byTestId('ladder-hosting')!.textContent).toContain('Rechenzentren')
    expect(byTestId('ladder-hosting')!.textContent).toMatch(/höchstens 7 (T|Tage)/)
  })

  it('the incident page of a behaviour block says how long and why, calmly and in German', async () => {
    await mountApp('/incidents/R4ZC-9HTK')
    await waitFor(() => !!byTestId('incident-sentence'))
    const sentence = byTestId('incident-sentence')!.textContent!
    expect(sentence).toContain('gesperrt: 7 Tage, weil Rechenzentrum und wiederholt')
    expect(sentence).not.toMatch(/Anfrage an\s+gesperrt/)
    expect(byTestId('block-duration')!.textContent).toContain('alle Websites')
    expect(bodyText()).not.toContain('Grundregel auf deinem Server')
    expect(bodyText()).not.toMatch(/behaviour [a-z_]+:/)
    expect(byTestId('incident-status')!.className).not.toMatch(/danger|destructive/)
  })
})

describe('click to filter without the request ring (D.3)', () => {
  it('offers one filter at a time and keeps the tables unfiltered and calm', async () => {
    const { router } = await mountApp('/w/verein.example')
    await waitFor(() => !!document.querySelector('[data-testid="overview-countries"] [data-row="US"] button'))
    await click(document.querySelector('[data-testid="overview-countries"] [data-row="US"] button'))
    await waitFor(() => String(router.currentRoute.value.query.filter) === 'country:US')
    await waitFor(() => !!byTestId('panels-unfiltered'))
    expect(byTestId('panels-unfiltered')!.textContent).toContain('einem Merkmal zur Zeit')
    // Tables keep their rows, nothing looks broken, no 48-hour offer that would not help.
    await waitFor(() => !!document.querySelector('[data-testid="overview-countries"] [data-row="US"]'))
    expect(document.querySelector('[data-testid="filter-unavailable"]')).toBeNull()
    expect(byTestId('filter-unavailable-page')).toBeNull()
    expect(bodyText()).not.toContain('Zeitraum verkürzen')
    // A second dimension replaces the filter.
    await waitFor(() => !!document.querySelector('[data-testid="donut-device"] [data-row] button'))
    const row = document.querySelector('[data-testid="donut-device"] [data-row] button')!
    await click(row)
    await waitFor(() => !String(router.currentRoute.value.query.filter).startsWith('country:'))
    expect([router.currentRoute.value.query.filter].flat()).toHaveLength(1)
  })

  it('keeps the last filter of a link with two', async () => {
    const { router } = await mountApp('/w/verein.example?time=7d&filter=country:US&filter=net_class:hosting')
    await waitFor(() => String(router.currentRoute.value.query.filter) === 'net_class:hosting')
    expect(byTestId('filter-unavailable-page')).toBeNull()
  })
})

describe('Letzte Alarme with the monitoring off (13)', () => {
  it('shows the alarms, which come from the stored events', async () => {
    mock.state.monitoring.enabled = false
    await mountApp('/w/verein.example')
    await waitFor(() => !!byTestId('monitoring-off'))
    await waitFor(() => !!document.querySelector('[data-testid="alerts-card"] [data-testid="alert-feed"]'))
    expect(byTestId('alerts-card')!.textContent).toContain('ohne Messung')
  })
})

describe('partial next to exact (contracts v0.5, D36 fix round 1)', () => {
  it('shows a gap in the range as a calm gap note, separate from Näherungswert', () => {
    const kpis = kpisPartialFixture as unknown as WebsiteKpis
    const w = mount(KpiRow, { props: { kpis, active: 'requests' } })
    const gap = w.find('[data-testid="kpi-gap"]')
    expect(gap.exists()).toBe(true)
    expect(gap.text()).toContain('Lücke im Zeitraum')
    expect(gap.text()).not.toContain('Näherungswert')
    // "≈" only where the number is an estimate (visitors, latency), never because of the gap.
    expect(w.find('[data-kpi="requests"]').text()).not.toContain('≈')
    expect(w.find('[data-kpi="visitors"]').text()).toContain('≈')
    expect(w.find('[data-kpi="requests"]').text()).toContain('Lücke im Zeitraum')
    expect(gap.html()).not.toMatch(/danger|destructive|red-/)
    w.unmount()
  })

  it('tells a restart ("Neustart") from real loss ("Messlücke") by gap_kind (contracts v0.5)', () => {
    const withKind = (kind: Record<string, 'restart' | 'lost' | undefined>) => {
      const k = structuredClone(kpisPartialFixture) as unknown as WebsiteKpis
      for (const [key, v] of Object.entries(k.current)) {
        if (!v?.partial) continue
        const g = kind[key] ?? kind['*']
        if (g) v.gap_kind = g
        else delete v.gap_kind
      }
      return k
    }
    let w = mount(KpiRow, { props: { kpis: withKind({ '*': 'restart' }), active: 'requests' } })
    expect(w.find('[data-testid="gap-note"]').attributes('data-gap-kind')).toBe('restart')
    expect(w.find('[data-testid="kpi-gap"]').text()).toContain('Neustart im Zeitraum')
    expect(w.find('[data-kpi="requests"]').text()).toContain('Neustart im Zeitraum')
    w.unmount()
    // lost wins over restart
    w = mount(KpiRow, { props: { kpis: withKind({ '*': 'restart', requests: 'lost' }), active: 'requests' } })
    expect(w.find('[data-testid="kpi-gap"]').text()).toContain('Messlücke im Zeitraum')
    w.unmount()
    // without gap_kind: the general wording
    w = mount(KpiRow, { props: { kpis: withKind({}), active: 'requests' } })
    expect(w.find('[data-testid="gap-note"]').attributes('data-gap-kind')).toBe('unknown')
    expect(w.find('[data-testid="kpi-gap"]').text()).toContain('Lücke im Zeitraum')
    w.unmount()
  })

  it('combines gap kinds: lost wins, a value without a kind makes it unknown', () => {
    expect(combineGapKind([{ partial: true, gap_kind: 'restart' }, { partial: false }])).toBe('restart')
    expect(combineGapKind([{ partial: true, gap_kind: 'restart' }, { partial: true, gap_kind: 'lost' }])).toBe('lost')
    expect(combineGapKind([{ partial: true, gap_kind: 'restart' }, { partial: true }])).toBeUndefined()
    expect(combineGapKind([{ partial: true }, { partial: true, gap_kind: 'lost' }])).toBe('lost')
    expect(combineGapKind([{ partial: false }, undefined])).toBeUndefined()
    expect(gapCopy('restart').label).toBe('Neustart im Zeitraum')
    expect(gapCopy('lost').label).toBe('Messlücke im Zeitraum')
    expect(gapCopy(undefined).label).toBe('Lücke im Zeitraum')
  })

  it('shows no gap note for a fully counted range', () => {
    const kpis = kpisFixture as unknown as WebsiteKpis
    const w = mount(KpiRow, { props: { kpis, active: 'requests' } })
    expect(w.find('[data-testid="kpi-gap"]').exists()).toBe(false)
    w.unmount()
  })

  it('names a grouped incident marker by count and its newest incident', () => {
    expect(annotationLabel({ t: '2026-10-28T18:00:00Z', until: '2026-10-28T18:10:00Z', kind: 'incident', ref: 'R3TJ-9PLC', count: 3 })).toBe('3 Vorfälle, zuletzt R3TJ-9PLC')
    expect(annotationLabel({ t: '2026-10-28T18:00:00Z', kind: 'incident', ref: 'R3TJ-9PLC' })).toBe('Vorfall R3TJ-9PLC')
  })
})
