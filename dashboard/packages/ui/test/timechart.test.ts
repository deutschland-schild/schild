import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import TimeChart from '../src/components/app/TimeChart.vue'
import { bandPath, gapLinePath, segmentsOf, seriesStats, stackLayers, stackTotal, timeTicks } from '../src/lib/chart'
import { formatBytes, formatDecimal, formatDuration, formatMs } from '../src/lib/format'

describe('chart helpers for monitoring', () => {
  it('splits series at gaps', () => {
    expect(segmentsOf([1, 2, null, 3, undefined, null, 4, 5])).toEqual([[0, 1], [3, 3], [6, 7]])
    expect(segmentsOf([])).toEqual([])
    expect(segmentsOf([null, null])).toEqual([])
  })
  it('draws one subpath per run (gaps stay gaps)', () => {
    const d = gapLinePath([1, 2, null, 3, 4], i => i * 10, v => 100 - v)
    expect(d.match(/M/g)).toHaveLength(2)
    expect(d).not.toContain('NaN')
  })
  it('stacks bottom-up and gaps a step where any layer is missing', () => {
    const [a, b] = stackLayers([[1, 2, 3], [10, null, 30]])
    expect(a!.hi).toEqual([1, null, 3])
    expect(b!.lo).toEqual([1, null, 3])
    expect(b!.hi).toEqual([11, null, 33])
    const band = bandPath(b!.lo, b!.hi, i => i * 10, v => 100 - v)
    expect(band.match(/Z/g)).toHaveLength(2)
  })
  it('totals a stack only where every layer has data', () => {
    expect(stackTotal([[1, 2, null], [3, 0, 4]], 0)).toBe(4)
    expect(stackTotal([[1, 2, null], [3, 0, 4]], 2)).toBeNull()
    expect(stackTotal([], 0)).toBeNull()
  })
  it('puts time ticks on round local times', () => {
    // 1-minute steps from 10:03 local time over two hours: ticks on full half hours or hours, never 10:03.
    const start = new Date(2026, 9, 29, 10, 3).getTime()
    const times = Array.from({ length: 121 }, (_, i) => start + i * 60_000)
    const idx = timeTicks(times, 6)
    expect(idx.length).toBeGreaterThanOrEqual(2)
    expect(idx.length).toBeLessThanOrEqual(6)
    for (const i of idx) expect(new Date(times[i]!).getMinutes() % 30).toBe(0)
    expect(timeTicks([], 4, 9)).toEqual([0, 3, 6])
  })
  it('summarises a series without gaps', () => {
    expect(seriesStats([2, null, 6])).toEqual({ mean: 4, max: 6, maxIndex: 2 })
    expect(seriesStats([null])).toBeNull()
  })
  it('formats bytes, ms, decimals and durations in German', () => {
    expect(formatBytes(1_234_000)).toBe('1,2 MB')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatMs(0.42)).toBe('0,4 ms')
    expect(formatMs(180.4)).toBe('180 ms')
    expect(formatMs(1400)).toBe('1,4 s')
    expect(formatDecimal(0.83)).toBe('0,83')
    expect(formatDecimal(42.26)).toBe('42,3')
    expect(formatDuration(90)).toBe('2 Minuten')
    expect(formatDuration(3 * 86400)).toBe('3 Tage')
  })
})

describe('TimeChart', () => {
  const props = {
    label: 'Anfragen pro Sekunde',
    labels: ['10:00', '10:10', '10:20', '10:30'],
    series: [
      { id: 'passed', label: 'Durchgelassen', values: [10, 12, null, 9], stack: true, color: 'var(--traffic-passed)' },
      { id: 'stopped', label: 'Gesperrt', values: [1, 2, null, 1], stack: true, color: 'var(--traffic-stopped)' },
      { id: 'would', label: 'Erkannt', values: [0, 1, null, 0], dashed: true },
    ],
    markers: [{ index: 3, label: 'Neustart von Schild' }],
  }
  it('names itself with a summary, draws areas and lines, marks restarts', () => {
    const w = mount(TimeChart, { props })
    const svg = w.get('svg[role="img"]')
    // A stack is summarised by its total.
    expect(svg.attributes('aria-label')).toBe('Anfragen pro Sekunde: im Mittel 11,667, höchstens 14 um 10:10')
    expect(w.findAll('path[data-series]')).toHaveLength(3)
    expect(w.find('[data-slot="total-line"]').exists()).toBe(true)
    expect(w.find('path[data-series="passed"]').attributes('d')).not.toMatch(/[CQS]/)
    expect(w.findAll('[data-slot="marker"]')).toHaveLength(1)
  })
  it('shows the same data as a table on request, gaps as "keine Daten"', async () => {
    const w = mount(TimeChart, { props })
    expect(w.find('table tbody').exists()).toBe(false)
    await w.get('button').trigger('click')
    expect(w.get('button').text()).toBe('Als Diagramm zeigen')
    const rows = w.findAll('table tbody tr')
    expect(rows).toHaveLength(4)
    expect(rows[2]!.text()).toContain('keine Daten')
    expect(w.findAll('table thead th').map(t => t.text())).toEqual(['Zeitpunkt', 'Gesamt', 'Durchgelassen', 'Gesperrt', 'Erkannt'])
    expect(rows[3]!.text()).toContain('Neustart von Schild')
  })
  it('moves the crosshair with the keyboard and shows a tooltip', async () => {
    const w = mount(TimeChart, { props })
    const svg = w.get('svg[role="img"]')
    await svg.trigger('keydown', { key: 'Home' })
    expect(w.get('[data-slot="tooltip"]').text()).toContain('10:00')
    await svg.trigger('keydown', { key: 'ArrowRight' })
    expect(w.get('[data-slot="tooltip"]').text()).toContain('Durchgelassen')
    expect(w.get('[data-slot="tooltip-total"]').text()).toContain('Gesamt')
    expect(w.get('[data-slot="tooltip-total"]').text()).toContain('14')
    // One neutral dot on the stack top, never one per layer in a layer colour; lines keep their own dot.
    const dots = w.findAll('[data-slot="crosshair"] circle')
    expect(dots.map(d => d.attributes('data-dot'))).toEqual(['stack', 'would'])
    expect(dots[0]!.attributes('fill')).toBe('var(--card)')
    await svg.trigger('keydown', { key: 'Escape' })
    expect(w.find('[data-slot="tooltip"]').exists()).toBe(false)
  })
})
