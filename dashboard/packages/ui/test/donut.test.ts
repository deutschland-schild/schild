import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import DonutChart from '../src/components/app/DonutChart.vue'
import { arcPath, donutAngles } from '../src/lib/chart'

describe('donut helpers', () => {
  it('splits a full circle by share and skips empty values', () => {
    const a = donutAngles([3, 1, 0])
    expect(a[0]!.share).toBe(0.75)
    expect(a[1]!.a1).toBeCloseTo(Math.PI * 2)
    expect(a[2]!.share).toBe(0)
    expect(donutAngles([0, 0]).every(x => x.share === 0)).toBe(true)
  })
  it('draws a ring segment, a full ring as two halves, nothing for an empty slice', () => {
    expect(arcPath(60, 60, 40, 56, 0, Math.PI / 2)).toMatch(/^M60 4 A56 56 0 0 1 116 60 L100 60 A40 40 0 0 0 60 20 Z$/)
    expect(arcPath(60, 60, 40, 56, 0, Math.PI * 2).match(/Z/g)).toHaveLength(2)
    expect(arcPath(60, 60, 40, 56, 1, 1)).toBe('')
  })
})

describe('DonutChart', () => {
  const slices = [
    { id: 'mobile', label: 'Mobil', value: 60, color: 'var(--chart-1)', clickable: true },
    { id: 'desktop', label: 'Desktop', value: 30, color: 'var(--chart-2)', clickable: true },
    { id: 'other', label: 'Andere', value: 10, color: 'var(--tone-neutral)', other: true },
  ]
  it('names every slice with its share, the largest in the centre, and emits clickable ones only', async () => {
    const w = mount(DonutChart, { props: { slices, label: 'Anfragen nach Gerät' } })
    expect(w.find('svg').attributes('aria-label')!.replace(/\s/g, ' ')).toBe('Anfragen nach Gerät: Mobil 60 %, Desktop 30 %, Andere 10 %')
    expect(w.findAll('path[data-slice]')).toHaveLength(3)
    expect(w.text()).toMatch(/60\s%/)
    await w.find('[data-row="desktop"] button').trigger('click')
    expect(w.emitted('select')).toEqual([['desktop']])
    expect(w.find('[data-row="other"] button').exists()).toBe(false)
    await w.find('[data-slice="other"]').trigger('click')
    expect(w.emitted('select')).toHaveLength(1)
  })
  it('has a table view with counts and shares', async () => {
    const w = mount(DonutChart, { props: { slices, label: 'Anfragen nach Gerät', unit: 'Anfragen' } })
    await w.find('button[aria-expanded]').trigger('click')
    const rows = w.findAll('tbody tr')
    expect(rows).toHaveLength(3)
    expect(rows[0]!.text()).toContain('Mobil')
    expect(rows[0]!.text()).toMatch(/60\s%/)
  })
})
