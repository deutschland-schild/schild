import { describe, expect, it } from 'vitest'
import { DONUTS, donutSlices, newReturningSlices, OTHER_COLOR, seriesSum, stepText } from '../src/lib/requests-overview'

/** Überblick of Zugriffe: donut slices, new and returning visitors, sums. */
describe('Zugriffe overview helpers', () => {
  it('groups bot categories into Menschen, Suchmaschinen, KI-Crawler and Andere Bots, largest first', () => {
    const v = donutSlices(DONUTS.bots, [
      { key: 'likely_browser', requests: 800 },
      { key: 'search_engine', requests: 60 },
      { key: 'ai_training', requests: 30 },
      { key: 'ai_search', requests: 20 },
      { key: 'seo_tool', requests: 70 },
    ], 20)
    expect(v.slices.map(s => s.id)).toEqual(['likely_browser', 'bots', 'search_engine', 'ai'])
    expect(v.slices.find(s => s.id === 'bots')!.value).toBe(90)
    expect(v.slices.some(s => s.id === '_other')).toBe(false)
    expect(v.slices.find(s => s.id === 'ai')!.tab).toBe('bots')
    expect(v.slices[0]!.filter).toBe('bot_category:likely_browser')
    expect(v.total).toBe(1000)
  })

  it('keeps colours with the entity, folds the rest into a grey Andere and leaves out unnamed devices', () => {
    const a = donutSlices(DONUTS.browser, [{ key: 'chrome', requests: 10 }, { key: 'safari', requests: 50 }, { key: 'opera', requests: 5 }, { key: 'none', requests: 40 }])
    const b = donutSlices(DONUTS.browser, [{ key: 'chrome', requests: 50 }, { key: 'safari', requests: 10 }])
    expect(a.slices.find(s => s.id === 'chrome')!.color).toBe(b.slices.find(s => s.id === 'chrome')!.color)
    expect(a.slices.at(-1)).toMatchObject({ id: '_other', label: 'Andere', value: 5, color: OTHER_COLOR, other: true })
    expect(a.excluded).toBe(40)
    expect(a.total).toBe(65)
    expect(a.slices.length).toBeLessThanOrEqual(6)
    const d = donutSlices(DONUTS.device, [{ key: 'mobile', requests: 5 }, { key: 'unknown', requests: 9 }, { key: 'other', requests: 1 }])
    expect(d.slices.map(s => s.label)).toEqual(['Mobil', 'Andere'])
    expect(d.excluded).toBe(9)
  })

  it('computes new and returning visitors, sums and steps', () => {
    expect(newReturningSlices(1000, 380).map(s => [s.id, s.value])).toEqual([['returning', 620], ['new', 380]])
    expect(newReturningSlices(null, 3)).toEqual([])
    expect(seriesSum([1, null, 2])).toBe(3)
    expect(seriesSum([null])).toBeNull()
    expect(stepText(600)).toBe('je 10 Minuten')
    expect(stepText(60)).toBe('je Minute')
    expect(stepText(10)).toBe('je 10 Sekunden')
  })
})
