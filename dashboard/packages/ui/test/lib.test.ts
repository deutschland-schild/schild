import { describe, expect, it } from 'vitest'
import { areaPath, describeTrend, linePath, niceStep, toPoints, yScale } from '../src/lib/chart'
import { countryName, flagEmoji, formatNumber, formatPercent, formatRelative, isIPv6 } from '../src/lib/format'

describe('format', () => {
  it('formats German numbers and percent', () => {
    expect(formatNumber(1234567)).toBe('1.234.567')
    expect(formatNumber(null)).toBe('–')
    expect(formatPercent(0.125)).toMatch(/12,5\s?%/)
  })
  it('formats relative times', () => {
    const now = new Date('2026-10-26T12:00:00Z')
    expect(formatRelative(new Date('2026-10-26T11:59:55Z'), now)).toBe('gerade eben')
    expect(formatRelative(new Date('2026-10-26T11:55:00Z'), now)).toBe('vor 5 Minuten')
    expect(formatRelative(new Date('2026-10-25T12:00:00Z'), now)).toBe('gestern')
    expect(formatRelative('not a date', now)).toBe('–')
  })
  it('builds flag emoji and country names', () => {
    expect(flagEmoji('de')).toBe('🇩🇪')
    expect(flagEmoji('XYZ')).toBe('')
    expect(flagEmoji(null)).toBe('')
    // ZZ is "unknown" (127.0.0.1): no flag exists, the letters would show as boxes.
    expect(flagEmoji('ZZ')).toBe('')
    expect(countryName('ZZ')).toBe('Unbekannt')
    expect(countryName('DE')).toBe('Deutschland')
    expect(countryName(undefined)).toBe('Unbekannt')
  })
  it('detects IPv6', () => {
    expect(isIPv6('2001:db8::1')).toBe(true)
    expect(isIPv6('192.0.2.1')).toBe(false)
  })
})

describe('chart helpers', () => {
  it('computes nice ticks from zero', () => {
    expect(niceStep(100, 4)).toBe(25)
    expect(yScale([3, 7, 42])).toEqual({ min: 0, max: 60, ticks: [0, 20, 40, 60] })
    expect(yScale([]).max).toBe(1)
  })
  it('maps values to points and paths', () => {
    const pts = toPoints([0, 5, 10], 100, 50)
    expect(pts).toEqual([{ x: 0, y: 50 }, { x: 50, y: 25 }, { x: 100, y: 0 }])
    expect(linePath(pts)).toBe('M0 50 L50 25 L100 0')
    expect(areaPath(pts, 50)).toBe('M0 50 L50 25 L100 0 L100 50 L0 50 Z')
    expect(areaPath([], 50)).toBe('')
  })
  it('describes trends for screen readers', () => {
    expect(describeTrend([3, 15, 12])).toBe('von 3 auf 12, Höchstwert 15')
    expect(describeTrend([])).toBe('keine Daten')
  })
})
