import { describe, expect, it } from 'vitest'
import { hourlyWindow } from '../src/lib/timeline'

describe('hourlyWindow', () => {
  const now = Date.parse('2026-10-26T20:17:00Z')

  it('fills 24 hourly buckets ending with the current hour', () => {
    const w = hourlyWindow([{ bucket: '2026-10-26T20:00:00Z', signals: 17, issuers: 3 }], now)
    expect(w).toHaveLength(24)
    expect(w.at(-1)).toEqual({ bucket: '2026-10-26T20:00:00.000Z', signals: 17, issuers: 3 })
    expect(w[0]!.bucket).toBe('2026-10-25T21:00:00.000Z')
    expect(w.slice(0, 23).every(b => b.signals === 0 && b.issuers === 0)).toBe(true)
  })

  it('drops buckets outside the window and merges buckets of the same hour', () => {
    const w = hourlyWindow([
      { bucket: '2026-10-20T10:00:00Z', signals: 5, issuers: 1 },
      { bucket: '2026-10-26T18:00:00Z', signals: 2, issuers: 1 },
      { bucket: '2026-10-26T18:30:00Z', signals: 3, issuers: 2 },
    ], now)
    expect(w.reduce((a, b) => a + b.signals, 0)).toBe(5)
    expect(w.find(b => b.bucket === '2026-10-26T18:00:00.000Z')).toEqual({ bucket: '2026-10-26T18:00:00.000Z', signals: 5, issuers: 2 })
  })
})
