/** One hourly bucket of a pattern timeline (as the API returns it: only hours with signals). */
export interface TimelineBucket {
  bucket: string
  signals: number
  issuers: number
}

const HOUR = 3_600_000

/**
 * Densify a sparse hourly timeline into exactly `hours` buckets ending with the current hour,
 * so a chart always shows the whole window (and a single active hour is not a lone, invisible point).
 * Buckets outside the window are dropped.
 */
export function hourlyWindow(timeline: readonly TimelineBucket[], now = Date.now(), hours = 24): TimelineBucket[] {
  const end = Math.floor(now / HOUR) * HOUR
  const byHour = new Map<number, TimelineBucket>()
  for (const t of timeline) {
    const h = Math.floor(Date.parse(t.bucket) / HOUR) * HOUR
    const prev = byHour.get(h)
    byHour.set(h, prev ? { bucket: prev.bucket, signals: prev.signals + t.signals, issuers: Math.max(prev.issuers, t.issuers) } : t)
  }
  const out: TimelineBucket[] = []
  for (let h = end - (hours - 1) * HOUR; h <= end; h += HOUR) {
    const t = byHour.get(h)
    out.push({ bucket: new Date(h).toISOString(), signals: t?.signals ?? 0, issuers: t?.issuers ?? 0 })
  }
  return out
}
