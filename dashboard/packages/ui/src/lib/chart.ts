/** Small, dependency-free helpers for SVG charts. */

export interface Point { x: number, y: number }

export interface Scale {
  min: number
  max: number
  ticks: number[]
}

/** "Nice" rounded step for axis ticks. */
export function niceStep(range: number, targetTicks = 4): number {
  if (range <= 0 || !Number.isFinite(range)) return 1
  const raw = range / targetTicks
  const mag = 10 ** Math.floor(Math.log10(raw))
  const norm = raw / mag
  const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10
  return nice * mag
}

/** Linear y scale starting at zero (counts are never negative in the dashboards). */
export function yScale(values: number[], targetTicks = 4): Scale {
  const max = Math.max(0, ...values.filter(Number.isFinite))
  if (max === 0) return { min: 0, max: 1, ticks: [0, 1] }
  const step = niceStep(max, targetTicks)
  const top = Math.ceil(max / step) * step
  const ticks: number[] = []
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(Number(v.toFixed(10)))
  return { min: 0, max: top, ticks }
}

/** Map values to points inside a width x height box (y grows downwards). */
export function toPoints(values: number[], width: number, height: number, max?: number, padY = 0): Point[] {
  if (values.length === 0) return []
  const top = max ?? Math.max(...values, 0)
  const span = top > 0 ? top : 1
  const stepX = values.length > 1 ? width / (values.length - 1) : 0
  return values.map((v, i) => ({
    x: values.length > 1 ? i * stepX : width / 2,
    y: padY + (height - 2 * padY) * (1 - (Number.isFinite(v) ? v : 0) / span),
  }))
}

const r = (n: number) => Math.round(n * 100) / 100

export function linePath(points: Point[]): string {
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'}${r(p.x)} ${r(p.y)}`).join(' ')
}

export function areaPath(points: Point[], baseline: number): string {
  if (points.length === 0) return ''
  const first = points[0]!
  const last = points[points.length - 1]!
  return `${linePath(points)} L${r(last.x)} ${r(baseline)} L${r(first.x)} ${r(baseline)} Z`
}

/** Short text summary for screen readers: "von 3 auf 12, Höchstwert 15". */
export function describeTrend(values: number[], format: (n: number) => string = String): string {
  if (values.length === 0) return 'keine Daten'
  const first = values[0]!
  const last = values[values.length - 1]!
  const max = Math.max(...values)
  return `von ${format(first)} auf ${format(last)}, Höchstwert ${format(max)}`
}

/** A value of a time series; null (or undefined) is a gap: no data for that step. */
export type MaybeNumber = number | null | undefined

const finite = (v: MaybeNumber): v is number => typeof v === 'number' && Number.isFinite(v)

/** Inclusive index runs of consecutive values that are not gaps. */
export function segmentsOf(values: MaybeNumber[]): [number, number][] {
  const out: [number, number][] = []
  let start = -1
  for (let i = 0; i <= values.length; i++) {
    const ok = i < values.length && finite(values[i])
    if (ok && start < 0) start = i
    if (!ok && start >= 0) {
      out.push([start, i - 1])
      start = -1
    }
  }
  return out
}

/** Line path with gaps: one subpath per run; a single point becomes a short dash. */
export function gapLinePath(values: MaybeNumber[], xOf: (i: number) => number, yOf: (v: number) => number): string {
  return segmentsOf(values).map(([a, b]) => {
    if (a === b) {
      const y = r(yOf(values[a] as number))
      return `M${r(xOf(a) - 1)} ${y} L${r(xOf(a) + 1)} ${y}`
    }
    const parts: string[] = []
    for (let i = a; i <= b; i++) parts.push(`${i === a ? 'M' : 'L'}${r(xOf(i))} ${r(yOf(values[i] as number))}`)
    return parts.join(' ')
  }).join(' ')
}

/**
 * Stack layers bottom-up. A step where any layer is a gap is a gap in every band,
 * so a stack never pretends a missing layer was zero.
 */
export function stackLayers(layers: MaybeNumber[][]): { lo: (number | null)[], hi: (number | null)[] }[] {
  const n = Math.max(0, ...layers.map(l => l.length))
  const gap = Array.from({ length: n }, (_, i) => layers.some(l => !finite(l[i])))
  const base: number[] = Array.from({ length: n }, () => 0)
  return layers.map((l) => {
    const lo: (number | null)[] = []
    const hi: (number | null)[] = []
    for (let i = 0; i < n; i++) {
      if (gap[i]) {
        lo.push(null)
        hi.push(null)
        continue
      }
      lo.push(base[i]!)
      base[i] = base[i]! + (l[i] as number)
      hi.push(base[i]!)
    }
    return { lo, hi }
  })
}

/** Closed area between two lines (a stack band), one subpath per run without gaps. */
export function bandPath(lo: MaybeNumber[], hi: MaybeNumber[], xOf: (i: number) => number, yOf: (v: number) => number): string {
  return segmentsOf(hi).map(([a, b]) => {
    // A lone point gets a 2 px wide band so it stays visible.
    const xs = a === b ? [xOf(a) - 1, xOf(a) + 1] : null
    const idx = a === b ? [a, a] : Array.from({ length: b - a + 1 }, (_, k) => a + k)
    const x = (k: number) => xs ? xs[k]! : xOf(idx[k]!)
    const top = idx.map((i, k) => `${k === 0 ? 'M' : 'L'}${r(x(k))} ${r(yOf(hi[i] as number))}`)
    const bottom = idx.map((i, k) => `L${r(x(k))} ${r(yOf((lo[i] ?? 0) as number))}`).reverse()
    return `${[...top, ...bottom].join(' ')} Z`
  }).join(' ')
}

/** Sum of the stacked layers at one step, or null when any layer is a gap there. */
export function stackTotal(layers: MaybeNumber[][], i: number): number | null {
  if (!layers.length) return null
  let sum = 0
  for (const l of layers) {
    const v = l[i]
    if (!finite(v)) return null
    sum += v
  }
  return sum
}

const TICK_INTERVALS_S = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800]

/**
 * Indices of x-axis ticks on round local times (full 10 minutes, hours, midnights): the smallest interval
 * that is a multiple of the step and yields at most `maxTicks` ticks. Without times: even spacing.
 */
export function timeTicks(times: number[], maxTicks: number, count = times.length): number[] {
  const max = Math.max(2, Math.floor(maxTicks))
  const even = (n: number) => {
    const every = Math.max(1, Math.ceil(n / max))
    return Array.from({ length: n }, (_, i) => i).filter(i => i % every === 0)
  }
  if (times.length < 2) return even(count)
  const stepS = Math.max(1, Math.round((times[1]! - times[0]!) / 1000))
  const spanS = stepS * (times.length - 1)
  const local = (t: number) => Math.round(t / 1000) - new Date(t).getTimezoneOffset() * 60
  for (const iv of TICK_INTERVALS_S) {
    if (iv % stepS !== 0 || spanS / iv > max) continue
    const out = times.map((t, i) => local(t) % iv === 0 ? i : -1).filter(i => i >= 0)
    if (out.length >= 2) return out
  }
  return even(times.length)
}

/** Mean and maximum (with its index) of a series, ignoring gaps; null without data. */
export function seriesStats(values: MaybeNumber[]): { mean: number, max: number, maxIndex: number } | null {
  let sum = 0
  let n = 0
  let max = -Infinity
  let maxIndex = -1
  values.forEach((v, i) => {
    if (!finite(v)) return
    sum += v
    n++
    if (v > max) {
      max = v
      maxIndex = i
    }
  })
  return n ? { mean: sum / n, max, maxIndex } : null
}

/**
 * Ring segment (donut slice) from angle a0 to a1 (radians, 0 = 12 o'clock, clockwise) between the radii
 * rInner and rOuter around (cx, cy). A full circle is drawn as two halves so the path never collapses.
 */
export function arcPath(cx: number, cy: number, rInner: number, rOuter: number, a0: number, a1: number): string {
  const span = a1 - a0
  if (!(span > 0)) return ''
  if (span >= Math.PI * 2 - 1e-6) {
    const mid = a0 + Math.PI
    return `${arcPath(cx, cy, rInner, rOuter, a0, mid)} ${arcPath(cx, cy, rInner, rOuter, mid, a0 + Math.PI * 2)}`
  }
  const pt = (rad: number, a: number) => `${r(cx + rad * Math.sin(a))} ${r(cy - rad * Math.cos(a))}`
  const large = span > Math.PI ? 1 : 0
  return [
    `M${pt(rOuter, a0)}`,
    `A${rOuter} ${rOuter} 0 ${large} 1 ${pt(rOuter, a1)}`,
    `L${pt(rInner, a1)}`,
    `A${rInner} ${rInner} 0 ${large} 0 ${pt(rInner, a0)}`,
    'Z',
  ].join(' ')
}

/** Start and end angle of each share around a full circle (radians, clockwise from 12 o'clock). */
export function donutAngles(values: number[]): { a0: number, a1: number, share: number }[] {
  const total = values.reduce((a, v) => a + (v > 0 ? v : 0), 0)
  let acc = 0
  return values.map((v) => {
    const share = total > 0 && v > 0 ? v / total : 0
    const a0 = acc * Math.PI * 2
    acc += share
    return { a0, a1: acc * Math.PI * 2, share }
  })
}
