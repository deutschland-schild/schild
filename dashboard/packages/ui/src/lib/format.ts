/** German formatting helpers for the dashboards. */

export const LOCALE = 'de-DE'

const numberFmt = new Intl.NumberFormat(LOCALE)
const compactFmt = new Intl.NumberFormat(LOCALE, { notation: 'compact', maximumFractionDigits: 1 })
const percentFmt = new Intl.NumberFormat(LOCALE, { style: 'percent', maximumFractionDigits: 1 })
const dateTimeFmt = new Intl.DateTimeFormat(LOCALE, { dateStyle: 'medium', timeStyle: 'medium' })
const relativeFmt = new Intl.RelativeTimeFormat(LOCALE, { numeric: 'auto' })

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–'
  return numberFmt.format(value)
}

export function formatCompact(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–'
  return compactFmt.format(value)
}

export function formatPercent(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || Number.isNaN(ratio)) return '–'
  return percentFmt.format(ratio)
}

export function toDate(value: Date | string | number): Date {
  return value instanceof Date ? value : new Date(value)
}

export function formatDateTime(value: Date | string | number): string {
  const d = toDate(value)
  return Number.isNaN(d.getTime()) ? '–' : dateTimeFmt.format(d)
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
  ['second', 1],
]

/** "vor 5 Minuten", "gerade eben", "in 2 Stunden". */
export function formatRelative(value: Date | string | number, now: Date = new Date()): string {
  const d = toDate(value)
  if (Number.isNaN(d.getTime())) return '–'
  const diffSec = Math.round((d.getTime() - now.getTime()) / 1000)
  if (Math.abs(diffSec) < 10) return 'gerade eben'
  for (const [unit, sec] of UNITS) {
    if (Math.abs(diffSec) >= sec || unit === 'second') {
      return relativeFmt.format(Math.round(diffSec / sec), unit)
    }
  }
  return relativeFmt.format(diffSec, 'second')
}

/** ZZ is "unknown" in the contracts (loopback and private addresses, no entry in the database); XX is the same in some databases. */
export function isUnknownCountry(countryCode: string | null | undefined): boolean {
  return !countryCode || /^(?:ZZ|XX)$/i.test(countryCode)
}

/** Regional indicator flag emoji for an ISO 3166-1 alpha-2 code, or '' if invalid or unknown (no flag exists, the letters would show as boxes). */
export function flagEmoji(countryCode: string | null | undefined): string {
  if (!countryCode || !/^[A-Za-z]{2}$/.test(countryCode) || isUnknownCountry(countryCode)) return ''
  const base = 0x1f1e6
  const cc = countryCode.toUpperCase()
  return String.fromCodePoint(base + cc.charCodeAt(0) - 65, base + cc.charCodeAt(1) - 65)
}

let regionNames: Intl.DisplayNames | undefined
/** German country name for an ISO code, falls back to the code. */
export function countryName(countryCode: string | null | undefined): string {
  if (!countryCode || isUnknownCountry(countryCode)) return 'Unbekannt'
  try {
    regionNames ??= new Intl.DisplayNames([LOCALE], { type: 'region' })
    return regionNames.of(countryCode.toUpperCase()) ?? countryCode
  }
  catch {
    return countryCode
  }
}

/** True for IPv6 literals (contains a colon). */
export function isIPv6(ip: string): boolean {
  return ip.includes(':')
}

const decimalFmt = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 1 })
const decimal2Fmt = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 2 })

/** Small numbers with up to one decimal ("0,8", "42", "1.234"); below 1 up to two decimals. */
export function formatDecimal(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–'
  if (Math.abs(value) >= 100) return numberFmt.format(Math.round(value))
  return (Math.abs(value) < 1 && value !== 0 ? decimal2Fmt : decimalFmt).format(value)
}

const BYTE_UNITS = ['B', 'kB', 'MB', 'GB', 'TB', 'PB']

/** Bytes in decimal units ("1,2 GB"), as df -H and most operators read them. */
export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–'
  let v = Math.abs(value)
  let u = 0
  while (v >= 1000 && u < BYTE_UNITS.length - 1) {
    v /= 1000
    u++
  }
  const s = u === 0 ? numberFmt.format(Math.round(v)) : decimalFmt.format(v)
  return `${value < 0 ? '-' : ''}${s} ${BYTE_UNITS[u]}`
}

/** Milliseconds: "0,4 ms", "12 ms", "1,4 s". */
export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '–'
  if (value >= 1000) return `${decimalFmt.format(value / 1000)} s`
  if (value >= 10) return `${numberFmt.format(Math.round(value))} ms`
  return `${decimalFmt.format(value)} ms`
}

/** Duration in words: "45 Sekunden", "12 Minuten", "3 Stunden", "2 Tage". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || Number.isNaN(seconds)) return '–'
  const s = Math.max(0, Math.round(seconds))
  const pick = (n: number, one: string, many: string) => `${numberFmt.format(n)} ${n === 1 ? one : many}`
  if (s < 60) return pick(s, 'Sekunde', 'Sekunden')
  if (s < 3600) return pick(Math.round(s / 60), 'Minute', 'Minuten')
  if (s < 2 * 86400) return pick(Math.round(s / 3600), 'Stunde', 'Stunden')
  return pick(Math.round(s / 86400), 'Tag', 'Tage')
}
