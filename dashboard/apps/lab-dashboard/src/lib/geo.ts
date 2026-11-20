import type { Count } from '@/api/types'
import { countryName, flagEmoji } from '@schild/ui'

/** "🇳🇱 NL" style label; country names in German for screen readers via title. */
export function countryLabel(code: string | number): string {
  const c = String(code)
  return `${flagEmoji(c)} ${countryName(c)}`.trim()
}

export function asnLabel(asn: string | number): string {
  return `AS${asn}`
}

export function toBarItems(counts: Count[] | undefined, label: (k: string | number) => string = String) {
  return (counts ?? []).map(c => ({ id: String(c.key), label: label(c.key), value: c.count }))
}

const NET_CLASS: Record<string, string> = {
  hosting: 'Rechenzentrum',
  residential: 'Privatanschluss',
  mobile: 'Mobilfunk',
  business: 'Firmennetz',
  education: 'Hochschule',
  government: 'Behörde',
  vpn: 'VPN',
  tor: 'Tor',
  unknown: 'unbekannt',
}

/** Net class in German with the code, e.g. "Rechenzentrum (hosting)". */
export function netClassLabel(key: string | number): string {
  const k = String(key)
  return NET_CLASS[k] ? `${NET_CLASS[k]} (${k})` : k
}
