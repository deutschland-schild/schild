// Deterministic demo data for the styleguide. Documentation address ranges only (RFC 5737 / RFC 3849).

export interface DemoEvent {
  id: string
  time: string
  type: 'schild.request.blocked.v1' | 'schild.request.evaluated.v1' | 'schild.session.flagged.v1'
  ip: string
  country: string
  asn: number
  asnOrg: string
  method: string
  path: string
  rule: string | null
  score: number
}

function mulberry32(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6D2B79F5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const NETS: [string, string, number, string][] = [
  ['192.0.2.', 'DE', 3320, 'Deutsche Telekom'],
  ['198.51.100.', 'NL', 14061, 'DigitalOcean'],
  ['203.0.113.', 'US', 16509, 'Amazon'],
  ['2001:db8::', 'FR', 16276, 'OVH'],
  ['192.0.2.', 'AT', 8447, 'A1 Telekom'],
]
const PATHS = ['/wp-login.php', '/xmlrpc.php', '/.env', '/kontakt', '/shop/warenkorb', '/api/login', '/wp-admin/admin-ajax.php']
const RULES = ['942100', '930120', '941100', '913100', null]
const TYPES: DemoEvent['type'][] = ['schild.request.blocked.v1', 'schild.request.evaluated.v1', 'schild.session.flagged.v1']

export function demoEvents(n = 120, seed = 42, now = Date.now()): DemoEvent[] {
  const rnd = mulberry32(seed)
  return Array.from({ length: n }, (_, i) => {
    const [net, country, asn, asnOrg] = NETS[Math.floor(rnd() * NETS.length)]!
    const host = Math.floor(rnd() * 250) + 1
    return {
      id: `evt-${String(i + 1).padStart(4, '0')}`,
      time: new Date(now - Math.floor(rnd() * 36 * 3600_000)).toISOString(),
      type: TYPES[Math.floor(rnd() * TYPES.length)]!,
      ip: net.includes(':') ? `${net}${host.toString(16)}` : `${net}${host}`,
      country,
      asn,
      asnOrg,
      method: rnd() > 0.3 ? 'GET' : 'POST',
      path: PATHS[Math.floor(rnd() * PATHS.length)]!,
      rule: RULES[Math.floor(rnd() * RULES.length)]!,
      score: Math.round(rnd() * 100) / 10,
    }
  })
}

export function demoSeries(n = 24, seed = 7, base = 400, spread = 250): number[] {
  const rnd = mulberry32(seed)
  return Array.from({ length: n }, (_, i) => Math.round(base + Math.sin(i / 3) * spread * 0.4 + rnd() * spread))
}

/** Example data of a local event (documentation address and ASN only, RFC 5737 and RFC 5398). */
export const demoEventData = {
  method: 'GET',
  path: '/produkte/',
  outcome: 'blocked',
  score: 45,
  rules: [{ id: 942100, source: 'crs', severity: 'critical' }],
  client: { ip: '203.0.113.42', geo: { country: 'NL', asn: 64500, net_class: 'hosting' } },
}

/** Kontext strip: one hour-like wave in 10 s steps with a short burst of alerts (made-up numbers). */
export const demoStrip = Array.from({ length: 61 }, (_, i) => {
  const requests = Math.round(40 + 18 * Math.sin(i / 6) + (i % 7))
  const burst = i >= 28 && i <= 33
  return { t: new Date(Date.UTC(2026, 9, 29, 14, 0, i * 10)).toISOString().replace(/\.\d{3}Z$/, 'Z'), requests, stopped: burst ? 14 : i % 9 === 0 ? 1 : 0, would_block: burst ? 4 : 0, detections: burst ? 18 : 0 }
})

/** Länder map: requests per country (made-up numbers). */
export const demoCountries = [
  ['DE', 182_400], ['AT', 11_200], ['CH', 8_100], ['NL', 6_300], ['US', 15_900], ['FR', 2_100], ['GB', 1_400], ['PL', 900], ['BR', 310], ['IN', 120], ['JP', 40], ['AU', 9],
].map(([key, requests]) => ({ key: key as string, requests: requests as number, stopped: Math.round((requests as number) * 0.02), would_block: 0 }))
