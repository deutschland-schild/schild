/**
 * Mock of the "requests" tag (contracts v0.5, MVP-22, D35): a deterministic request ring built on the
 * monitoring model, so the list, the Kontext of an event, the bot overview and the alert rates per rule
 * and page tell the same story as the overview (verein.example: login wave and a false positive on the
 * join form; shop.example: slow app and a false positive on the search). Records are sparse (a few per
 * 15 s slot and website) but realistic; the stored events join their record by event id.
 * Mock mode and tests only. Every visitor, address and operator here is made up (documentation ranges).
 */
import type { HttpHandler } from 'msw'
import type { MockState, StoredEvent } from './data'
import type { MockSite, MonitoringMock } from './monitoring'
import type { BotCategory, BotOverview, BotVerification, PageAlert, RequestContext, RequestOutcome, RequestRecord, RuleAlert, SiteStripPoint } from '@/api/requests'
import { http, HttpResponse } from 'msw'
import { effectiveAction } from '@/lib/crawlers'
import { countersAt, distOf, latency, REQUEST_RING_MS } from './monitoring'
import { fpHints } from './websites'

const isoS = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
const SLOT_MS = 15_000
/** Records read per page before scan_capped (the gateway reads 100000; the mock ring is about 30x sparser). */
export const MOCK_SCAN_CAP = 3000

function hash(...parts: (string | number)[]): number {
  let h = 2166136261
  for (const ch of parts.join('|')) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0
  h ^= h >>> 13
  h = Math.imul(h, 0x5BD1E995) >>> 0
  h ^= h >>> 15
  return (h >>> 0) / 4294967296
}
function hex(seed: string, n: number): string {
  let out = ''
  for (let k = 0; out.length < n; k++) out += Math.floor(hash(seed, k) * 4294967296).toString(16).padStart(8, '0')
  return out.slice(0, n)
}
const pick = <T>(xs: readonly T[], r: number): T => xs[Math.min(xs.length - 1, Math.floor(r * xs.length))]!
/** Weighted pick from [value, weight] pairs. */
function weighted<T>(xs: readonly (readonly [T, number])[], r: number): T {
  const total = xs.reduce((a, [, w]) => a + w, 0)
  let x = r * total
  for (const [v, w] of xs) {
    x -= w
    if (x <= 0) return v
  }
  return xs[xs.length - 1]![0]
}
const dayOf = (ms: number) => Math.floor(ms / 86400_000)
/** Daily visitor key: same client, same UTC day, same key (D35); never across days. */
export const visitorKey = (client: string, ms: number) => `v1-${hex(`visitor:${client}:${dayOf(ms)}`, 16)}`

// ------------------------------------------------------------------ bot catalogue (made-up counts)

export interface MockBot { id: string, name: string, operator: string, category: BotCategory, token: string, weight: number, ranges: 'fresh' | 'stale' | 'none', respects: 'yes' | 'no' | 'unclear', readsRobots: boolean }
export const MOCK_BOTS: MockBot[] = [
  { id: 'googlebot', name: 'Googlebot', operator: 'Google', category: 'search_engine', token: 'Googlebot', weight: 0.55, ranges: 'fresh', respects: 'yes', readsRobots: true },
  { id: 'bingbot', name: 'Bingbot', operator: 'Microsoft', category: 'search_engine', token: 'bingbot', weight: 0.25, ranges: 'fresh', respects: 'yes', readsRobots: true },
  { id: 'applebot', name: 'Applebot', operator: 'Apple', category: 'search_engine', token: 'Applebot', weight: 0.08, ranges: 'fresh', respects: 'yes', readsRobots: true },
  { id: 'gptbot', name: 'GPTBot', operator: 'OpenAI', category: 'ai_training', token: 'GPTBot', weight: 0.4, ranges: 'fresh', respects: 'yes', readsRobots: true },
  { id: 'claudebot', name: 'ClaudeBot', operator: 'Anthropic', category: 'ai_training', token: 'ClaudeBot', weight: 0.2, ranges: 'none', respects: 'yes', readsRobots: true },
  { id: 'bytespider', name: 'Bytespider', operator: 'ByteDance', category: 'ai_training', token: 'Bytespider', weight: 0.3, ranges: 'none', respects: 'no', readsRobots: false },
  { id: 'ccbot', name: 'CCBot', operator: 'Common Crawl', category: 'ai_training', token: 'CCBot', weight: 0.1, ranges: 'none', respects: 'unclear', readsRobots: false },
  { id: 'oai-searchbot', name: 'OAI-SearchBot', operator: 'OpenAI', category: 'ai_search', token: 'OAI-SearchBot', weight: 0.6, ranges: 'fresh', respects: 'yes', readsRobots: true },
  { id: 'perplexitybot', name: 'PerplexityBot', operator: 'Perplexity', category: 'ai_search', token: 'PerplexityBot', weight: 0.4, ranges: 'fresh', respects: 'unclear', readsRobots: true },
  { id: 'chatgpt-user', name: 'ChatGPT-User', operator: 'OpenAI', category: 'ai_assistant', token: 'ChatGPT-User', weight: 0.7, ranges: 'fresh', respects: 'unclear', readsRobots: false },
  { id: 'perplexity-user', name: 'Perplexity-User', operator: 'Perplexity', category: 'ai_assistant', token: 'Perplexity-User', weight: 0.3, ranges: 'fresh', respects: 'unclear', readsRobots: false },
  { id: 'amazonbot', name: 'Amazonbot', operator: 'Amazon', category: 'archive_research', token: 'Amazonbot', weight: 0.5, ranges: 'stale', respects: 'yes', readsRobots: true },
  { id: 'ia-archiver', name: 'Internet Archive', operator: 'Internet Archive', category: 'archive_research', token: 'archive.org_bot', weight: 0.5, ranges: 'none', respects: 'yes', readsRobots: true },
  { id: 'ahrefsbot', name: 'AhrefsBot', operator: 'Ahrefs', category: 'seo_tool', token: 'AhrefsBot', weight: 0.6, ranges: 'fresh', respects: 'yes', readsRobots: true },
  { id: 'semrushbot', name: 'SemrushBot', operator: 'Semrush', category: 'seo_tool', token: 'SemrushBot', weight: 0.4, ranges: 'none', respects: 'yes', readsRobots: true },
  { id: 'facebookexternalhit', name: 'Facebook-Vorschau', operator: 'Meta', category: 'preview_social', token: 'facebookexternalhit', weight: 0.6, ranges: 'none', respects: 'unclear', readsRobots: false },
  { id: 'whatsapp', name: 'WhatsApp-Vorschau', operator: 'Meta', category: 'preview_social', token: 'WhatsApp', weight: 0.4, ranges: 'none', respects: 'unclear', readsRobots: false },
  { id: 'uptimerobot', name: 'UptimeRobot', operator: 'UptimeRobot', category: 'monitoring', token: 'UptimeRobot', weight: 1, ranges: 'fresh', respects: 'unclear', readsRobots: false },
  { id: 'feedly', name: 'Feedly', operator: 'Feedly', category: 'feed_reader', token: 'Feedly', weight: 1, ranges: 'none', respects: 'unclear', readsRobots: false },
  { id: 'nuclei', name: 'Nuclei', operator: 'ProjectDiscovery', category: 'security_scanner', token: 'Nuclei', weight: 1, ranges: 'none', respects: 'no', readsRobots: false },
  { id: 'python-requests', name: 'python-requests', operator: 'Python', category: 'tool_library', token: 'python-requests', weight: 0.6, ranges: 'none', respects: 'unclear', readsRobots: false },
  { id: 'curl', name: 'curl', operator: 'curl', category: 'tool_library', token: 'curl', weight: 0.4, ranges: 'none', respects: 'unclear', readsRobots: false },
]
/** Range snapshots shipped with the release (Amazon's is older than 30 days: unknown_stale). */
function rangeSnapshots(now: number): BotOverview['ranges'] {
  const ops: [string, string, number, 'release' | 'fetch'][] = [
    ['google', 'Google', 6, 'release'], ['bing', 'Microsoft', 6, 'release'], ['apple', 'Apple', 6, 'release'], ['openai', 'OpenAI', 6, 'release'],
    ['perplexity', 'Perplexity', 6, 'release'], ['ahrefs', 'Ahrefs', 6, 'release'], ['uptimerobot', 'UptimeRobot', 6, 'release'], ['amazon', 'Amazon', 41, 'release'],
  ]
  return ops.map(([id, operator, days, source]) => ({ id, operator, fetched_at: isoS(now - days * 86400_000), stale: days > 30, source }))
}
function verificationOf(b: MockBot, r: number): BotVerification {
  if (b.ranges === 'none') return 'claimed'
  if (b.ranges === 'stale') return 'unknown_stale'
  // Someone borrows Googlebot's name from a data centre now and then.
  if (b.id === 'googlebot' && r < 0.12) return 'mismatch'
  return 'verified'
}

// ------------------------------------------------------------------ record generator

const BROWSERS = [['chrome', 0.5], ['safari', 0.26], ['firefox', 0.08], ['edge', 0.07], ['samsung', 0.04], ['opera', 0.01], ['other', 0.04]] as const
const OSES = { chrome: ['android', 'windows', 'macos', 'linux', 'chromeos'], safari: ['ios', 'macos'], firefox: ['windows', 'linux', 'android', 'macos'], edge: ['windows', 'macos'], samsung: ['android'], opera: ['windows', 'android'], other: ['other', 'linux'] } as const
const COUNTRIES = [['DE', 0.83], ['AT', 0.06], ['CH', 0.04], ['NL', 0.02], ['FR', 0.015], ['US', 0.015], ['GB', 0.01], ['IT', 0.01]] as const
const ASNS: Record<string, number> = { DE: 64510, AT: 64511, CH: 64512, NL: 64513, FR: 64514, US: 64515, GB: 64516, IT: 64517, CN: 64520, SG: 64505, RU: 64521 }
const SCAN_PATHS = ['/.env', '/wp-login.php', '/xmlrpc.php', '/.git/config', '/vendor/phpunit/{rest}', '/admin/{rest}', '/wp-admin/{rest}', '/phpmyadmin/{rest}', '/cgi-bin/{rest}']
const SCAN_RULES: Record<string, string> = { '/.env': '930130', '/wp-login.php': '930120', '/xmlrpc.php': '913100', '/.git/config': '930130', '/vendor/phpunit/{rest}': '932160', '/admin/{rest}': '920350', '/wp-admin/{rest}': '930120', '/phpmyadmin/{rest}': '913100', '/cgi-bin/{rest}': '932160' }

/** Pages a person would open on this website (path templates with real traffic). */
function browsePaths(site: string): string[] {
  return distOf('path', site).filter(r => r[1] >= 0.02 && !SCAN_PATHS.includes(r[0])).map(r => r[0])
}
const isAsset = (p: string) => p.startsWith('/assets/') || p === '/feed.xml' || p === '/robots.txt'

interface Gen { m: MonitoringMock, observe: boolean }

function record(base: Partial<RequestRecord> & Pick<RequestRecord, 't' | 'site' | 'path' | 'visitor'>): RequestRecord {
  return {
    ip: `203.0.113.${Math.floor(hash(base.visitor, 'ip') * 254) + 1}`,
    user_agent: base.bot ? `Mozilla/5.0 (compatible; ${base.bot}/2.1)` : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36',
    host: base.site,
    path_kind: 'template',
    method: 'GET',
    status: 200,
    outcome: 'passed',
    anomaly_score: 0,
    country: 'DE',
    asn: 64510,
    net_class: 'residential',
    browser: 'chrome',
    os: 'windows',
    device: 'desktop',
    bot_category: 'likely_browser',
    referrer: '_direct',
    duration_ms: 42,
    bytes_out: 14_000,
    page_view: false,
    ...base,
  } as RequestRecord
}

/** exp1.25 duration scale (D35): the upper bound of the bucket, at most 25 % above the true value. */
function exp125(ms: number): number {
  const k = Math.ceil(Math.log(Math.max(0.05, ms) / 0.05) / Math.log(1.25))
  return Math.round(0.05 * 1.25 ** k * 100) / 100
}

function browserRecord(g: Gen, site: MockSite, t: number, client: string, r: (k: string) => number): RequestRecord {
  const paths = browsePaths(site.id)
  const path = pick(paths, r('path'))
  const browser = weighted(BROWSERS, hash(client, 'browser'))
  const os = pick(OSES[browser], hash(client, 'os'))
  const mobile = os === 'android' || os === 'ios'
  const country = weighted(COUNTRIES, hash(client, 'country'))
  const slow = g.m.events[site.id]?.slow
  const lat = latency(g.m, t / 1000, site.id).total.p50 * (0.4 + r('lat') * 1.6) * (slow && t >= slow.from && path !== '/assets/{file}' ? 1.4 : 1)
  const asset = isAsset(path)
  const status = asset && r('304') < 0.3 ? 304 : r('404') < 0.02 ? 404 : slow && t >= slow.from && r('5xx') < slow.errors ? 502 : 200
  const ref = asset ? '_intern' : weighted([['_direct', 0.4], ['google.com', 0.26], ['_intern', 0.18], ['bing.com', 0.03], ['ecosia.org', 0.02], ['ai:chatgpt', 0.03], ['ai:perplexity', 0.01], ['facebook.com', 0.02], ['instagram.com', 0.015], ['stadt.example', 0.01]] as const, r('ref'))
  return record({
    t: isoS(t), site: site.id, host: pick(site.hosts, hash(client, 'host')), path, visitor: visitorKey(client, t),
    status, country, asn: ASNS[country] ?? 64510, net_class: mobile && hash(client, 'net') < 0.6 ? 'mobile' : 'residential',
    browser, os, device: os === 'ios' && hash(client, 'ipad') < 0.15 ? 'tablet' : mobile ? 'mobile' : 'desktop',
    referrer: ref, duration_ms: exp125(lat), bytes_out: asset ? Math.round(8000 + r('b') * 180_000) : Math.round(9000 + r('b') * 60_000),
    page_view: !asset && status === 200,
  })
}

function botRecord(g: Gen, site: MockSite, t: number, client: string, r: (k: string) => number): RequestRecord {
  const b = weighted(MOCK_BOTS.map(x => [x, x.weight * (x.category === 'search_engine' ? 3 : x.category.startsWith('ai_') ? 2 : 1)] as const), hash(client, 'bot'))
  const verification = verificationOf(b, hash(client, 'verify'))
  const scanner = b.category === 'security_scanner'
  const path = scanner ? pick(SCAN_PATHS, r('path')) : r('robots') < 0.05 && b.readsRobots ? '/robots.txt' : pick(browsePaths(site.id), r('path'))
  const blocked = scanner && !g.observe
  const rule = scanner ? SCAN_RULES[path] : undefined
  const foreign = verification === 'mismatch'
  const country = foreign ? 'NL' : b.operator === 'ByteDance' ? 'SG' : 'US'
  return record({
    t: isoS(t), site: site.id, path, visitor: visitorKey(client, t), method: 'GET',
    status: blocked ? 403 : scanner ? 404 : 200, outcome: scanner ? (blocked ? 'blocked_waf' : 'would_block') : 'passed',
    anomaly_score: scanner ? 10 : 0, ...(rule ? { rules: [rule] } : {}),
    country, asn: foreign ? 64500 : ASNS[country] ?? 64515, net_class: 'hosting', browser: 'none', os: 'none', device: 'unknown',
    bot: b.id, bot_category: b.category, verification, referrer: '_direct',
    duration_ms: exp125(20 + r('lat') * 180), bytes_out: Math.round(4000 + r('b') * 40_000), page_view: false,
  })
}

function scannerRecord(g: Gen, site: MockSite, t: number, client: string, r: (k: string) => number): RequestRecord {
  const path = pick(SCAN_PATHS, r('path'))
  const blocked = !g.observe
  const country = pick(['NL', 'US', 'CN', 'SG', 'RU'] as const, hash(client, 'country'))
  return record({
    t: isoS(t), site: site.id, path, visitor: visitorKey(client, t), method: r('m') < 0.2 ? 'POST' : 'GET',
    status: blocked ? 403 : 404, outcome: blocked ? 'blocked_waf' : 'would_block', anomaly_score: 5 + Math.floor(r('s') * 6) * 5,
    rules: [SCAN_RULES[path] ?? '913100'], country, asn: ASNS[country] ?? 64500, net_class: 'hosting',
    browser: 'none', os: 'none', device: 'unknown', bot_category: hash(client, 'tool') < 0.5 ? 'likely_automated' : 'tool_library',
    referrer: '_direct', duration_ms: exp125(1 + r('lat') * 6), bytes_out: 640, page_view: false,
  })
}

/** Records of one website in one 15 s slot, newest first. */
function slotRecords(g: Gen, site: MockSite, slot: number): RequestRecord[] {
  const t0 = slot * SLOT_MS
  const n = Math.floor(hash(site.id, slot, 'n') * site.weight * 8 + 0.4)
  const bucket = Math.floor(slot / 20) // visitors come back within about 5 minutes
  const out: RequestRecord[] = []
  for (let i = 0; i < n; i++) {
    const r = (k: string) => hash(site.id, slot, i, k)
    const t = t0 + Math.floor(r('t') * SLOT_MS)
    const who = Math.floor(r('who') * 10)
    const client = `${site.id}:${bucket}:${who}`
    if (who <= 6) out.push(browserRecord(g, site, t, client, r))
    else if (who <= 8) out.push(botRecord(g, site, t, client, r))
    else out.push(scannerRecord(g, site, t, client, r))
  }
  return out.sort((a, b) => Date.parse(b.t) - Date.parse(a.t))
}

/** The record of a stored request event (the event joins its record by event_id). */
export function eventRecord(e: StoredEvent): RequestRecord | null {
  const s = e.summary
  if (!s.type.startsWith('schild.request.') || !s.site || !s.path) return null
  const t = Date.parse(s.time)
  const ua = e.detail.data.user_agent ?? ''
  const browserUa = /^Mozilla\/5\.0 \((Windows|Macintosh|X11|Linux|iPhone|iPad)/.test(ua) && !/bot|compatible/i.test(ua)
  const outcome: RequestOutcome = s.outcome === 'blocked' ? 'blocked_waf' : s.outcome === 'would_block' ? 'would_block' : 'passed'
  return record({
    t: isoS(t), site: s.site, host: s.host ?? s.site, path: s.path, visitor: visitorKey(s.ip ?? s.id, t),
    method: s.method ?? 'GET', status: s.status ?? 200, outcome, anomaly_score: s.score ?? 0,
    ...(s.rules?.length ? { rules: s.rules.slice(0, 3) } : {}), event_id: s.id,
    country: s.geo?.country ?? 'ZZ', asn: s.geo?.asn ?? 0, ...(s.geo?.net_class ? { net_class: s.geo.net_class as RequestRecord['net_class'] } : {}),
    browser: browserUa ? 'chrome' : 'none', os: browserUa ? (ua.includes('Windows') ? 'windows' : 'macos') : 'none', device: browserUa ? 'desktop' : 'unknown',
    bot_category: browserUa ? 'likely_browser' : /nikto|sqlmap|nuclei/i.test(ua) ? 'security_scanner' : 'likely_automated',
    referrer: '_direct', duration_ms: exp125(outcome === 'blocked_waf' ? 2 : 80), bytes_out: outcome === 'blocked_waf' ? 640 : 12_000, page_view: false,
  })
}

// ------------------------------------------------------------------ queryRequests

export interface RequestListQuery {
  from: number
  to: number
  site?: string
  path?: string
  rule?: string
  outcome?: string
  status_class?: string
  country?: string
  bot_category?: string
  bot?: string
  verification?: string
  visitor?: string
  ip?: string
  user_agent?: string
  limit: number
  cursor?: string | null
}

function matches(r: RequestRecord, q: RequestListQuery): boolean {
  if (q.path && r.path !== q.path) return false
  if (q.rule && !(r.rules ?? []).includes(q.rule)) return false
  if (q.outcome && r.outcome !== q.outcome) return false
  if (q.status_class && `${Math.floor(r.status / 100)}xx` !== q.status_class) return false
  if (q.country && r.country !== q.country) return false
  if (q.bot_category && r.bot_category !== q.bot_category) return false
  if (q.bot && r.bot !== q.bot) return false
  if (q.verification && r.verification !== q.verification) return false
  if (q.visitor && r.visitor !== q.visitor) return false
  if (q.ip && r.ip !== q.ip) return false
  if (q.user_agent && !r.user_agent?.toLowerCase().includes(q.user_agent.toLowerCase())) return false
  return true
}

/** Sample rate of the mock ring: the degraded gateway is at its size cap (consistent sampling by visitor). */
export const sampleRateOf = (st: MockState) => st.scenario === 'degraded' ? 0.5 : 1
const sampledOut = (st: MockState, r: RequestRecord) => sampleRateOf(st) < 1 && !r.event_id && hash(r.visitor, 'sample') >= sampleRateOf(st)

export function queryRequests(st: MockState, q: RequestListQuery) {
  const g: Gen = { m: st.monitoring, observe: st.settings.profile === 'test' }
  const sites = st.monitoring.sites.filter(s => !q.site || s.id === q.site)
  const events = st.events.map(e => eventRecord(e)).filter((r): r is RequestRecord => !!r && (!q.site || r.site === q.site))
  let cursor: { s: number, i: number } | null
  try {
    cursor = q.cursor ? JSON.parse(atob(q.cursor)) as { s: number, i: number } : null
  }
  catch { cursor = null }
  const first = Math.floor((q.to - 1) / SLOT_MS)
  const last = Math.floor(q.from / SLOT_MS)
  const items: RequestRecord[] = []
  let scanned = 0
  for (let slot = cursor ? cursor.s : first; slot >= last; slot--) {
    const t0 = slot * SLOT_MS
    const recs = [
      ...sites.flatMap(s => slotRecords(g, s, slot)),
      ...events.filter(r => { const t = Date.parse(r.t); return t >= t0 && t < t0 + SLOT_MS }),
    ]
      .filter(r => { const t = Date.parse(r.t); return t >= q.from && t < q.to && !sampledOut(st, r) })
      .sort((a, b) => Date.parse(b.t) - Date.parse(a.t))
    const start = cursor && slot === cursor.s ? cursor.i : 0
    for (let i = start; i < recs.length; i++) {
      scanned++
      if (matches(recs[i]!, q)) items.push(recs[i]!)
      if (items.length >= q.limit || scanned >= MOCK_SCAN_CAP) {
        const capped = scanned >= MOCK_SCAN_CAP && items.length < q.limit
        const more = i + 1 < recs.length ? { s: slot, i: i + 1 } : slot - 1 >= last ? { s: slot - 1, i: 0 } : null
        const next = more ? btoa(JSON.stringify(more)) : null
        return { from: isoS(q.from), to: isoS(q.to), items, next_cursor: next, scanned, scan_capped: capped, sample_rate: sampleRateOf(st), keep_hours: REQUEST_RING_MS / 3600_000 }
      }
    }
  }
  return { from: isoS(q.from), to: isoS(q.to), items, next_cursor: null, scanned, scan_capped: false, sample_rate: sampleRateOf(st), keep_hours: REQUEST_RING_MS / 3600_000 }
}

// ------------------------------------------------------------------ Kontext

function stripOf(m: MonitoringMock, site: string, from: number): SiteStripPoint[] {
  return Array.from({ length: 61 }, (_, k) => {
    const t = from + k * 10_000
    const c = countersAt(m, t / 1000 + 5, site)
    return { t: isoS(t), requests: Math.round(c.requests * 10), stopped: Math.round(c.stopped * 10), would_block: Math.round(c.would_block * 10), detections: Math.round(c.detections * 10) }
  })
}

/** Normal browsing around an event: the pages a member opens before and after sending a form. */
function sessionAround(g: Gen, anchor: RequestRecord, client: string): RequestRecord[] {
  const t = Date.parse(anchor.t)
  const site = g.m.sites.find(s => s.id === anchor.site)
  if (!site) return []
  const pages = browsePaths(site.id).filter(p => !isAsset(p) && p !== anchor.path)
  const steps = [-260, -200, -170, -120, -95, -40, -12, 30, 95, 180]
  return steps.map((d, k) => {
    const r = (x: string) => hash(client, k, x)
    const path = d === -12 ? anchor.path : k % 3 === 2 ? '/assets/{file}' : pick(pages, r('p'))
    return record({
      ...anchor,
      t: isoS(t + d * 1000), path, method: 'GET', status: path === '/assets/{file}' && r('c') < 0.4 ? 304 : 200, outcome: 'passed', anomaly_score: 0,
      rules: undefined, event_id: undefined, referrer: k === 0 ? 'google.com' : '_intern', page_view: !isAsset(path),
      duration_ms: exp125(30 + r('l') * 220), bytes_out: Math.round(9000 + r('b') * 50_000),
    })
  }).map(({ rules: _r, event_id: _e, ...rest }) => rest as RequestRecord)
}

/** A scanner's run: only probes, every one an alert. */
function probesAround(g: Gen, anchor: RequestRecord): RequestRecord[] {
  const t = Date.parse(anchor.t)
  const blocked = anchor.outcome !== 'would_block'
  return [-150, -110, -75, -50, -20, 25, 60].map((d, k) => {
    const path = SCAN_PATHS[(k + Math.floor(hash(anchor.visitor, 'p') * 9)) % SCAN_PATHS.length]!
    const { event_id: _e, ...rest } = anchor
    return record({ ...rest, t: isoS(t + d * 1000), path, method: 'GET', status: blocked ? 403 : 404, outcome: blocked ? 'blocked_waf' : 'would_block', rules: [SCAN_RULES[path] ?? '913100'], anomaly_score: 10, page_view: false, duration_ms: exp125(2), bytes_out: 640 })
  }).filter(r => g.m.sites.length > 0 && r.t !== anchor.t)
}

export function requestContext(st: MockState, eventId: string, now: number): RequestContext | 'not_found' {
  const e = st.events.find(x => x.summary.id === eventId)
  if (!e) return 'not_found'
  const t = Date.parse(e.summary.time)
  const from = Math.floor((t - 300_000) / 10_000) * 10_000
  const to = from + 600_000
  const site = e.summary.site ?? st.monitoring.sites[0]?.id ?? 'default'
  const total = Math.max(1, st.monitoring.sites.length)
  const inc = e.summary.incident ? st.incidents.get(e.summary.incident) : undefined
  const sites_affected = inc?.sites_affected ?? { sites: [site], count: 1, total }
  if (now - t > REQUEST_RING_MS) {
    return { event_id: eventId, state: 'expired', from: isoS(from), to: isoS(to), anchor: null, visitor_requests: [], truncated: false, site_strip: [], sites_affected }
  }
  const anchor = eventRecord(e)
  if (!anchor) return 'not_found'
  const g: Gen = { m: st.monitoring, observe: st.settings.profile === 'test' }
  const normal = anchor.browser !== 'none' && (anchor.net_class === 'residential' || anchor.net_class === 'mobile' || anchor.net_class === 'business')
  const others = st.events
    .filter(x => x !== e && x.summary.ip === e.summary.ip && Math.abs(Date.parse(x.summary.time) - t) <= 300_000)
    .map(x => eventRecord(x))
    .filter((r): r is RequestRecord => !!r)
  const around = normal ? sessionAround(g, anchor, e.summary.ip ?? eventId) : probesAround(g, anchor)
  const visitor_requests = [anchor, ...others, ...around]
    .filter(r => Date.parse(r.t) >= from && Date.parse(r.t) <= Math.min(to, now))
    .sort((a, b) => Date.parse(a.t) - Date.parse(b.t))
  const alerts = visitor_requests.filter(r => r.outcome !== 'passed' || (r.rules?.length ?? 0) > 0).length
  const pageViews = visitor_requests.filter(r => r.page_view).length
  const pattern = alerts === 0 ? 'no_alert' : alerts === visitor_requests.length ? 'alert_only' : 'in_session'
  const sampled = sampleRateOf(st) < 1 && !e.summary.incident
  return {
    event_id: eventId,
    state: sampled ? 'sampled' : 'complete',
    from: isoS(from),
    to: isoS(to),
    anchor,
    visitor_requests,
    truncated: false,
    visitor_summary: { requests: visitor_requests.length, page_views: pageViews, status_2xx: visitor_requests.filter(r => r.status >= 200 && r.status < 300).length, alerts, pattern },
    site_strip: stripOf(st.monitoring, site, from),
    sites_affected,
  }
}

// ------------------------------------------------------------------ aggregates over a range

function sums(m: MonitoringMock, from: number, to: number, site?: string) {
  const z = { requests: 0, clean: 0, stopped: 0, would: 0, detections: 0, bytes: 0 }
  const step = to - from > 6 * 3600_000 ? 600_000 : 60_000
  for (let t = from; t < to; t += step) {
    const span = Math.min(step, to - t) / 1000
    const c = countersAt(m, (t + Math.min(step, to - t) / 2) / 1000, site)
    z.requests += c.requests * span
    z.clean += (c.requests - c.stopped - c.would_block) * span
    z.stopped += c.stopped * span
    z.would += c.would_block * span
    z.detections += c.detections * span
    z.bytes += c.bytes_out * span
  }
  return z
}

export function botOverview(st: MockState, from: number, to: number, site: string | undefined, now: number): BotOverview {
  const z = sums(st.monitoring, from, to, site)
  const dist = distOf('bot_category', site)
  const bots: BotOverview['bots'] = []
  const categories: BotOverview['categories'] = []
  // D57: what the crawler policy of this website blocked (or, while observing, would have blocked).
  const policy = site ? st.crawlers[site]?.policy : undefined
  const observe = st.settings.profile === 'test'
  for (const [cat, cleanShare, badShare] of dist) {
    if (cat === 'likely_browser') continue
    const reqs = z.clean * cleanShare + (z.stopped + z.would) * badShare
    const members = MOCK_BOTS.filter(b => b.category === cat)
    const wsum = members.reduce((a, b) => a + b.weight, 0)
    let catBots = 0
    for (const b of members) {
      const n = Math.round(reqs * (b.weight / wsum))
      if (n <= 0) continue
      catBots++
      const v = { verified: 0, claimed: 0, mismatch: 0, unknown_stale: 0 }
      if (b.ranges === 'none') v.claimed = n
      else if (b.ranges === 'stale') v.unknown_stale = n
      else if (b.id === 'googlebot') {
        v.mismatch = Math.round(n * 0.04)
        v.verified = n - v.mismatch
      }
      else v.verified = n
      const hit = !policy ? 0 : effectiveAction(policy, b) === 'block' ? n : policy.impersonators === 'block' ? v.mismatch : 0
      const lastSeen = now - Math.floor(hash(b.id, 'seen') * 40 * 60_000)
      bots.push({
        id: b.id, name: b.name, operator: b.operator, category: b.category, requests: n,
        bytes_out: Math.round(n * (b.category.startsWith('ai_') ? 46_000 : 18_000) * (0.6 + hash(b.id, 'b') * 0.8)),
        last_seen: isoS(Math.max(from, lastSeen)), verification: v,
        ...(hit ? (observe ? { would_block: hit } : { blocked: hit }) : {}),
        robots: {
          token: b.token,
          read_at: b.readsRobots ? isoS(now - Math.floor((0.2 + hash(b.id, 'r') * 20) * 3600_000)) : null,
          disallowed_requests: b.respects === 'no' ? Math.max(1, Math.round(n * 0.18)) : 0,
          respects: b.respects,
        },
      })
    }
    if (cat !== 'likely_automated' && !catBots && reqs < 1) continue
    categories.push({ category: cat as BotCategory, requests: Math.round(reqs), bytes_out: Math.round(reqs * 20_000), bots: catBots })
  }
  bots.sort((a, b) => b.requests - a.requests)
  categories.sort((a, b) => b.requests - a.requests)
  return {
    from: isoS(from), to: isoS(to), ...(site ? { site } : {}),
    catalogue_version: '2026-10-20.1',
    verification: { ranges: true, fcrdns: false, ranges_fetch: false },
    ranges: rangeSnapshots(now),
    categories,
    bots,
    sample_rate: sampleRateOf(st),
  }
}

/** Rules that are mostly false positives on one website (they match the hints of mock/websites.ts). */
const FP_RULES: Record<string, string> = { 'verein.example': '942100', 'shop.example': '941100' }

export function ruleAlerts(st: MockState, from: number, to: number, site: string | undefined, top: number, now: number) {
  const m = st.monitoring
  const z = sums(m, from, to, site)
  const observe = st.settings.profile === 'test'
  const ringFrom = Math.max(from, now - REQUEST_RING_MS)
  const inRing = ringFrom < to
  const pathDist = distOf('path', site).filter(r => (r[4] ?? 0) > 0)
  const hints = fpHints(st, site, now)
  const items: RuleAlert[] = distOf('rule', site).map(([rule, , share], k) => {
    const detections = Math.round(z.detections * share)
    const blocked = observe ? 0 : Math.round(detections * 0.92)
    const fpHere = hints.find(h => h.rule_id === rule)
    const fpSite = site ? FP_RULES[site] === rule : Object.values(FP_RULES).includes(rule)
    const pages = inRing
      ? (fpHere ? [[fpHere.path, 0.1, 0, undefined, 0.8] as const, ...pathDist.slice(0, 2)] : pathDist.filter((_, i) => (i + k) % 3 === 0).slice(0, 3))
          .map(([path, cleanShare, , , det]) => {
            const d = Math.round(detections * (det ?? 0) * (fpHere ? 1 : 1.6))
            const requests = Math.max(d, Math.round(z.clean * cleanShare + d))
            return { path, detections: d, requests, rate: requests ? Math.min(1, d / requests) : 0 }
          })
          .filter(p => p.detections > 0)
      : []
    const hit = Math.max(1, Math.round(detections / (fpSite ? 1.4 : 6)))
    return {
      rule_id: rule, detections, blocked, would_block: detections - blocked, error: k < 3 ? 0 : Math.round(detections * 0.01),
      pages, clients: inRing ? { hit, alert_only: fpSite ? Math.round(hit * 0.1) : Math.round(hit * 0.9), in_session: fpSite ? Math.round(hit * 0.85) : Math.round(hit * 0.05) } : { hit: 0, alert_only: 0, in_session: 0 },
      possible_false_positive: !!fpHere,
    }
  }).filter(r => r.detections > 0).sort((a, b) => b.detections - a.detections).slice(0, top)
  return { from: isoS(from), to: isoS(to), ...(site ? { site } : {}), resolution: to - from > 48 * 3600_000 ? '10m' as const : '1m' as const, ring_from: inRing ? isoS(ringFrom) : null, items }
}

export function pageAlerts(st: MockState, from: number, to: number, site: string | undefined, top: number, now: number) {
  const m = st.monitoring
  const z = sums(m, from, to, site)
  const observe = st.settings.profile === 'test'
  const ringFrom = Math.max(from, now - REQUEST_RING_MS)
  const inRing = ringFrom < to
  const slow = site ? m.events[site]?.slow : undefined
  const hints = fpHints(st, site, now)
  const rules = distOf('rule', site)
  const base = latency(m, now / 1000 - 30, site).total.p95
  const items: PageAlert[] = distOf('path', site).map(([path, cleanShare, badShare, , detShare], k) => {
    const bad = (z.stopped + z.would) * badShare
    const requests = Math.round(z.clean * cleanShare + bad)
    const detections = Math.round(z.detections * (detShare ?? 0))
    const blocked = observe ? 0 : Math.round(detections * 0.9)
    const hint = hints.find(h => h.path === path)
    const followed = hint ? Math.round(hint.detections * 0.9) : 0
    const s5 = slow && (path.startsWith('/api/') || path === '/suche' || path === '/kasse') ? Math.round(requests * 0.03) : !isAsset(path) && cleanShare > badShare ? Math.round(requests * 0.004 * hash(path, 's5')) : 0
    const s4 = Math.round(bad * 0.95 + requests * 0.01)
    const s3 = isAsset(path) ? Math.round(requests * 0.25) : Math.round(requests * 0.02)
    const p95 = (isAsset(path) ? base * 0.3 : path === '/suche' || path.startsWith('/api/') ? base * 1.8 : path === '/kasse' ? base * 2.4 : badShare > cleanShare ? 4 : base) * (0.7 + hash(path, 'p95') * 0.9)
    return {
      path, requests, detections, rate: requests ? Math.min(1, detections / requests) : 0, blocked, would_block: detections - blocked,
      error: k < 3 ? 0 : Math.round(requests * 0.004),
      ...(inRing
        ? {
            status: { s1xx: 0, s2xx: Math.max(0, requests - s3 - s4 - s5), s3xx: s3, s4xx: s4, s5xx: s5 },
            latency_p95_ms: Math.round(p95 * 10) / 10,
            observe_followed_by_2xx: followed,
            rules: rules.filter((_, i) => (i + k) % 4 === 0).slice(0, detections ? 3 : 0).map(([rule_id, , sh]) => ({ rule_id, detections: Math.round(detections * sh * 2) }))
              .concat(hint ? [{ rule_id: hint.rule_id, detections: hint.detections }] : [])
              .filter(r => r.detections > 0).slice(0, 5),
          }
        : {}),
      review: followed > 0,
    }
  }).filter(p => p.requests > 0).sort((a, b) => b.requests - a.requests).slice(0, top)
  return { from: isoS(from), to: isoS(to), ...(site ? { site } : {}), resolution: to - from > 48 * 3600_000 ? '10m' as const : '1m' as const, ring_from: inRing ? isoS(ringFrom) : null, items }
}

// ------------------------------------------------------------------ handlers

type Params = Record<string, string | readonly string[] | undefined>
type Fn = (args: { request: Request, params: Params }) => Promise<Response> | Response

export interface RequestHandlerTools {
  base: string
  state: () => MockState
  now: () => number
  guard: (kind: 'read' | 'write', fn: Fn) => (args: { request: Request, params: Params }) => Promise<Response>
  problem: (status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) => Response
}

export function requestHandlers(t: RequestHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object) => HttpResponse.json(body as Record<string, unknown>)
  const gate = (q: URLSearchParams) => {
    const st = t.state()
    if (st.scenario === 'error') return problem(503, 'internal', 'Interner Fehler')
    if (!st.monitoring.enabled) return problem(409, 'monitoring_off', 'Monitoring ist ausgeschaltet')
    if (!st.monitoring.requestRing) return problem(409, 'requests_off', 'Das Zugriffsprotokoll ist aus')
    const site = q.get('site')
    if (site && !st.monitoring.sites.some(s => s.id === site)) return problem(400, 'invalid', 'Unbekannte Website', [{ pointer: '#/query/site', detail: 'unknown site' }])
    return null
  }
  const range = (q: URLSearchParams, defLen: number) => {
    const now = t.now()
    const to = q.get('to') ? Date.parse(q.get('to')!) : now
    const from = q.get('from') ? Date.parse(q.get('from')!) : to - defLen
    return { from, to, now }
  }
  const tooLong = (from: number, to: number, max: number) => (!(from < to) || to - from > max)
    ? problem(400, 'invalid', 'Ungültiger Zeitraum', [{ pointer: '#/query/from', detail: `range must be > 0 and <= ${max / 1000} s` }])
    : null

  return [
    http.get(`${base}/requests`, guard('read', ({ request }) => {
      const q = new URL(request.url).searchParams
      const e = gate(q)
      if (e) return e
      const { from, to, now } = range(q, 3600_000)
      const bad = tooLong(from, to, q.has('ip') || q.has('user_agent') ? 49 * 3600_000 : 6 * 3600_000) ?? (now - from > REQUEST_RING_MS + 60_000 ? problem(400, 'invalid', 'Außerhalb des Zugriffsprotokolls', [{ pointer: '#/query/from', detail: 'outside keep_hours' }]) : null)
      if (bad) return bad
      const get = (k: string) => q.get(k) ?? undefined
      const limit = Math.min(500, Math.max(1, Number(q.get('limit') ?? 50) || 50))
      return json(queryRequests(t.state(), { from, to, site: get('site'), path: get('path'), rule: get('rule'), outcome: get('outcome'), status_class: get('status_class'), country: get('country'), bot_category: get('bot_category'), bot: get('bot'), verification: get('verification'), visitor: get('visitor'), ip: get('ip'), user_agent: get('user_agent'), limit, cursor: q.get('cursor') }))
    })),
    http.get(`${base}/requests/context/:id`, guard('read', ({ params }) => {
      const e = gate(new URLSearchParams())
      if (e) return e
      const r = requestContext(t.state(), String(params.id), t.now())
      if (r === 'not_found') return problem(404, 'not_found', 'Ereignis nicht gefunden')
      return json(r)
    })),
    http.get(`${base}/requests/bots`, guard('read', ({ request }) => {
      const q = new URL(request.url).searchParams
      const e = gate(q)
      if (e) return e
      const { from, to, now } = range(q, 86400_000)
      const bad = tooLong(from, to, REQUEST_RING_MS + 600_000)
      if (bad) return bad
      return json(botOverview(t.state(), from, to, q.get('site') ?? undefined, now))
    })),
    http.get(`${base}/requests/alerts/rules`, guard('read', ({ request }) => {
      const q = new URL(request.url).searchParams
      const e = gate(q)
      if (e) return e
      const { from, to, now } = range(q, 14 * 86400_000)
      const bad = tooLong(from, to, 14 * 86400_000 + 600_000)
      if (bad) return bad
      return json(ruleAlerts(t.state(), from, to, q.get('site') ?? undefined, Math.min(64, Number(q.get('top') ?? 20) || 20), now))
    })),
    http.get(`${base}/requests/alerts/pages`, guard('read', ({ request }) => {
      const q = new URL(request.url).searchParams
      const e = gate(q)
      if (e) return e
      const { from, to, now } = range(q, 14 * 86400_000)
      const bad = tooLong(from, to, 14 * 86400_000 + 600_000)
      if (bad) return bad
      return json(pageAlerts(t.state(), from, to, q.get('site') ?? undefined, Math.min(64, Number(q.get('top') ?? 20) || 20), now))
    })),
  ]
}

