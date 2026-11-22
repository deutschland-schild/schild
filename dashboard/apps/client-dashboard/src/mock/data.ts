/**
 * In-memory mock backend state for the client dashboard (mock mode and tests only, never in production builds).
 * Seeded from the contract fixtures (contracts/api/fixtures/client) plus deterministic generated data.
 * Only documentation addresses (RFC 5737, RFC 3849) and documentation ASNs (RFC 5398) are used.
 */
import type { RunningBlock } from '@/api/blocks'
import type {
  AllowlistEntry,
  EventSummary,
  Geo,
  Incident,
  LocalEvent,
  MatchedRule,
  Mode,
  MyIP,
  Outcome,
  Overview,
  Session,
  Settings,
  WouldBlockReason,
} from '@/api/types'
import type { AccessProtection } from '@/api/access'
import type { CrawlerPolicyState } from '@/api/crawlers'
import type { GroupStatus } from '@/api/group'
import allowlistFixture from '../../../../../contracts/api/fixtures/client/listAllowlist.json'
import eventDetailFixture from '../../../../../contracts/api/fixtures/client/getEvent.json'
import eventPageFixture from '../../../../../contracts/api/fixtures/client/listEvents.json'
import myIpFixture from '../../../../../contracts/api/fixtures/client/getMyIP.json'
import overviewDegraded from '../../../../../contracts/api/fixtures/client/getOverview.degraded.json'
import groupFixture from '../../../../../contracts/api/fixtures/client/getGroupStatus.json'
import overviewNormal from '../../../../../contracts/api/fixtures/client/getOverview.json'
import overviewStandalone from '../../../../../contracts/api/fixtures/client/getOverview.standalone.json'
import settingsFixture from '../../../../../contracts/api/fixtures/client/getSettings.json'
import type { AgentApiMock } from './agentapi'
import type { BehaviourMock } from './behaviour'
import type { HostMock } from './hosts'
import type { MonitoringMock } from './monitoring'
import type { RulesMock } from './rules'
import { createAgentApiState } from './agentapi'
import { createBehaviourState } from './behaviour'
import { createHostState, serversSummary } from './hosts'
import { seedWebsites } from './websites'
import { createMonitoringState } from './monitoring'
import { createRulesState } from './rules'

/**
 * standalone: a gateway that started a few hours ago and cannot reach the CrowdSec Hub. observe: the test
 * profile, in which nothing is blocked (D89: there is no protection mode).
 */
export type Scenario = 'default' | 'observe' | 'first-run' | 'login' | 'degraded' | 'empty' | 'error' | 'standalone' | 'group' | 'group-large'
export const SCENARIOS: Scenario[] = ['default', 'observe', 'first-run', 'login', 'degraded', 'empty', 'error', 'standalone', 'group', 'group-large']

/** What the gateway does with a decision, as the server derives it (D89): the test profile only observes. */
export function gatewayMode(s: Pick<Settings, 'profile'>): Mode {
  return s.profile === 'test' ? 'observe' : 'autoblock'
}

/** Fixture times are around this instant; they are shifted so the mock data looks current. */
const FIXTURE_NOW = Date.parse('2026-10-26T12:00:00Z')

// ------------------------------------------------------------------ deterministic randomness

export function rng(seed: number) {
  let s = seed >>> 0
  const next = () => {
    s = (s + 0x6D2B79F5) >>> 0
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
  return {
    next,
    int: (min: number, max: number) => min + Math.floor(next() * (max - min + 1)),
    pick: <T>(arr: readonly T[]): T => arr[Math.floor(next() * arr.length)]!,
    hex: (n: number) => Array.from({ length: n }, () => Math.floor(next() * 16).toString(16)).join(''),
    uuid() {
      const h = this.hex(32).split('')
      h[12] = '4'
      h[16] = '89ab'[Math.floor(next() * 4)]!
      const s2 = h.join('')
      return `${s2.slice(0, 8)}-${s2.slice(8, 12)}-${s2.slice(12, 16)}-${s2.slice(16, 20)}-${s2.slice(20)}`
    },
  }
}
export type Rng = ReturnType<typeof rng>

const INCIDENT_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
function incidentNumber(r: Rng) {
  const part = () => Array.from({ length: 4 }, () => r.pick(INCIDENT_ALPHABET.split(''))).join('')
  return `${part()}-${part()}`
}

/** RFC 3339 UTC without milliseconds (the dashboard API Timestamp pattern allows fractions, the fixtures use none). */
export function iso(ms: number) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z')
}
function isoMs(ms: number) {
  return new Date(ms).toISOString()
}

// ------------------------------------------------------------------ pools

interface Origin { ips: string[], geo: Geo }
const ORIGINS: Origin[] = [
  { ips: ['198.51.100.23', '198.51.100.24', '198.51.100.88', '198.51.100.120'], geo: { country: 'DE', city: 'Berlin', asn: 64496, as_org: 'Example Telekom', net_class: 'residential' } },
  { ips: ['198.51.100.140', '198.51.100.141'], geo: { country: 'DE', city: 'München', asn: 64497, as_org: 'Example Kabel GmbH', net_class: 'residential' } },
  { ips: ['192.0.2.70', '192.0.2.71'], geo: { country: 'AT', city: 'Wien', asn: 64498, as_org: 'Example Mobilfunk AT', net_class: 'mobile' } },
  { ips: ['203.0.113.42', '2001:db8::17', '203.0.113.43'], geo: { country: 'NL', city: 'Amsterdam', asn: 64500, as_org: 'Example Hosting B.V.', net_class: 'hosting' } },
  { ips: ['203.0.113.77', '203.0.113.78', '2001:db8:4::9'], geo: { country: 'US', city: 'Ashburn', asn: 64501, as_org: 'Example Cloud Inc.', net_class: 'hosting' } },
  { ips: ['203.0.113.150', '203.0.113.151'], geo: { country: 'CN', city: 'Shenzhen', asn: 64502, as_org: 'Example Data Center', net_class: 'hosting' } },
  { ips: ['203.0.113.200'], geo: { country: 'RU', city: 'Moskau', asn: 64503, as_org: 'Example Hosting RU', net_class: 'hosting' } },
  { ips: ['192.0.2.130', '192.0.2.131'], geo: { country: 'BR', city: 'São Paulo', asn: 64504, as_org: 'Example Telecom BR', net_class: 'residential' } },
  { ips: ['2001:db8:7::1'], geo: { country: 'SG', city: 'Singapur', asn: 64505, as_org: 'Example VPS Asia', net_class: 'hosting' } },
  { ips: ['192.0.2.200'], geo: { country: 'FR', city: 'Paris', asn: 64506, as_org: 'Example Online SAS', net_class: 'hosting' } },
]
const HUMAN_ORIGINS = ORIGINS.filter(o => o.geo.net_class !== 'hosting')
const BOT_ORIGINS = ORIGINS.filter(o => o.geo.net_class === 'hosting')

const LEGIT: { method: string, path: string }[] = [
  { method: 'GET', path: '/' },
  { method: 'GET', path: '/produkte/' },
  { method: 'GET', path: '/produkte/vereinstrikot' },
  { method: 'GET', path: '/kontakt' },
  { method: 'POST', path: '/kontakt' },
  { method: 'GET', path: '/blog/sommerfest' },
  { method: 'GET', path: '/warenkorb' },
  { method: 'GET', path: '/impressum' },
]
const BROWSERS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0',
]

interface Attack {
  method: string
  path: string
  query?: string
  rules: MatchedRule[]
  score: number
  ua: string
  content_type?: string
}
/** A CrowdSec Hub rule that waits for approval or settles: a match only logs (D73). */
const HUB_ATTACK: Attack = {
  method: 'GET', path: '/api/gis/raster', query: 'lookup=1', score: 0,
  rules: [{ id: 62846312, repository: 'crowdsec', msg: 'crowdsec hub crowdsecurity/vpatch-CVE-2026-1207', severity: 'critical', crowdsec: { name: 'crowdsecurity/vpatch-CVE-2026-1207', version: '0.3', label: 'Django - SQL Injection', cves: ['CVE-2026-1207'] } }],
  ua: 'curl/8.7.1',
}
const ATTACKS: Attack[] = [
  HUB_ATTACK,
  {
    method: 'POST', path: '/wp-login.php', score: 72,
    rules: [{ id: 930120, repository: 'crs', msg: 'OS File Access Attempt', severity: 'critical', match_shape: { location: 'ARGS:log', content_type: 'application/x-www-form-urlencoded', len_bucket: '16-64' } }, { id: 949110, repository: 'crs', msg: 'Inbound Anomaly Score Exceeded', severity: 'critical' }],
    ua: 'python-requests/2.31.0', content_type: 'application/x-www-form-urlencoded',
  },
  {
    method: 'GET', path: '/produkte/', query: 'id=1%27%20OR%201%3D1--', score: 85,
    rules: [{ id: 942100, repository: 'crs', msg: 'SQL Injection Attack Detected via libinjection', severity: 'critical', match_shape: { location: 'ARGS:id', len_bucket: '1-16' } }, { id: 949110, repository: 'crs', msg: 'Inbound Anomaly Score Exceeded', severity: 'critical' }],
    ua: 'sqlmap/1.8.3#stable (https://sqlmap.org)',
  },
  {
    method: 'GET', path: '/suche', query: 'q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', score: 60,
    rules: [{ id: 941100, repository: 'crs', msg: 'XSS Attack Detected via libinjection', severity: 'critical', match_shape: { location: 'ARGS:q', len_bucket: '16-64' } }],
    ua: 'curl/8.4.0',
  },
  {
    // One critical CRS finding reaches the threshold on its own: score 40, and 949110 decides (as on a real gateway).
    method: 'GET', path: '/.env', score: 40,
    rules: [{ id: 930130, repository: 'crs', msg: 'Restricted File Access Attempt', severity: 'critical', match_shape: { location: 'REQUEST_FILENAME', len_bucket: '1-16' } }, { id: 949110, repository: 'crs', msg: 'Inbound Anomaly Score Exceeded', severity: 'critical' }],
    ua: 'Go-http-client/1.1',
  },
  {
    method: 'GET', path: '/cgi-bin/status', query: 'cmd=%3Bcat%20%2Fetc%2Fpasswd', score: 90,
    rules: [{ id: 932160, repository: 'crs', msg: 'Remote Command Execution: Unix Shell Code Found', severity: 'critical', match_shape: { location: 'ARGS:cmd', len_bucket: '16-64' } }, { id: 949110, repository: 'crs', msg: 'Inbound Anomaly Score Exceeded', severity: 'critical' }],
    ua: 'Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))',
  },
  {
    method: 'POST', path: '/xmlrpc.php', score: 50,
    rules: [{ id: 1000010, repository: 'local', msg: 'xmlrpc.php not used on this site', severity: 'warning', match_shape: { location: 'REQUEST_FILENAME', len_bucket: '1-16' } }],
    ua: 'WordPress/6.4; https://wp.example', content_type: 'text/xml',
  },
  {
    method: 'GET', path: '/wp-admin/install.php', score: 40,
    rules: [{ id: 913100, repository: 'crs', msg: 'Found User-Agent associated with security scanner', severity: 'critical', match_shape: { location: 'REQUEST_HEADERS:User-Agent', len_bucket: '16-64' } }],
    ua: 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)',
  },
]

// ------------------------------------------------------------------ state

export interface StoredEvent {
  summary: EventSummary
  detail: LocalEvent
}

export interface MockState {
  scenario: Scenario
  now: () => number
  session: Session
  password: string | null
  failedLogins: number
  overview: Overview
  events: StoredEvent[]
  /** D73: rule repositories and their rules (mock/rules.ts). */
  ruleRepos: RulesMock
  /** D56: Passwortschutz by website id. */
  access: Record<string, AccessProtection>
  /** Maintenance mode by website (D98); absent = off. */
  maintenance: Record<string, { message: string, updated_at: string }>
  /** D57: KI-Crawler by website id (policy, last change). */
  crawlers: Record<string, Pick<CrawlerPolicyState, 'policy' | 'updated_at' | 'actor'>>
  allowlist: AllowlistEntry[]
  myIp: MyIP
  settings: Settings
  incidents: Map<string, Incident>
  liveSeq: number
  rand: Rng
  /** v0.3 "Server" section (mock/hosts.ts). */
  hosts: HostMock
  /** v0.4 "Verhalten & Limits" (mock/behaviour.ts). */
  behaviour: BehaviourMock
  /** D87: the handoff to the host's firewall as the mock sees it (off until a test switches it on). */
  firewall: { state: 'off' | 'stale' | 'ok' | 'error', banned: string[] }
  /** D88: addresses blocked by hand, until lifted. */
  manualBlocks: RunningBlock[]
  /** v0.4 traffic and server monitoring (mock/monitoring.ts, MVP-21). */
  monitoring: MonitoringMock
  /** MVP-27: the mode this gateway runs in. A single gateway in every scenario but `group`. */
  group: GroupStatus
  /** D103: the switch of the agent API and its tokens (mock/agentapi.ts). */
  agentApi: AgentApiMock
}

const CSRF = 'mock-csrf-token-7f3a9c22b1e04d55'

/** Deep-shift every RFC 3339 timestamp in a fixture object by `delta` ms. */
/** A cluster of 16 gateways for the map and the table of many servers: one away, one draining, one not ready. */
function largeGroup(base: GroupStatus): GroupStatus {
  const [self, peer] = base.members!
  const members = Array.from({ length: 16 }, (_, i) => {
    if (i === 0) return self!
    const k = i + 1
    const id = `n-${k.toString(16).padStart(2, '0')}${peer!.id.slice(4)}`
    const m = { ...peer!, id, name: `web-${k}`, address: `192.0.2.${k}:8790`, config: 'same' as const }
    if (k === 7) return { ...m, state: 'unreachable' as const, vitals: undefined, config: 'unknown' as const, error: `dial tcp 192.0.2.${k}:8790: i/o timeout` }
    const service = k === 12 ? 'draining' as const : k === 15 ? 'not_ready' as const : 'ready' as const
    return { ...m, vitals: { ...peer!.vitals!, service, requests_per_s: service === 'ready' ? 30 + ((k * 37) % 23) : 0, cpu_usage: ((k * 17) % 70 + 12) / 100, memory_used_ratio: ((k * 29) % 55 + 30) / 100, disk_used_ratio: ((k * 13) % 40 + 25) / 100 } }
  })
  return { ...base, state: 'degraded', members: [...members, ...base.members!.filter(m => m.role === 'edge')], config: { version: base.config!.version, differing: [] } }
}

function shiftTimes<T>(value: T, delta: number): T {
  return JSON.parse(JSON.stringify(value), (_k, v) => {
    if (typeof v === 'string' && /^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(v)) {
      const shifted = Date.parse(v) + delta
      return /\.\d+Z$/.test(v) ? isoMs(shifted) : iso(shifted)
    }
    return v
  }) as T
}

function geoOf(e: EventSummary): Geo {
  return e.geo ?? { country: 'ZZ', asn: 0, net_class: 'unknown' }
}

function requestType(outcome: Outcome) {
  return outcome === 'blocked' ? 'schild.request.blocked.v1' : 'schild.request.evaluated.v1'
}

function statusFor(outcome: Outcome) {
  return outcome === 'blocked' ? 403 : 200
}

export function buildDetail(s: EventSummary, extra: { ua?: string, query?: string, rules?: MatchedRule[], mode: Mode }): LocalEvent {
  if (!s.type.startsWith('schild.request.')) {
    return { id: s.id, type: s.type, time: isoMs(Date.parse(s.time)), source: 'schild://web-1', data: {} }
  }
  const rules: MatchedRule[] = extra.rules ?? (s.rules ?? []).filter(id => /^\d+$/.test(id)).map(id => ({ id: Number(id), repository: 'crs' as const }))
  return {
    id: s.id,
    type: s.type,
    time: isoMs(Date.parse(s.time)),
    source: 'schild://web-1',
    data: {
      request_id: `req-${s.id.slice(0, 8)}`,
      client: { ip: s.ip!, port: 40000 + (s.id.charCodeAt(0) * 37) % 20000, attribution: 'tcp_peer', geo: geoOf(s) },
      method: s.method!,
      host: s.host!,
      path: s.path!,
      ...(extra.query ? { query: extra.query } : {}),
      protocol: 'h2',
      status: s.status!,
      user_agent: extra.ua ?? BROWSERS[0],
      ...(s.session_id ? { session_id: s.session_id } : {}),
      rules,
      score: s.score ?? 0,
      outcome: s.outcome!,
      ...(s.outcome === 'would_block' && s.would_block_reason ? { would_block_reason: s.would_block_reason } : {}),
      mode: extra.mode,
      duration_ms: 3.2,
      waf_ms: 0.8,
      ...(s.incident ? { incident: s.incident } : {}),
    },
  }
}

/**
 * The website (D36) of a generated event, from its id so the random sequence stays as it was:
 * attacks lean towards verein.example (a WordPress site everyone scans), visits follow the traffic shares.
 */
export function websiteFor(st: Partial<Pick<MockState, 'monitoring'>>, id: string, attack: boolean): string {
  const sites = st.monitoring?.sites ?? []
  if (sites.length <= 1) return sites[0]?.id ?? 'shop.example'
  const x = Number.parseInt(id.slice(0, 4), 16) / 65536
  const weights = sites.map(s => attack ? s.burst : s.weight)
  let acc = 0
  for (let i = 0; i < sites.length; i++) {
    acc += weights[i]!
    if (x < acc) return sites[i]!.id
  }
  return sites[sites.length - 1]!.id
}

const SHARED_NETS = new Set(['cgnat', 'mobile', 'tor'])
const OTHER_REASONS: WouldBlockReason[] = ['allowlist', 'site_observe', 'scenario_observe', 'learning']

/**
 * would_block_reason of a mock event (contracts v0.5, D36 open items): the gateway mode first, then
 * shared addresses, else a stable spread over the other reasons so every label shows up somewhere in the mock.
 */
export function wouldBlockReasonFor(mode: Mode, s: Pick<EventSummary, 'id' | 'rules' | 'geo'>): WouldBlockReason {
  if (mode === 'observe') return 'gateway_observe'
  if (s.geo?.net_class && SHARED_NETS.has(s.geo.net_class)) return 'shared_address'
  let h = 0
  for (const ch of s.id) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return OTHER_REASONS[h % OTHER_REASONS.length]!
}

/** Set would_block_reason on every would_block event that has none (summary and detail). */
export function markWouldBlockReasons(events: StoredEvent[], mode: Mode): void {
  for (const e of events) {
    if (e.summary.outcome !== 'would_block') {
      delete e.summary.would_block_reason
      delete e.detail.data.would_block_reason
      continue
    }
    const r = e.summary.would_block_reason ?? wouldBlockReasonFor(mode, e.summary)
    e.summary.would_block_reason = r
    e.detail.data.would_block_reason = r
  }
}

/**
 * Incident aggregation (contracts v0.5, D38): WAF blocks of one client, rule and UTC minute share one
 * number. The fixture incident and about a third of the generated WAF incidents get a count > 1 with
 * first and last seen inside their minute; behaviour blocks stay one incident per block.
 */
function aggregateIncidents(st: MockState, fixtureIncident: string | undefined): void {
  for (const [k, inc] of st.incidents) {
    if (inc.block) continue
    let h = 0
    for (const ch of k) h = (h * 31 + ch.charCodeAt(0)) >>> 0
    const n = k === fixtureIncident ? 6 : h % 3 === 0 ? 2 + (h % 11) : 1
    if (n <= 1) continue
    const t = Date.parse(inc.time)
    const minuteEnd = t - (t % 60_000) + 59_000
    const last = Math.max(t, Math.min(minuteEnd, t + (n - 1) * 4_000))
    st.incidents.set(k, { ...inc, count: n, first_seen: inc.time, last_seen: iso(last) })
  }
}

/** Create one request event (summary + detail) at time `at`. */
export function generateRequest(st: Pick<MockState, 'rand' | 'settings' | 'incidents'> & Partial<Pick<MockState, 'monitoring'>>, at: number, attackShare = 0.3): StoredEvent {
  const r = st.rand
  const mode = gatewayMode(st.settings)
  const isAttack = r.next() < attackShare
  const id = r.uuid()
  if (!isAttack) {
    const o = r.pick(HUMAN_ORIGINS)
    const l = r.pick(LEGIT)
    const summary: EventSummary = {
      id, time: iso(at), type: 'schild.request.evaluated.v1', outcome: 'passed', ip: r.pick(o.ips), geo: o.geo,
      method: l.method, host: websiteFor(st, id, false), path: l.path, status: 200, score: 0, rules: [], session_id: `s_${r.hex(10)}`,
    }
    summary.site = summary.host
    return { summary, detail: buildDetail(summary, { ua: r.pick(BROWSERS), mode }) }
  }
  const a = r.pick(ATTACKS)
  const o = r.pick(r.next() < 0.8 ? BOT_ORIGINS : HUMAN_ORIGINS)
  const roll = r.next()
  let outcome: Outcome
  // The CrowdSec Hub stands on Erkennen by default: its matches are "Erkannt" (D90).
  if (a === HUB_ATTACK) outcome = 'would_block'
  else if (mode === 'observe') outcome = a.score >= 50 ? 'would_block' : 'logged'
  else outcome = a.score >= 70 || roll < 0.5 ? 'blocked' : 'logged'
  const incident = outcome === 'blocked' ? incidentNumber(r) : undefined
  const ip = r.pick(o.ips)
  const summary: EventSummary = {
    id, time: iso(at), type: requestType(outcome), outcome, ip, geo: o.geo, method: a.method, host: websiteFor(st, id, true), path: a.path,
    status: statusFor(outcome), score: a.score, rules: a.rules.map(x => String(x.id)),
    ...(incident ? { incident } : {}),
    session_id: `s_${r.hex(10)}`,
  }
  summary.site = summary.host
  if (outcome === 'would_block') summary.would_block_reason = a === HUB_ATTACK ? 'source_detect' : wouldBlockReasonFor(mode, summary)
  const detail = buildDetail(summary, { ua: a.ua, query: a.query, rules: a.rules, mode })
  if (incident) {
    st.incidents.set(incident, {
      incident, status: 'blocked', time: summary.time, request: summary,
      reason: a.rules.map(x => `${x.id} ${x.msg ?? ''}`.trim()).join(', '),
      unblocked_at: null, allowlist_entry: null,
      site: summary.site,
    })
  }
  return { summary, detail }
}

// ------------------------------------------------------------------ seed

export interface CreateStateOptions {
  scenario?: Scenario
  now?: () => number
  seed?: number
  events?: number
  /** The request ring (MVP-22) runs; off by default like the gateway today. */
  requestRing?: boolean
}

export function createState(opts: CreateStateOptions = {}): MockState {
  const scenario = opts.scenario ?? 'default'
  const now = opts.now ?? (() => Date.now())
  const t0 = now()
  const delta = t0 - FIXTURE_NOW
  const rand = rng(opts.seed ?? 42)
  const empty = scenario === 'empty'
  const mode: Mode = scenario === 'observe' ? 'observe' : 'autoblock'

  const settings = shiftTimes(settingsFixture as Settings, delta)
  // Like the server (D89): only the test profile observes. Scenarios that block run the production profile.
  settings.profile = mode === 'observe' ? 'test' : 'production'
  const standalone = scenario === 'standalone'

  const overview = shiftTimes((standalone ? overviewStandalone : scenario === 'degraded' ? overviewDegraded : overviewNormal) as Overview, delta)
  // MVP-27: the group fixture has one gateway that is not reached and one whose configuration differs; the
  // overview of that group names both, as the gateway does.
  if (scenario === 'group') {
    overview.baseline = { state: 'degraded', reasons: [{ code: 'cluster_peers_unreachable', since: iso(t0 - 7 * 60_000) }, { code: 'cluster_config_drift', since: iso(t0 - 5 * 3600_000) }] }
  }

  const st: MockState = {
    scenario,
    now,
    session: scenario === 'first-run'
      ? { authenticated: false, first_run: true }
      : scenario === 'login'
        ? { authenticated: false, first_run: false }
        : { authenticated: true, first_run: false, user: 'admin', role: 'admin', csrf_token: CSRF, expires_at: iso(t0 + 12 * 3600_000), via: 'password' },
    password: scenario === 'first-run' ? null : 'mock-passwort-123',
    failedLogins: 0,
    overview,
    events: [],
    ruleRepos: createRulesState(scenario, t0),
    access: {},
    maintenance: {},
    crawlers: {},
    allowlist: empty ? [] : shiftTimes((allowlistFixture.items as AllowlistEntry[]), delta),
    myIp: { ...(myIpFixture as MyIP) },
    settings,
    incidents: new Map(),
    liveSeq: 0,
    rand,
    hosts: createHostState(scenario, t0),
    behaviour: createBehaviourState(scenario, t0),
    firewall: { state: 'off', banned: [] },
    manualBlocks: [],
    monitoring: createMonitoringState(scenario, t0, mode === 'observe'),
    // The fixture is written around 14:05:30 of its day; shifted so its contacts are seconds old.
    group: scenario === 'group' || scenario === 'group-large'
      ? shiftTimes(scenario === 'group' ? groupFixture as GroupStatus : largeGroup(groupFixture as GroupStatus), t0 - Date.parse(groupFixture.generated_at))
      : { mode: 'single' },
    agentApi: createAgentApiState(scenario, t0),
  }
  // MVP-22 (D35): which geo database is in use. The degraded gateway downloads IPinfo with the operator's
  // own key and its last download failed, so it keeps the previous database.
  st.overview.geo_db = scenario === 'degraded'
    ? { source: 'ipinfo_lite', provider: 'ipinfo', databases: ['ipinfo_lite'], built_at: iso(t0 - 3 * 86400_000), refreshed_at: iso(t0 - 3 * 86400_000), last_error: 'download_failed', last_error_at: iso(t0 - 2 * 3600_000) }
    : { ...st.overview.geo_db, provider: 'dbip' }
  st.monitoring.requestRing = opts.requestRing ?? false
  st.overview.profile = settings.profile
  if (empty) return finalize(st)

  // Generated history: newest first. Requests thin out at night.
  const total = opts.events ?? 420
  const generated: StoredEvent[] = []
  for (let i = 0; i < total; i++) {
    const at = t0 - 90_000 - Math.floor(((i + rand.next()) / total) * 24 * 3600_000)
    generated.push(generateRequest(st, at))
  }

  // Contract fixtures (shifted to now): the blocked request K7QM-4XWD and its neighbours.
  const fixtureEvents = shiftTimes(eventPageFixture.items as EventSummary[], delta)
  const fixtureDetail = shiftTimes(eventDetailFixture as unknown as { event: LocalEvent }, delta)
  const fixtureStored: StoredEvent[] = fixtureEvents.map((s) => {
    if (s.id === fixtureDetail.event.id) {
      const d = structuredClone(fixtureDetail.event)
      d.data.mode = mode
      return { summary: s, detail: d }
    }
    return { summary: s, detail: buildDetail(s, { mode, ua: s.outcome === 'passed' ? BROWSERS[1] : 'python-requests/2.31.0' }) }
  })
  for (const f of fixtureStored) {
    if (mode === 'observe' && f.summary.outcome === 'blocked') {
      // In observe mode nothing is blocked.
      f.summary.outcome = 'would_block'
      f.summary.type = 'schild.request.evaluated.v1'
      f.summary.status = 200
      delete f.summary.incident
      f.detail.type = 'schild.request.evaluated.v1'
      f.detail.data.outcome = 'would_block'
      f.detail.data.status = 200
      delete f.detail.data.incident
    }
  }
  const blockedFixture = fixtureStored.find(f => f.summary.incident)
  if (blockedFixture) {
    st.incidents.set(blockedFixture.summary.incident!, {
      incident: blockedFixture.summary.incident!, status: 'blocked', time: blockedFixture.summary.time, request: blockedFixture.summary,
      reason: '930120 OS File Access Attempt', unblocked_at: null, allowlist_entry: null,
    })
  }
  st.events = [...fixtureStored, ...generated].sort((a, b) => Date.parse(b.summary.time) - Date.parse(a.summary.time))
  // D36: every event and incident belongs to a website; the wave and its long block on verein.example.
  seedWebsites(st)
  markWouldBlockReasons(st.events, mode)
  aggregateIncidents(st, blockedFixture?.summary.incident)

  return finalize(st)
}

/** Recompute derived numbers (overview counters, rule hits, series) from the stored events. */
export function finalize(st: MockState): MockState {
  const t0 = st.now()
  const day = st.events.filter(e => t0 - Date.parse(e.summary.time) <= 24 * 3600_000)
  const requests = day.filter(e => e.summary.type.startsWith('schild.request.'))
  // The mock stores a sample; overview counts are scaled to a realistic day.
  const scale = st.events.length ? Math.max(1, Math.round((st.overview.counters_24h.requests || 48213) / Math.max(1, requests.length))) : 0
  const count = (o: Outcome) => requests.filter(e => e.summary.outcome === o).length
  const c = st.overview.counters_24h
  c.requests = requests.length * scale
  c.evaluated = c.requests
  c.blocked = count('blocked')
  c.would_block = count('would_block')
  c.incidents = c.blocked
  c.p95_overhead_ms ??= 1.8
  // D36 open items: the counters begin at the schild start when that is inside the window; the degraded
  // scenario dropped events (events_dropped_1h), so its counters have a gap without a later start.
  delete c.since
  delete c.partial
  const started = st.monitoring?.startedAt
  if (started && started > t0 - 24 * 3600_000 && !empty(st)) Object.assign(c, { partial: true, since: iso(started) })
  else if (st.scenario === 'degraded') c.partial = true

  const hours = (pred: (e: StoredEvent) => boolean, mult = 1) => Array.from({ length: 24 }, (_, i) => {
    const from = t0 - (24 - i) * 3600_000
    const to = from + 3600_000
    return day.filter(e => pred(e) && Date.parse(e.summary.time) >= from && Date.parse(e.summary.time) < to).length * mult
  })
  st.overview.series_24h = empty(st)
    ? undefined
    : {
        requests: hours(e => e.summary.type.startsWith('schild.request.'), scale),
        blocked: hours(e => e.summary.outcome === 'blocked'),
        would_block: hours(e => e.summary.outcome === 'would_block'),
      }

  for (const rule of st.ruleRepos.rules) {
    const hits = requests.filter(e => e.summary.rules?.includes(rule.id)).length
    rule.hits_24h = hits * Math.max(1, Math.round(scale / 4))
    rule.match_share_24h = c.requests ? Math.min(1, rule.hits_24h / c.requests) : 0
  }
  const servers = serversSummary(st.hosts, t0)
  if (servers) st.overview.servers = servers
  else delete st.overview.servers
  st.overview.generated_at = iso(t0)
  return st
}

function empty(st: MockState) {
  return st.events.length === 0
}
