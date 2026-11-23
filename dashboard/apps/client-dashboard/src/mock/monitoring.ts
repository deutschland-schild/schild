/**
 * Mock of the "monitoring" tag (contracts v0.4, MVP-21): a deterministic traffic and server model,
 * so series, breakdowns, the live stream and the snapshot agree with each other and stay stable
 * across reloads. Values are a function of time (and site), nothing is stored. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { Scenario } from './data'
import type {
  BreakdownDimension,
  HealthHint,
  LiveTick,
  MetricCatalogue,
  MetricSeries,
  MonitoringNow,
  ServerNow,
  ServerSnapshot,
  TopEntry,
  TrafficBreakdown,
  TrafficCounters,
} from '@/api/monitoring'
import { http, HttpResponse } from 'msw'

/**
 * One website of the mock gateway (D36). share: its part of the steady traffic; burst: its part of the
 * scanner bursts. Shares add up to 1, so the gateway total equals the sum of its websites.
 */
export interface MockSite { id: string, label: string, hosts: string[], weight: number, burst: number }

/** Things that happened on one website (ms since epoch), so charts, annotations and alerts agree. */
export interface MockSiteEvents {
  /** Distributed login attack on verein.example (wave, then a 7-day block of a data-centre address). */
  wave?: { from: number, to: number, rps: number }
  /** Traffic spike on praxis.example (a newsletter went out): clean requests x factor. */
  spike?: { from: number, to: number, factor: number }
  /** shop.example: the app answers slowly (and with errors) since `from`. */
  slow?: { from: number, latency: number, errors: number }
}

export interface MonitoringMock {
  enabled: boolean
  /** The gateway just restarted: no website has its in-memory numbers (WebsiteSummary.now) yet. */
  restarted?: boolean
  scenario: Scenario
  observe: boolean
  startedAt: number
  /** Time the mock state was created; the website events are placed relative to it. */
  anchor: number
  /** Earlier restarts (ms); each leaves a 3 min gap before it. */
  restarts: number[]
  sites: MockSite[]
  events: Record<string, MockSiteEvents>
  /** Keep of the rings in seconds (10 s, 1 min, 10 min). */
  keep: [number, number, number]
  /**
   * The request ring (MVP-22) runs. Off by default like the gateway today: filtered breakdowns,
   * combined filters and the /requests operations answer 409 (filter_unavailable, requests_off).
   */
  requestRing: boolean
}

const iso = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')

/** Four apps on one server (web-1), .example domains only. */
export const MOCK_WEBSITES: MockSite[] = [
  { id: 'verein.example', label: 'verein.example', hosts: ['verein.example', 'www.verein.example'], weight: 0.42, burst: 0.45 },
  { id: 'praxis.example', label: 'praxis.example', hosts: ['praxis.example', 'www.praxis.example'], weight: 0.24, burst: 0.15 },
  { id: 'shop.example', label: 'shop.example', hosts: ['shop.example'], weight: 0.22, burst: 0.3 },
  { id: 'blog.example', label: 'blog.example', hosts: ['blog.example'], weight: 0.12, burst: 0.1 },
]

export function createMonitoringState(scenario: Scenario, t0: number, observe: boolean): MonitoringMock {
  const empty = scenario === 'empty'
  const multi = scenario === 'default' || scenario === 'observe' || scenario === 'degraded'
  const min = 60_000
  const hour = 3600_000
  // Standalone: schild started 7 hours ago, so the 24-hour counters say "seit …" (D36 open items).
  const started = empty ? t0 - 25_000 : scenario === 'standalone' ? t0 - 7 * hour - 12 * min : t0 - 26 * hour - 17 * min
  return {
    enabled: true,
    scenario,
    observe,
    startedAt: started,
    anchor: t0,
    restarts: empty ? [] : [started, t0 - 9 * 86400_000 - 4 * 3600_000],
    // One website in the single-site scenarios: the gateway still lists it (D36, also a single one).
    sites: multi ? MOCK_WEBSITES.map(s => ({ ...s, hosts: [...s.hosts] })) : [{ id: 'shop.example', label: 'shop.example', hosts: ['shop.example'], weight: 1, burst: 1 }],
    events: multi
      ? {
          'verein.example': { wave: { from: t0 - 5 * hour - 10 * min, to: t0 - 4 * hour - 25 * min, rps: 9 } },
          'praxis.example': { spike: { from: t0 - 9 * hour - 20 * min, to: t0 - 8 * hour - 30 * min, factor: 4.5 } },
          'shop.example': { slow: { from: t0 - 35 * min, latency: scenario === 'degraded' ? 9 : 6, errors: scenario === 'degraded' ? 0.32 : 0.04 } },
        }
      : {},
    keep: [6 * 3600, 48 * 3600, 14 * 86400],
    requestRing: false,
  }
}

// ------------------------------------------------------------------ deterministic model

/** Integer hash -> [0, 1). */
function hash(a: number, b = 0): number {
  let h = (Math.imul(a | 0, 0x9E3779B1) ^ Math.imul((b | 0) + 0x632BE5AB, 0x85EBCA77)) >>> 0
  h ^= h >>> 15
  h = Math.imul(h, 0x2C1B3C6D) >>> 0
  h ^= h >>> 12
  h = Math.imul(h, 0x297A2D39) >>> 0
  h ^= h >>> 15
  return (h >>> 0) / 4294967296
}

/** Smooth noise in [-1, 1] over 5 min nodes. */
function smooth(tSec: number, salt: number): number {
  const node = 300
  const i = Math.floor(tSec / node)
  const f = (tSec - i * node) / node
  const a = hash(i, salt) * 2 - 1
  const b = hash(i + 1, salt) * 2 - 1
  const s = f * f * (3 - 2 * f)
  return a + (b - a) * s
}

/** Daily shape (CET): quiet at night, peaks around noon and in the evening. */
function diurnal(tSec: number): number {
  const h = ((tSec / 3600 + 1) % 24 + 24) % 24
  const day = Math.exp(-(((h - 12.5) / 4.5) ** 2))
  const eve = 0.55 * Math.exp(-(((h - 20.5) / 2) ** 2))
  const dow = new Date(tSec * 1000).getUTCDay()
  const weekend = dow === 0 || dow === 6 ? 0.8 : 1
  return (0.12 + 0.88 * Math.min(1, day + eve)) * weekend
}

const BASE_RPS = 16

/** Scanner bursts: a few windows of 12 min per day, mostly stopped. */
function burst(tSec: number): number {
  const hour = Math.floor(tSec / 3600)
  if (hash(hour, 77) > 0.22) return 0
  const start = Math.floor(hash(hour, 78) * 45) * 60
  const off = tSec - hour * 3600 - start
  if (off < 0 || off > 12 * 60) return 0
  return 2.5 + 4 * hash(hour, 79)
}

interface Model {
  rps: number
  burst: number
  /** Requests per second of a distributed attack wave (mostly stopped by behaviour and limits). */
  wave: number
  load: number
}

/** Smooth ramp in and out of an event window (2 min). */
function windowShape(tMs: number, from: number, to: number): number {
  if (tMs < from || tMs > to) return 0
  const edge = 120_000
  return Math.min(1, (tMs - from) / edge, (to - tMs) / edge)
}

function siteModel(m: MonitoringMock, tSec: number, s: MockSite, base: number, b: number) {
  const ev = m.events[s.id]
  const tMs = tSec * 1000
  let rps = base * s.weight
  let wave = 0
  if (ev?.spike) rps *= 1 + (ev.spike.factor - 1) * windowShape(tMs, ev.spike.from, ev.spike.to)
  if (ev?.wave) wave = ev.wave.rps * windowShape(tMs, ev.wave.from, ev.wave.to) * (0.85 + 0.3 * hash(Math.floor(tSec / 60), 91))
  return { rps, burst: b * s.burst, wave }
}

function model(m: MonitoringMock, tSec: number, site?: string): Model {
  const d = diurnal(tSec)
  let base = BASE_RPS * d * (1 + 0.18 * smooth(tSec, 11))
  const b = burst(tSec)
  if (m.scenario === 'degraded' && tSec > Date.now() / 1000 - 600) base *= 5.5
  const list = site ? m.sites.filter(x => x.id === site) : m.sites
  let rps = 0
  let bu = 0
  let wave = 0
  for (const s of list) {
    const x = siteModel(m, tSec, s, base, b)
    rps += x.rps
    bu += x.burst
    wave += x.wave
  }
  const all = siteModelTotal(m, tSec, base, b)
  return { rps, burst: bu, wave, load: Math.min(1, all / (BASE_RPS * 1.2)) }
}

/** Server load follows all websites together. */
function siteModelTotal(m: MonitoringMock, tSec: number, base: number, b: number): number {
  let sum = 0
  for (const s of m.sites) {
    const x = siteModel(m, tSec, s, base, b)
    sum += x.rps + x.burst + x.wave
  }
  return sum
}

/** The slow-app episode of a website at t (latency factor and share of upstream errors). */
function slowAt(m: MonitoringMock, tSec: number, site?: string): { latency: number, errors: number } {
  const list = site ? m.sites.filter(x => x.id === site) : m.sites
  let lat = 1
  let err = 0
  for (const s of list) {
    const sl = m.events[s.id]?.slow
    if (!sl || tSec * 1000 < sl.from) continue
    // A slow website lifts the gateway-wide p95 a little, its own a lot.
    lat = Math.max(lat, site ? sl.latency : 1 + (sl.latency - 1) * s.weight)
    err += site ? sl.errors : sl.errors * s.weight
  }
  return { latency: lat, errors: err }
}

/** Expected counters per second at t (fractions, not rounded). */
export function countersAt(m: MonitoringMock, tSec: number, site?: string): TrafficCounters {
  const { rps, burst: b, wave: w } = model(m, tSec, site)
  const degraded = m.scenario === 'degraded'
  const slow = slowAt(m, tSec, site)
  const total = rps + b + w
  const waf = rps * 0.004 + b * 0.7 + w * 0.12
  const beh = rps * 0.0008 + b * 0.05 + w * 0.5
  const rl = rps * 0.0015 + b * 0.15 + w * 0.3
  const rej = rps * 0.0003
  const failBusy = degraded ? rps * 0.004 : rps * 0.00002
  const failTimeout = degraded ? rps * 0.0006 : 0
  const fail = failBusy + failTimeout
  const stoppedRaw = waf + beh + rl + rej
  const probelauf = rps * 0.0012
  const observe = m.observe
  const stopped = observe ? rej : stoppedRaw
  const forwarded = total - stopped - fail
  const would = observe ? waf + beh : probelauf
  const wouldRl = observe ? rl : 0
  const clean = forwarded - (observe ? waf + beh + rl : 0)
  const upErr = clean * (degraded ? 0.009 : 0.0004) + clean * slow.errors * 0.8
  const upTimeout = clean * (degraded ? 0.002 : 0.0001) + clean * slow.errors * 0.2
  const s5 = clean * (degraded ? 0.012 : 0.004) + fail + clean * slow.errors
  const s4 = clean * 0.065 + stopped + (observe ? (waf + beh + rl) * 0.6 : 0)
  const s3 = clean * 0.09
  const s2 = total - s5 - s4 - s3
  return {
    requests: total,
    forwarded,
    stopped,
    blocked_waf: observe ? 0 : waf,
    blocked_behaviour: observe ? 0 : beh,
    rate_limited: observe ? 0 : rl,
    rejected_limit: rej,
    challenged: 0,
    fail_closed: fail,
    fail_closed_by: { waf_timeout: failTimeout, waf_busy: failBusy, not_ready: 0, panic: 0 },
    would_block: would,
    would_rate_limit: wouldRl,
    page_views: Math.max(0, clean - w * 0.05) * 0.17,
    detections: observe ? waf : waf + probelauf * 0.7,
    status: { s1xx: 0, s2xx: s2, s3xx: s3, s4xx: s4, s5xx: s5 },
    upstream_errors: upErr,
    upstream_timeouts: upTimeout,
    bytes_in: total * 950,
    bytes_out: forwarded * 31_000,
  }
}

const COUNTER_FIELDS: Record<string, (c: TrafficCounters) => number> = {
  'traffic.requests': c => c.requests,
  'traffic.forwarded': c => c.forwarded,
  'traffic.stopped': c => c.stopped,
  'traffic.blocked_waf': c => c.blocked_waf,
  'traffic.blocked_behaviour': c => c.blocked_behaviour,
  'traffic.rate_limited': c => c.rate_limited,
  'traffic.rejected_limit': c => c.rejected_limit,
  'traffic.challenged': c => c.challenged,
  'traffic.blocked_crawler': c => c.blocked_crawler ?? 0,
  'traffic.fail_closed': c => c.fail_closed,
  'traffic.fail_closed_waf_busy': c => c.fail_closed_by.waf_busy,
  'traffic.fail_closed_waf_timeout': c => c.fail_closed_by.waf_timeout,
  'traffic.would_block': c => c.would_block,
  'traffic.would_rate_limit': c => c.would_rate_limit,
  'traffic.page_views': c => c.page_views,
  'traffic.detections': c => c.detections,
  'traffic.status_1xx': c => c.status.s1xx,
  'traffic.status_2xx': c => c.status.s2xx,
  'traffic.status_3xx': c => c.status.s3xx,
  'traffic.status_4xx': c => c.status.s4xx,
  'traffic.status_5xx': c => c.status.s5xx,
  'traffic.upstream_errors': c => c.upstream_errors,
  'traffic.upstream_timeouts': c => c.upstream_timeouts,
  'traffic.bytes_in': c => c.bytes_in,
  'traffic.bytes_out': c => c.bytes_out,
}

/** Latency in ms at t: app (upstream), schild (overhead), total. Quantised to bucket bounds. */
export function latency(m: MonitoringMock, tSec: number, site?: string) {
  const { load } = model(m, tSec, site)
  const slow = (m.scenario === 'degraded' && tSec > Date.now() / 1000 - 1800 ? 3.2 : 1) * slowAt(m, tSec, site).latency
  const j = 1 + 0.12 * smooth(tSec, 23)
  const app = { p50: 38 * (1 + 0.5 * load) * j * slow, p95: 170 * (1 + load) * j * slow, p99: 460 * (1 + 1.2 * load) * j * slow }
  const ov = { p50: 0.32 * (1 + 0.3 * load), p95: 1.15 * (1 + 0.4 * load), p99: 2.6 * (1 + 0.5 * load) }
  const q = (v: number) => 0.05 * 1.25 ** Math.ceil(Math.log(v / 0.05) / Math.log(1.25) - 1e-9)
  return {
    upstream: { p50: q(app.p50), p95: q(app.p95), p99: q(app.p99) },
    overhead: { p50: q(ov.p50), p95: q(ov.p95), p99: q(ov.p99) },
    total: { p50: q(app.p50 + ov.p50), p95: q(app.p95 + ov.p95), p99: q(app.p99 + ov.p99) },
  }
}

// ------------------------------------------------------------------ server model

const CORES = 4
const MEM_TOTAL = 16e9
interface MountDef { mount: string, device: string, fs: string, size: number, base: number, growthPerDay: number, inodes: number }
function mounts(m: MonitoringMock): MountDef[] {
  const full = m.scenario === 'degraded' ? 0.905 : m.scenario === 'standalone' ? 0.48 : 0.74
  return [
    { mount: '/', device: 'sda1', fs: 'ext4', size: 80e9, base: 0.41, growthPerDay: 0.001, inodes: 5.2e6 },
    { mount: '/var/lib/docker', device: 'sdb', fs: 'ext4', size: 120e9, base: full, growthPerDay: 0.003, inodes: 7.8e6 },
    { mount: '/srv/backup', device: 'sdc', fs: 'xfs', size: 250e9, base: 0.63, growthPerDay: 0.002, inodes: 12e6 },
  ]
}

function gauge(m: MonitoringMock, id: string, tSec: number, object?: string): number | null {
  const { load } = model(m, tSec)
  const degraded = m.scenario === 'degraded'
  const n = (s: number) => smooth(tSec, s)
  const cpu = Math.min(0.99, (degraded && tSec > Date.now() / 1000 - 900 ? 0.93 : 0.07 + 0.38 * load) + 0.04 * n(31))
  switch (id) {
    case 'server.cpu_usage': return cpu
    case 'server.cpu_iowait': return 0.006 + 0.01 * Math.abs(n(32))
    case 'server.cpu_steal': return 0.002 + 0.002 * Math.abs(n(33))
    case 'server.load1': return Math.max(0, cpu * CORES * 1.1 + 0.3 * n(34))
    case 'server.load5': return Math.max(0, cpu * CORES * 1.05)
    case 'server.load15': return Math.max(0, cpu * CORES)
    case 'server.memory_used': return MEM_TOTAL * ((degraded ? 0.92 : 0.6) + 0.04 * load + 0.01 * n(35))
    case 'server.memory_available': return MEM_TOTAL - (gauge(m, 'server.memory_used', tSec) ?? 0)
    case 'server.swap_used': return degraded ? 6.2e8 : 0
    case 'server.disk_used':
    case 'server.disk_used_ratio':
    case 'server.disk_inodes_used_ratio': {
      const d = mounts(m).find(x => x.mount === object)
      if (!d) return null
      const ratio = Math.min(0.999, d.base - d.growthPerDay * ((Date.now() / 1000 - tSec) / 86400))
      if (id === 'server.disk_used') return ratio * d.size
      if (id === 'server.disk_used_ratio') return ratio
      return ratio * 0.35
    }
    case 'server.disk_busy': return object === 'sdb' ? 0.05 + 0.2 * load : 0.01 + 0.03 * load
    case 'server.tcp_established': return Math.round(40 + (model(m, tSec).rps) * 6)
    case 'server.tcp_syn_recv': return Math.round(Math.abs(n(36)) * 3)
    case 'server.tcp_time_wait': return Math.round(model(m, tSec).rps * 28)
    case 'server.tcp_close_wait': return Math.round(Math.abs(n(37)) * 2)
    case 'server.conntrack_used_ratio': return 0.008 + 0.01 * load
    case 'server.files_open_ratio': return 0.004 + 0.002 * load
    case 'container.cpu_usage': return 0.02 + 0.06 * load
    case 'container.cpu_throttled': return 0
    case 'container.memory_used': return 2.1e8 + 4e7 * load
    case 'process.cpu_usage': return 0.008 + 0.03 * load
    case 'process.rss': return 1.85e8 + 3e7 * load
    case 'process.heap': return 9.2e7 + 2e7 * load
    case 'process.goroutines': return Math.round(140 + 60 * load)
    case 'process.gc_pause_p99': return 0.35 + 0.2 * load
    case 'process.open_files': return Math.round(80 + 40 * load)
    case 'schild.event_queue_fill': return 0.005 + 0.02 * load
    case 'schild.eval_slots_used': return degraded ? 0.85 : 0.04 + 0.15 * load
    case 'schild.store_bytes': return 2.1e8
    case 'schild.sampler_ms': return 5 + 2 * Math.abs(n(38))
  }
  return null
}

function counterServer(m: MonitoringMock, id: string, tSec: number, object?: string): number | null {
  const c = countersAt(m, tSec)
  const load = model(m, tSec).load
  switch (id) {
    case 'server.disk_read_bytes': return object === 'sdb' ? 2.4e6 * (0.3 + load) : object === 'sda' || object === 'sda1' ? 4e5 * (0.3 + load) : 1e5
    case 'server.disk_write_bytes': return object === 'sdb' ? 3.1e6 * (0.3 + load) : object === 'sda' || object === 'sda1' ? 6e5 * (0.3 + load) : 2.5e5
    case 'server.net_rx_bytes': return object === 'eth0' ? c.bytes_in * 1.2 + 6e4 : 2e3
    case 'server.net_tx_bytes': return object === 'eth0' ? c.bytes_out * 1.06 + 2e4 : 1.5e3
    case 'server.net_errors': return 0
    case 'server.net_drops': return object === 'eth0' ? 0.02 : 0
    case 'server.tcp_listen_drops': return m.scenario === 'degraded' ? 0.4 : 0
    case 'server.tcp_retransmits': return 0.6 + 2 * load
    case 'schild.events_dropped': return m.scenario === 'degraded' ? 0.3 : 0
  }
  return null
}

const OBJECTS: Record<string, string[]> = {
  mount: ['/', '/var/lib/docker', '/srv/backup'],
  device: ['sda', 'sdb', 'sdc'],
  interface: ['eth0', 'wg0'],
}

// ------------------------------------------------------------------ catalogue

type Kind = 'counter' | 'gauge' | 'histogram' | 'estimate'
interface CatEntry { id: string, kind: Kind, unit: string, scope: string, exact: boolean, error_bound?: number, per_object: string, site_aware: boolean }
const STATS: Record<Kind, string[]> = { counter: ['rate', 'sum'], gauge: ['avg', 'min', 'max'], histogram: ['p95', 'p50', 'p99'], estimate: ['value'] }

const CATALOGUE: CatEntry[] = [
  ...Object.keys(COUNTER_FIELDS).map(id => ({ id, kind: 'counter' as Kind, unit: id.startsWith('traffic.bytes') ? 'bytes' : 'requests', scope: 'traffic', exact: true, per_object: 'none', site_aware: true })),
  ...['latency_total', 'latency_overhead', 'latency_upstream'].map(x => ({ id: `traffic.${x}`, kind: 'histogram' as Kind, unit: 'ms', scope: 'traffic', exact: false, error_bound: 0.25, per_object: 'none', site_aware: true })),
  ...['clients_unique', 'clients_new'].map(x => ({ id: `traffic.${x}`, kind: 'estimate' as Kind, unit: 'clients', scope: 'traffic', exact: false, error_bound: 0.033, per_object: 'none', site_aware: true })),
  ...([
    ['server.cpu_usage', 'gauge', 'ratio'], ['server.cpu_iowait', 'gauge', 'ratio'], ['server.cpu_steal', 'gauge', 'ratio'],
    ['server.load1', 'gauge', 'count'], ['server.load5', 'gauge', 'count'], ['server.load15', 'gauge', 'count'],
    ['server.memory_used', 'gauge', 'bytes'], ['server.memory_available', 'gauge', 'bytes'], ['server.swap_used', 'gauge', 'bytes'],
    ['server.disk_used', 'gauge', 'bytes', 'mount'], ['server.disk_used_ratio', 'gauge', 'ratio', 'mount'], ['server.disk_inodes_used_ratio', 'gauge', 'ratio', 'mount'],
    ['server.disk_read_bytes', 'counter', 'bytes', 'device'], ['server.disk_write_bytes', 'counter', 'bytes', 'device'], ['server.disk_busy', 'gauge', 'ratio', 'device'],
    ['server.net_rx_bytes', 'counter', 'bytes', 'interface'], ['server.net_tx_bytes', 'counter', 'bytes', 'interface'],
    ['server.net_errors', 'counter', 'packets', 'interface'], ['server.net_drops', 'counter', 'packets', 'interface'],
    ['server.tcp_established', 'gauge', 'count'], ['server.tcp_syn_recv', 'gauge', 'count'], ['server.tcp_time_wait', 'gauge', 'count'], ['server.tcp_close_wait', 'gauge', 'count'],
    ['server.tcp_listen_drops', 'counter', 'count'], ['server.tcp_retransmits', 'counter', 'segments'],
    ['server.conntrack_used_ratio', 'gauge', 'ratio'], ['server.files_open_ratio', 'gauge', 'ratio'],
    ['container.cpu_usage', 'gauge', 'ratio'], ['container.cpu_throttled', 'gauge', 'ratio'], ['container.memory_used', 'gauge', 'bytes'],
    ['process.cpu_usage', 'gauge', 'ratio'], ['process.rss', 'gauge', 'bytes'], ['process.heap', 'gauge', 'bytes'], ['process.goroutines', 'gauge', 'count'],
    ['process.gc_pause_p99', 'gauge', 'ms'], ['process.open_files', 'gauge', 'count'],
    ['schild.event_queue_fill', 'gauge', 'ratio'], ['schild.events_dropped', 'counter', 'count'], ['schild.eval_slots_used', 'gauge', 'ratio'],
    ['schild.store_bytes', 'gauge', 'bytes'], ['schild.sampler_ms', 'gauge', 'ms'],
  ] as [string, Kind, string, string?][]).map(([id, kind, unit, obj]) => ({ id, kind, unit, scope: id.split('.')[0]!, exact: true, per_object: obj ?? 'none', site_aware: false })),
]
const CAT = new Map(CATALOGUE.map(c => [c.id, c]))

// ------------------------------------------------------------------ series

const STEPS: Record<string, number> = { '10s': 10, '1m': 60, '10m': 600 }

/** One value of a metric over the step starting at t (ms), or null for a gap. */
function valueAt(m: MonitoringMock, c: CatEntry, stat: string, tMs: number, stepS: number, now: number, site?: string, object?: string): number | null {
  const tSec = tMs / 1000
  if (tMs > now) return null
  if (tMs + stepS * 1000 <= m.startedAt - 60_000 && m.scenario === 'empty') return null
  for (const r of m.restarts) if (tMs + stepS * 1000 > r - 180_000 && tMs < r) return null
  const mid = Math.min(tSec + stepS / 2, now / 1000)
  if (c.kind === 'counter') {
    // Like the gateway: the bucket's count over the whole step (rate = count / step_s), not the model at one
    // instant. A point sample at the bucket middle turned a 12-minute burst into one or two full-height
    // 10-minute buckets and let 1 min and 10 min disagree. Sampled every 10 s up to 1 min, then every minute.
    const sub = stepS <= 60 ? 10 : 60
    const end = Math.min(tSec + stepS, now / 1000)
    let sum = 0
    let n = 0
    for (let s = tSec + sub / 2; s < end; s += sub) {
      const v = c.scope === 'traffic' ? COUNTER_FIELDS[c.id]!(countersAt(m, s, site)) : counterServer(m, c.id, s, object)
      if (v === null) return null
      sum += v
      n++
    }
    const perS = n ? sum / n : (c.scope === 'traffic' ? COUNTER_FIELDS[c.id]!(countersAt(m, mid, site)) : counterServer(m, c.id, mid, object))
    if (perS === null) return null
    // D36: a partial bucket covers fewer seconds; its rate is per covered second, its sum what was counted.
    return stat === 'sum' ? Math.round(perS * Math.max(0, Math.min(stepS, end - tSec))) : perS
  }
  if (c.kind === 'histogram') {
    const l = latency(m, mid, site)
    const part = c.id === 'traffic.latency_total' ? l.total : c.id === 'traffic.latency_overhead' ? l.overhead : l.upstream
    return part[stat as 'p50' | 'p95' | 'p99'] ?? part.p95
  }
  if (c.kind === 'estimate') {
    // Visitors are people (D36 amendment): from the page views, a little above the KPI's 0.58 per page view
    // (distinct per day), since per-step counts are not additive. New visitors count once (not seen in 7
    // days), so their sum over the steps is about a third of the KPI Besucher.
    const at = countersAt(m, mid, site)
    const unique = Math.round(at.page_views * stepS * 0.62 + at.requests * stepS * 0.004)
    return c.id === 'traffic.clients_new' ? Math.round(at.page_views * stepS * 0.58 * 0.36) : unique
  }
  const g = gauge(m, c.id, mid, object)
  if (g === null) return null
  if (stat === 'min') return g * 0.92
  if (stat === 'max') return c.unit === 'ratio' ? Math.min(1, g * 1.12) : g * 1.12
  return g
}

function seriesFor(m: MonitoringMock, q: string, from: number, stepS: number, points: number, now: number, site?: string, object?: string): MetricSeries[] | string {
  const [id, statIn] = q.split(':')
  const c = CAT.get(id!)
  if (!c) return `unknown metric "${id}"`
  const stat = statIn ?? STATS[c.kind][0]!
  if (!STATS[c.kind].includes(stat)) return `stat "${stat}" not allowed for ${c.kind} metric ${id}`
  const objs = c.per_object === 'none' ? [undefined] : object ? [object] : OBJECTS[c.per_object]!
  return objs.map((o) => {
    const values: (number | null)[] = []
    for (let i = 0; i < points; i++) values.push(valueAt(m, c, stat, from + i * stepS * 1000, stepS, now, c.site_aware ? site : undefined, o))
    return {
      metric: c.id,
      stat,
      kind: c.kind,
      unit: c.unit,
      exact: c.exact,
      ...(c.error_bound ? { error_bound: c.error_bound } : {}),
      ...(o ? { object: o } : {}),
      values,
    } as MetricSeries
  })
}

// ------------------------------------------------------------------ breakdowns

/** [key, share of clean traffic, share of stopped traffic, label?, share of detections?] */
export type Dist = [string, number, number, string?, number?][]

const DIST: Record<Exclude<BreakdownDimension, 'site'>, Dist> = {
  path: [
    ['/', 0.21, 0.01, undefined, 0.01], ['/assets/{file}', 0.27, 0, undefined, 0], ['/termine', 0.07, 0.005, undefined, 0.01],
    ['/kontakt', 0.04, 0.04, undefined, 0.12], ['/blog/{slug}', 0.09, 0.01, undefined, 0.02], ['/api/termine/{id}', 0.06, 0.02, undefined, 0.03],
    ['/wp-login.php', 0.004, 0.22, undefined, 0.24], ['/xmlrpc.php', 0.001, 0.12, undefined, 0.13], ['/.env', 0.0005, 0.14, undefined, 0.15],
    ['/suche', 0.03, 0.06, undefined, 0.11], ['/impressum', 0.015, 0, undefined, 0], ['/feed.xml', 0.02, 0, undefined, 0],
    ['/admin/{rest}', 0.004, 0.09, undefined, 0.08], ['/robots.txt', 0.008, 0, undefined, 0], ['/vendor/phpunit/{rest}', 0.0002, 0.06, undefined, 0.06],
  ],
  country: [['DE', 0.79, 0.21], ['AT', 0.05, 0.01], ['CH', 0.035, 0.005], ['NL', 0.02, 0.12], ['US', 0.045, 0.24], ['FR', 0.012, 0.03], ['GB', 0.008, 0.02], ['CN', 0.003, 0.11], ['SG', 0.002, 0.08], ['RU', 0.001, 0.07], ['BR', 0.002, 0.04], ['ZZ', 0.002, 0.03]],
  asn: [
    ['3320', 0.31, 0.01, 'Deutsche Telekom'], ['3209', 0.17, 0.005, 'Vodafone'], ['6805', 0.11, 0.005, 'Telefónica Germany'], ['8881', 0.07, 0.002, '1&1 Versatel'],
    ['24940', 0.03, 0.19, 'Hetzner Online'], ['16509', 0.035, 0.17, 'Amazon'], ['14061', 0.004, 0.16, 'DigitalOcean'], ['15169', 0.04, 0.005, 'Google'],
    ['8075', 0.02, 0.01, 'Microsoft'], ['16276', 0.006, 0.12, 'OVH'], ['31334', 0.02, 0.003, 'Vodafone Kabel'], ['4134', 0.002, 0.09, 'China Telecom'],
  ],
  net_class: [['residential', 0.67, 0.08], ['mobile', 0.2, 0.02], ['hosting', 0.09, 0.78], ['business', 0.03, 0.02], ['cgnat', 0.008, 0], ['vpn', 0.004, 0.06], ['tor', 0.0003, 0.03], ['unknown', 0.002, 0.01]],
  ua_class: [['browser', 0.86, 0.12], ['bot_unverified', 0.11, 0.18], ['tool', 0.015, 0.55], ['none', 0.004, 0.13], ['other', 0.011, 0.02], ['bot_verified', 0, 0]],
  method: [['GET', 0.93, 0.62], ['POST', 0.05, 0.33], ['HEAD', 0.015, 0.04], ['OPTIONS', 0.004, 0], ['PUT', 0.001, 0.01]],
  status_class: [['2xx', 0.845, 0], ['3xx', 0.09, 0], ['4xx', 0.061, 1], ['5xx', 0.004, 0]],
  referrer: [
    ['_direct', 0.44, 0.93], ['google.com', 0.24, 0.01], ['_intern', 0.17, 0.02], ['bing.com', 0.03, 0], ['ecosia.org', 0.018, 0], ['duckduckgo.com', 0.02, 0],
    ['ai:chatgpt', 0.024, 0, 'ChatGPT'], ['ai:perplexity', 0.009, 0, 'Perplexity'], ['facebook.com', 0.016, 0], ['instagram.com', 0.011, 0], ['_other', 0.01, 0.04], ['stadt.example', 0.008, 0],
  ],
  browser: [['chrome', 0.47, 0.06], ['safari', 0.24, 0.02], ['firefox', 0.07, 0.03], ['edge', 0.06, 0.01], ['samsung', 0.03, 0], ['opera', 0.006, 0], ['other', 0.004, 0.02], ['none', 0.12, 0.86]],
  os: [['android', 0.31, 0.02], ['windows', 0.22, 0.05], ['ios', 0.2, 0.01], ['macos', 0.1, 0.01], ['linux', 0.03, 0.06], ['chromeos', 0.004, 0], ['other', 0.006, 0.02], ['none', 0.13, 0.83]],
  device: [['mobile', 0.5, 0.02], ['desktop', 0.33, 0.08], ['tablet', 0.04, 0], ['other', 0.002, 0], ['unknown', 0.128, 0.9]],
  bot_category: [
    ['likely_browser', 0.86, 0.12], ['search_engine', 0.06, 0], ['ai_training', 0.022, 0.01], ['ai_search', 0.009, 0], ['ai_assistant', 0.004, 0],
    ['seo_tool', 0.012, 0.01], ['monitoring', 0.008, 0], ['preview_social', 0.005, 0], ['feed_reader', 0.004, 0], ['archive_research', 0.001, 0],
    ['security_scanner', 0.001, 0.31], ['tool_library', 0.008, 0.33], ['likely_automated', 0.006, 0.22],
  ],
  // D65: addresses (documentation ranges) and User-Agents, from the request ring only.
  ip: [
    ['192.0.2.10', 0.012, 0], ['192.0.2.44', 0.008, 0], ['198.51.100.7', 0.006, 0], ['2001:db8::1f', 0.005, 0], ['192.0.2.81', 0.004, 0.01],
    ['203.0.113.5', 0, 0.21], ['203.0.113.77', 0.0005, 0.14], ['198.51.100.200', 0, 0.09], ['2001:db8:4::9', 0, 0.05],
  ],
  user_agent: [
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 0.21, 0.02],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1', 0.17, 0],
    ['Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36', 0.12, 0.01],
    ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 0.04, 0],
    ['Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 0.015, 0],
    ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', 0.012, 0],
    ['python-requests/2.32.3', 0.002, 0.24], ['curl/8.5.0', 0.003, 0.11], ['Go-http-client/1.1', 0.001, 0.13],
  ],
  rule: [
    ['930120', 0, 0.21], ['942100', 0, 0.16], ['913100', 0, 0.14], ['941100', 0, 0.09], ['920350', 0, 0.08], ['932160', 0, 0.07], ['930130', 0, 0.06],
    ['921110', 0, 0.04], ['942430', 0, 0.05], ['933160', 0, 0.03], ['944130', 0, 0.02], ['9100030', 0, 0.05],
  ],
}

/** Pages of each website (path templates), so every app has its own attack surface. */
const SITE_PATHS: Record<string, Dist> = {
  'verein.example': [
    ['/', 0.24, 0.01, undefined, 0.01], ['/assets/{file}', 0.3, 0, undefined, 0], ['/termine', 0.12, 0.005, undefined, 0.01], ['/mitglied-werden', 0.05, 0.03, undefined, 0.09],
    ['/wp-login.php', 0.006, 0.46, undefined, 0.3], ['/xmlrpc.php', 0.001, 0.14, undefined, 0.16], ['/galerie/{slug}', 0.08, 0.005, undefined, 0.01], ['/kontakt', 0.03, 0.05, undefined, 0.14],
    ['/.env', 0.0004, 0.08, undefined, 0.1], ['/impressum', 0.02, 0, undefined, 0], ['/wp-admin/{rest}', 0.004, 0.06, undefined, 0.07],
  ],
  'praxis.example': [
    ['/', 0.28, 0.01, undefined, 0.01], ['/assets/{file}', 0.26, 0, undefined, 0], ['/sprechzeiten', 0.16, 0, undefined, 0], ['/team', 0.07, 0, undefined, 0],
    ['/online-termin', 0.09, 0.08, undefined, 0.22], ['/kontakt', 0.04, 0.06, undefined, 0.15], ['/.env', 0.0003, 0.3, undefined, 0.25], ['/admin/{rest}', 0.002, 0.28, undefined, 0.2],
    ['/datenschutz', 0.02, 0, undefined, 0], ['/vendor/phpunit/{rest}', 0.0001, 0.2, undefined, 0.15],
  ],
  'shop.example': [
    ['/', 0.15, 0.01, undefined, 0.01], ['/assets/{file}', 0.28, 0, undefined, 0], ['/produkte/{slug}', 0.22, 0.02, undefined, 0.03], ['/warenkorb', 0.06, 0.01, undefined, 0.02],
    ['/kasse', 0.03, 0.04, undefined, 0.08], ['/suche', 0.05, 0.22, undefined, 0.3], ['/api/produkte/{id}', 0.08, 0.18, undefined, 0.22], ['/konto/anmelden', 0.03, 0.2, undefined, 0.18],
    ['/.git/config', 0.0001, 0.12, undefined, 0.1], ['/impressum', 0.01, 0, undefined, 0],
  ],
  'blog.example': [
    ['/', 0.2, 0.01, undefined, 0.01], ['/assets/{file}', 0.3, 0, undefined, 0], ['/artikel/{slug}', 0.33, 0.02, undefined, 0.05], ['/feed.xml', 0.07, 0, undefined, 0],
    ['/kommentare', 0.02, 0.25, undefined, 0.4], ['/wp-login.php', 0.001, 0.4, undefined, 0.3], ['/suche', 0.02, 0.2, undefined, 0.2], ['/impressum', 0.01, 0, undefined, 0],
  ],
}

export function distOf(by: Exclude<BreakdownDimension, 'site'>, site?: string): Dist {
  if (by === 'path' && site && SITE_PATHS[site]) return SITE_PATHS[site]!
  return DIST[by]
}

/** Share of clean and of attack traffic that matches one filter (`dimension:value`); unknown values are tiny. */
export function filterShare(expr: string, site?: string): { clean: number, bad: number, known: boolean } {
  const i = expr.indexOf(':')
  const dim = expr.slice(0, i) as BreakdownDimension
  const value = expr.slice(i + 1)
  // D64: one address or one kind of client is a small part of the traffic.
  if ((dim as string) === 'ip') return { clean: 0.002, bad: 0.02, known: true }
  if ((dim as string) === 'user_agent') return { clean: 0.04, bad: 0.08, known: true }
  if (dim === 'site' || !(dim in DIST)) return { clean: 0, bad: 0, known: false }
  const row = distOf(dim as Exclude<BreakdownDimension, 'site'>, site).find(r => r[0] === value)
  if (!row) return { clean: 0.0005, bad: 0.0005, known: false }
  if (dim === 'rule') return { clean: 0, bad: row[2], known: true }
  return { clean: row[1], bad: row[2], known: true }
}

/** Product of the shares of every filter (dimensions treated as independent in the mock). */
export function filtersShare(filters: string[], site?: string): { clean: number, bad: number, exact: boolean } {
  let clean = 1
  let bad = 1
  let exact = true
  for (const f of filters) {
    const x = filterShare(f, site)
    clean *= x.clean
    bad *= x.bad
    if (!x.known || ESTIMATED.has(f.slice(0, f.indexOf(':')) as BreakdownDimension)) exact = false
  }
  return { clean, bad, exact }
}

/** Filters only the request ring answers: two or more, or an address or User-Agent (D64). */
export function needsRequestRing(filters: string[]): boolean {
  return filters.length > 1 || filters.some(f => f.startsWith('ip:') || f.startsWith('user_agent:'))
}

/** Metrics a single filter answers from the rings over every range (D36). */
export const FILTERABLE = new Set(['traffic.requests', 'traffic.stopped', 'traffic.would_block', 'traffic.detections'])
const BAD_METRICS = new Set(['traffic.stopped', 'traffic.would_block', 'traffic.detections', 'traffic.blocked_waf', 'traffic.blocked_behaviour', 'traffic.rate_limited'])
/** The mock ring keeps 48 h (a gateway with keep_hours 48 or raw_ip_days 2; D66 default is 14 days). */
export const REQUEST_RING_MS = 48 * 3600_000

const ESTIMATED = new Set<BreakdownDimension>(['path', 'asn', 'referrer', 'rule'])

function breakdown(m: MonitoringMock, by: BreakdownDimension, from: number, to: number, site: string | undefined, top: number, now: number, filters: string[] = []): TrafficBreakdown {
  const span = to - from
  const resolution = span <= 48 * 3600_000 ? '1m' : '10m'
  const step = STEPS[resolution]! * 1000
  // Sum the model over the range at the ring's step.
  const tot = { requests: 0, stopped: 0, would: 0, clean: 0, detections: 0 }
  for (let t = Math.floor(from / step) * step; t < Math.min(to, now); t += step) {
    const c = countersAt(m, t / 1000 + step / 2000, site)
    const s = step / 1000
    tot.requests += c.requests * s
    tot.stopped += c.stopped * s
    tot.would += c.would_block * s
    tot.detections += c.detections * s
    tot.clean += (c.requests - c.stopped - c.would_block) * s
  }
  const bad = tot.stopped + tot.would
  const stopShare = bad ? tot.stopped / bad : 0
  let items: TopEntry[]
  if (by === 'site') {
    items = m.sites.map((s) => {
      const share = s.weight
      return { key: s.id, requests: Math.round(tot.requests * share), stopped: Math.round(tot.stopped * share), would_block: Math.round(tot.would * share), error: 0 }
    })
  }
  else if (by === 'rule') {
    items = DIST.rule.map(([key, , sh]) => {
      const requests = Math.round(tot.detections * sh)
      const stopped = Math.min(requests, Math.round(requests * stopShare))
      return { key, requests, stopped, would_block: requests - stopped, error: 0 }
    })
  }
  else {
    items = distOf(by, site).map(([key, cleanShare, badShare, label, detShare]) => {
      const badN = bad * badShare
      const e: TopEntry = {
        key,
        requests: Math.round(tot.clean * cleanShare + badN),
        stopped: Math.round(badN * stopShare),
        would_block: Math.round(badN * (1 - stopShare)),
        error: 0,
      }
      if (label) e.label = label
      if (by === 'path' && detShare) e.detections = Math.round(tot.detections * detShare)
      return e
    })
  }
  if (filters.length) {
    // A breakdown under a filter: the rows that also match it (request ring, D36).
    const f = filtersShare(filters, site)
    const own = filters.find(x => x.startsWith(`${by}:`))
    items = items
      .filter(i => !own || own === `${by}:${i.key}`)
      .map((i) => {
        const k = own ? 1 : (i.stopped + i.would_block > i.requests / 2 ? f.bad : f.clean)
        const s = (v: number) => Math.round(v * k)
        return { ...i, requests: s(i.requests), stopped: s(i.stopped), would_block: s(i.would_block), ...(i.detections !== undefined ? { detections: s(i.detections) } : {}) }
      })
  }
  items = items.filter(i => i.requests > 0).sort((a, b) => b.requests - a.requests)
  if (ESTIMATED.has(by)) items = items.map((e, i) => ({ ...e, error: i < 3 ? 0 : Math.round(e.requests * 0.004) }))
  const shown = items.slice(0, top)
  const rest = items.slice(top)
  const sum = (xs: TopEntry[], k: 'requests' | 'stopped' | 'would_block') => xs.reduce((a, x) => a + x[k], 0)
  const fs = filters.length ? filtersShare(filters, site) : { clean: 1, bad: 1 }
  const total = by === 'rule' || filters.length
    ? { requests: by === 'rule' ? sum(items, 'requests') : Math.round(tot.clean * fs.clean + (tot.stopped + tot.would) * fs.bad), stopped: Math.round(tot.stopped * fs.bad), would_block: Math.round(tot.would * fs.bad) }
    : { requests: Math.round(tot.requests), stopped: Math.round(tot.stopped), would_block: Math.round(tot.would) }
  return {
    by,
    from: iso(from),
    to: iso(to),
    resolution,
    ...(site ? { site } : {}),
    exact: !ESTIMATED.has(by) && !filters.length,
    // Contracts v0.5 (D36 fix round 1): a restart gap in the range makes the window partial.
    ...(m.restarts.some(r => r - 180_000 < to && r > from) ? { partial: true, gap_kind: 'restart' as const } : {}),
    ...(filters.length ? { source: 'requests' as const, filters } : by === 'ip' || by === 'user_agent' ? { source: 'requests' as const } : {}),
    ...(by === 'bot_category' || by === 'ua_class' ? { bot_verification: false } : {}),
    total,
    items: shown,
    other: by === 'rule' || by === 'site'
      ? { requests: sum(rest, 'requests'), stopped: sum(rest, 'stopped'), would_block: sum(rest, 'would_block') }
      : { requests: Math.max(0, total.requests - sum(shown, 'requests')), stopped: Math.max(0, total.stopped - sum(shown, 'stopped')), would_block: Math.max(0, total.would_block - sum(shown, 'would_block')) },
  }
}

// ------------------------------------------------------------------ live

/** Whole-number counters of one second (rounded by a per-second hash, so totals stay close to the model). */
export function tickCounters(m: MonitoringMock, sec: number, site?: string): TrafficCounters {
  const c = countersAt(m, sec + 0.5, site)
  let salt = 100
  const r = (v: number) => {
    const f = Math.floor(v)
    return f + (hash(sec, salt++) < v - f ? 1 : 0)
  }
  const waf = r(c.blocked_waf)
  const beh = r(c.blocked_behaviour)
  const rl = r(c.rate_limited)
  const rej = r(c.rejected_limit)
  const busy = r(c.fail_closed_by.waf_busy)
  const tout = r(c.fail_closed_by.waf_timeout)
  const stopped = waf + beh + rl + rej
  const fail = busy + tout
  const forwarded = Math.max(0, r(c.forwarded))
  const requests = forwarded + stopped + fail
  const would = Math.min(forwarded, r(c.would_block))
  const s5 = Math.min(forwarded, r(c.status.s5xx - c.fail_closed)) + fail
  const s3 = Math.min(forwarded, r(c.status.s3xx))
  const s4 = Math.min(Math.max(0, forwarded - s3), r(c.status.s4xx - c.stopped)) + stopped
  const s2 = requests - s5 - s4 - s3
  const pv = Math.min(forwarded, Math.max(0, s2), r(c.page_views))
  return {
    requests, forwarded, stopped,
    blocked_waf: waf, blocked_behaviour: beh, rate_limited: rl, rejected_limit: rej, challenged: 0,
    fail_closed: fail, fail_closed_by: { waf_timeout: tout, waf_busy: busy, not_ready: 0, panic: 0 },
    would_block: would, would_rate_limit: r(c.would_rate_limit), page_views: pv, detections: waf + Math.min(would, r(c.detections - c.blocked_waf)),
    status: { s1xx: 0, s2xx: Math.max(0, s2), s3xx: s3, s4xx: s4, s5xx: s5 },
    upstream_errors: r(c.upstream_errors), upstream_timeouts: r(c.upstream_timeouts),
    bytes_in: Math.round(c.bytes_in * (requests / Math.max(0.01, c.requests))), bytes_out: Math.round(c.bytes_out * (forwarded / Math.max(0.01, c.forwarded))),
  }
}

function serverNow(m: MonitoringMock, tMs: number): ServerNow {
  const s = Math.floor(tMs / 10_000) * 10
  const used = gauge(m, 'server.memory_used', s)!
  const fullest = mounts(m).map(d => ({ mount: d.mount, used_ratio: gauge(m, 'server.disk_used_ratio', s, d.mount)! })).sort((a, b) => b.used_ratio - a.used_ratio)[0]!
  return {
    sampled_at: iso(s * 1000),
    scope: 'host',
    cpu_usage: gauge(m, 'server.cpu_usage', s),
    cores: CORES,
    load1: gauge(m, 'server.load1', s),
    memory_used_ratio: used / MEM_TOTAL,
    memory_available_bytes: Math.round(MEM_TOTAL - used),
    swap_used_bytes: Math.round(gauge(m, 'server.swap_used', s)!),
    disk: fullest,
    net_rx_bytes_per_s: counterServer(m, 'server.net_rx_bytes', s, 'eth0'),
    net_tx_bytes_per_s: counterServer(m, 'server.net_tx_bytes', s, 'eth0'),
    uptime_s: Math.round((tMs - (Date.parse('2026-09-14T03:12:00Z'))) / 1000),
  }
}

function liveTick(m: MonitoringMock, sec: number, site?: string): LiveTick {
  const t: LiveTick = { t: iso(sec * 1000), traffic: tickCounters(m, sec, site) }
  const l = latency(m, sec, site)
  t.latency_total_p95_ms = l.total.p95
  t.latency_overhead_p95_ms = l.overhead.p95
  if (!site && m.sites.length) t.sites = m.sites.map(s => ({ site: s.id, requests: tickCounters(m, sec, s.id).requests, stopped: tickCounters(m, sec, s.id).stopped }))
  t.schild = { event_queue_fill: gauge(m, 'schild.event_queue_fill', sec)!, eval_slots_used: Math.round(gauge(m, 'schild.eval_slots_used', sec)! * 16), eval_slots_max: 16 }
  if (sec % 10 === 0) t.server = serverNow(m, sec * 1000)
  return t
}

export function hints(m: MonitoringMock, now: number, site?: string): HealthHint[] {
  const ago = (ms: number) => iso(now - ms)
  if (m.scenario === 'empty' || m.scenario === 'standalone') return []
  const out: HealthHint[] = []
  const docker = mounts(m)[1]!
  if (docker.base >= 0.9) out.push({ code: 'disk_full_soon', level: 'notice', since: ago(3 * 86400_000), value: docker.base, threshold: 0.9, object: docker.mount })
  if (m.scenario === 'degraded') {
    out.unshift(
      { code: 'traffic_spike', level: 'notice', since: ago(9 * 60_000), value: 5.6, threshold: 5 },
      { code: 'cpu_high', level: 'warning', since: ago(14 * 60_000), value: 0.94, threshold: 0.9 },
      { code: 'waf_saturated', level: 'warning', since: ago(6 * 60_000), value: 213, threshold: 1 },
      { code: 'upstream_errors', level: 'notice', since: ago(11 * 60_000), value: 87, threshold: 10 },
      { code: 'memory_low', level: 'warning', since: ago(20 * 60_000), value: 0.07, threshold: 0.1 },
    )
    // v0.5 (D38): schild's own store (server only) and the 7-day projection of the root file system.
    out.push(
      { code: 'store_cap_unreachable', level: 'warning', since: ago(50 * 60_000), value: 1_090_000_000, threshold: 1_048_576_000 },
      { code: 'storage_budget', level: 'notice', since: ago(5 * 3600_000), value: null, threshold: 1_073_741_824, object: '/var/lib/schild' },
      { code: 'disk_fill_projection', level: 'notice', since: ago(26 * 3600_000), value: 9, threshold: 14, object: '/' },
    )
  }
  // Website-scoped hints (D36): computed from that website's own counters, marked with site.
  for (const s of m.sites) {
    const sl = m.events[s.id]?.slow
    if (!sl || now < sl.from || (site && site !== s.id)) continue
    if (sl.errors >= 0.01) out.push({ code: 'upstream_errors', level: 'notice', since: iso(sl.from + 60_000), value: Math.round(countersAt(m, now / 1000, s.id).upstream_errors * 300), threshold: 10, site: s.id })
    out.push({ code: 'upstream_slow', level: 'notice', since: iso(sl.from), value: latency(m, now / 1000, s.id).upstream.p95, threshold: 2000, site: s.id })
  }
  return out
}

function monitoringNow(m: MonitoringMock, now: number, site?: string): MonitoringNow {
  const sec = Math.floor(now / 1000) - 1
  const win = Array.from({ length: 60 }, (_, i) => tickCounters(m, sec - i, site))
  const sum = (k: (c: TrafficCounters) => number, n = 60) => win.slice(0, n).reduce((a, c) => a + k(c), 0)
  const req = sum(c => c.requests)
  const fwd = sum(c => c.forwarded)
  const l = latency(m, sec, site)
  const empty = m.scenario === 'empty' && now - m.startedAt < 10_000
  return {
    generated_at: iso(now),
    started_at: iso(m.startedAt),
    ...(site ? { site } : {}),
    traffic: {
      window_s: 60,
      requests_per_s: req / 60,
      requests_per_s_10s: sum(c => c.requests, 10) / 10,
      stopped_share: req ? sum(c => c.stopped) / req : null,
      would_block_share: req ? sum(c => c.would_block) / req : null,
      fail_closed: sum(c => c.fail_closed),
      upstream_error_share: fwd ? sum(c => c.upstream_errors + c.upstream_timeouts) / fwd : null,
      latency_total_p50_ms: l.total.p50,
      latency_total_p95_ms: l.total.p95,
      latency_overhead_p95_ms: l.overhead.p95,
      latency_upstream_p95_ms: l.upstream.p95,
      bytes_in_per_s: sum(c => c.bytes_in) / 60,
      bytes_out_per_s: sum(c => c.bytes_out) / 60,
      clients_unique: Math.round(req / 5),
    },
    server: empty ? null : serverNow(m, now),
    hints: hints(m, now, site),
    ...(!site && m.sites.length
      ? {
          sites: m.sites.map((s) => {
            const w = Array.from({ length: 60 }, (_, i) => tickCounters(m, sec - i, s.id))
            const r = w.reduce((a, c) => a + c.requests, 0)
            return { site: s.id, label: s.label, requests_per_s: r / 60, stopped_share: r ? w.reduce((a, c) => a + c.stopped, 0) / r : null }
          }),
        }
      : {}),
  }
}

function snapshot(m: MonitoringMock, now: number): ServerSnapshot {
  const s = Math.floor(now / 10_000) * 10
  const cpu = gauge(m, 'server.cpu_usage', s)!
  const used = gauge(m, 'server.memory_used', s)!
  const own = m.scenario === 'standalone'
  return {
    generated_at: iso(now),
    sampled_at: iso(s * 1000),
    interval_s: 10,
    environment: { os_family: 'linux', container: true, cgroup: 'v2', net_namespace: own ? 'own' : 'host', lxcfs: false },
    os: { source: 'host_report', name: 'Ubuntu 24.04.1 LTS', kernel: '6.8.0-47-generic', arch: 'x86_64', eol: '2029-05-31', report_at: iso(now - 5 * 3600_000) },
    uptime_s: Math.round((now - Date.parse('2026-09-14T03:12:00Z')) / 1000),
    cpu: {
      scope: 'host',
      cores: CORES,
      usage: cpu,
      user: cpu * 0.72,
      system: cpu * 0.22,
      iowait: gauge(m, 'server.cpu_iowait', s)!,
      steal: gauge(m, 'server.cpu_steal', s)!,
      per_core: Array.from({ length: CORES }, (_, i) => Math.min(1, Math.max(0, cpu * (0.7 + 0.6 * hash(s, i))))),
      load1: gauge(m, 'server.load1', s)!,
      load5: gauge(m, 'server.load5', s)!,
      load15: gauge(m, 'server.load15', s)!,
    },
    memory: {
      scope: 'host',
      total_bytes: MEM_TOTAL,
      available_bytes: Math.round(MEM_TOTAL - used),
      used_bytes: Math.round(used),
      cached_bytes: 3.4e9,
      swap_total_bytes: 2e9,
      swap_used_bytes: Math.round(gauge(m, 'server.swap_used', s)!),
      oom_kills_24h: 0,
    },
    container: { cpu_limit_cores: null, cpu_usage: gauge(m, 'container.cpu_usage', s)!, cpu_throttled: 0, memory_used_bytes: Math.round(gauge(m, 'container.memory_used', s)!), memory_limit_bytes: 1e9, oom_kills: 0 },
    mounts: mounts(m).map((d, i) => {
      const ratio = gauge(m, 'server.disk_used_ratio', s, d.mount)!
      const dev = OBJECTS.device![i]!
      return {
        mount: d.mount,
        device: dev,
        fs_type: d.fs,
        size_bytes: d.size,
        used_bytes: Math.round(d.size * ratio),
        avail_bytes: Math.round(d.size * (1 - ratio)),
        used_ratio: ratio,
        inodes_total: d.inodes,
        inodes_used: Math.round(d.inodes * ratio * 0.35),
        read_bytes_per_s: counterServer(m, 'server.disk_read_bytes', s, dev),
        write_bytes_per_s: counterServer(m, 'server.disk_write_bytes', s, dev),
        reads_per_s: 4 + 20 * model(m, s).load,
        writes_per_s: 9 + 30 * model(m, s).load,
        busy: gauge(m, 'server.disk_busy', s, dev),
      }
    }),
    interfaces: (own ? ['eth0'] : OBJECTS.interface!).map(name => ({
      name,
      rx_bytes_per_s: counterServer(m, 'server.net_rx_bytes', s, name)!,
      tx_bytes_per_s: counterServer(m, 'server.net_tx_bytes', s, name)!,
      rx_packets_per_s: counterServer(m, 'server.net_rx_bytes', s, name)! / 800,
      tx_packets_per_s: counterServer(m, 'server.net_tx_bytes', s, name)! / 1200,
      errors_per_s: 0,
      drops_per_s: counterServer(m, 'server.net_drops', s, name)!,
    })),
    // Degraded: many sockets, so only the sockstat totals (D36 amendment: listen null = unknown).
    tcp: m.scenario === 'degraded'
      ? {
          source: 'sockstat',
          established: gauge(m, 'server.tcp_established', s)!,
          syn_sent: 0,
          syn_recv: 0,
          fin_wait: 0,
          time_wait: gauge(m, 'server.tcp_time_wait', s)!,
          close_wait: 0,
          last_ack: 0,
          closing: 0,
          listen: null,
          inuse: gauge(m, 'server.tcp_established', s)!,
          orphan: 3,
          listen_drops_per_s: counterServer(m, 'server.tcp_listen_drops', s)!,
          retransmits_per_s: counterServer(m, 'server.tcp_retransmits', s)!,
        }
      : {
          source: 'netlink',
          established: gauge(m, 'server.tcp_established', s)!,
          syn_sent: 2,
          syn_recv: gauge(m, 'server.tcp_syn_recv', s)!,
          fin_wait: 6,
          time_wait: gauge(m, 'server.tcp_time_wait', s)!,
          close_wait: gauge(m, 'server.tcp_close_wait', s)!,
          last_ack: 1,
          closing: 0,
          listen: 9,
          listen_drops_per_s: counterServer(m, 'server.tcp_listen_drops', s)!,
          retransmits_per_s: counterServer(m, 'server.tcp_retransmits', s)!,
        },
    conntrack: own ? null : { count: Math.round(262144 * gauge(m, 'server.conntrack_used_ratio', s)!), max: 262144 },
    files: { open: Math.round(9_000 + 2_000 * model(m, s).load), max: 1_048_576 },
    process: {
      started_at: iso(m.startedAt),
      version: '0.1.0-alpha',
      cpu_usage: gauge(m, 'process.cpu_usage', s)!,
      rss_bytes: Math.round(gauge(m, 'process.rss', s)!),
      heap_bytes: Math.round(gauge(m, 'process.heap', s)!),
      goroutines: gauge(m, 'process.goroutines', s)!,
      threads: 14,
      gc_pause_p99_ms: gauge(m, 'process.gc_pause_p99', s)!,
      open_files: gauge(m, 'process.open_files', s)!,
      open_files_limit: 65_536,
    },
    schild: {
      event_queue_used: Math.round(4096 * gauge(m, 'schild.event_queue_fill', s)!),
      event_queue_capacity: 4096,
      events_dropped_1h: m.scenario === 'degraded' ? 1_080 : 0,
      eval_slots_used: Math.round(16 * gauge(m, 'schild.eval_slots_used', s)!),
      eval_slots_max: 16,
      // retention.max_size_mb 1000 (in MiB); degraded: above the cap it cannot reach (store_cap_unreachable).
      store_bytes: m.scenario === 'degraded' ? 1_090_000_000 : 2.1e8,
      store_max_bytes: 1_048_576_000,
      metrics_store_bytes: 2.6e7,
      sampler_ms: gauge(m, 'schild.sampler_ms', s)!,
      sampler_budget_ms: 50,
    },
    unavailable: own ? [{ area: 'conntrack', reason: 'container_hidden' }] : [],
  }
}

function catalogue(m: MonitoringMock): MetricCatalogue {
  const rings: [string, number, number][] = [['10s', 10, m.keep[0]], ['1m', 60, m.keep[1]], ['10m', 600, m.keep[2]]]
  return {
    resolutions: rings.map(([resolution, step, keep]) => ({ resolution, step_s: step, keep_s: keep, slots: keep / step, oldest: iso(Math.max(m.restarts[m.restarts.length - 1] ?? m.startedAt, Date.now() - keep * 1000)) })) as MetricCatalogue['resolutions'],
    max_points: 1000,
    max_series: 16,
    metrics: CATALOGUE.map(c => ({
      id: c.id,
      kind: c.kind,
      unit: c.unit,
      scope: c.scope,
      exact: c.exact,
      ...(c.error_bound ? { error_bound: c.error_bound } : {}),
      stats: STATS[c.kind],
      default_stat: STATS[c.kind][0],
      per_object: c.per_object,
      site_aware: c.site_aware,
      available: !(m.scenario === 'standalone' && c.id === 'server.conntrack_used_ratio'),
      ...(m.scenario === 'standalone' && c.id === 'server.conntrack_used_ratio' ? { reason: 'container_hidden' } : {}),
    })) as MetricCatalogue['metrics'],
  }
}

// ------------------------------------------------------------------ handlers

type Params = Record<string, string | readonly string[] | undefined>
type Fn = (args: { request: Request, params: Params }) => Promise<Response> | Response
export interface MonitoringHandlerTools {
  base: string
  monitoring: () => MonitoringMock
  scenario: () => Scenario
  now: () => number
  guard: (kind: 'read' | 'write', fn: Fn) => (args: { request: Request, params: Params }) => Promise<Response>
  problem: (status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) => Response
  /** Interval of live ticks (ms); 1000 in the browser, shorter in tests. */
  tickMs?: number
  /**
   * MVP-27: what an answer covers in a cluster, for the `node` asked for (null: none); undefined on a single
   * gateway, 'invalid' for a node that is no gateway of the cluster.
   */
  cluster?: (node: string | null) => ClusterScope | undefined | 'invalid'
}

type ClusterScope = import('@/api/generated/schema').components['schemas']['ClusterScope']

/** Rounded counters of a whole bucket from the per-second model. */
function bucketCounters(m: MonitoringMock, fromSec: number, stepS: number, site?: string): TrafficCounters {
  const scale = (v: unknown): unknown => typeof v === 'number'
    ? Math.round(v * stepS)
    : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scale(x)])) : v
  return scale(countersAt(m, fromSec + stepS / 2, site)) as TrafficCounters
}

/**
 * The two newest finished 10-minute buckets with per-website numbers. Visitors (clients.unique) count
 * people only; clients.bots the bot and tool clients (D36 amendment).
 */
function tenMinuteBuckets(m: MonitoringMock, now: number) {
  const step = 600
  const end = Math.floor(now / 1000 / step) * step
  const empty = { scheme: 'exp1.25-0.05ms', counts: {} }
  const est = (c: TrafficCounters) => ({ unique: Math.round(c.page_views * 0.6), new: Math.round(c.page_views * 0.2), bots: Math.max(1, Math.round(c.requests * 0.004)) })
  return [end - 2 * step, end - step].map((from) => {
    const traffic = bucketCounters(m, from, step)
    return {
      t: new Date(from * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      resolution: '10m',
      step_s: step,
      partial: false,
      traffic,
      latency: { total: empty, overhead: empty, upstream: empty },
      clients: est(traffic),
      sites: m.sites.filter(x => x.id).map((x) => {
        const c = bucketCounters(m, from, step, x.id)
        return { site: x.id, traffic: c, clients: est(c) }
      }),
      values: {},
    }
  })
}

export function monitoringHandlers(t: MonitoringHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const gate = () => {
    if (t.scenario() === 'error') return problem(503, 'internal', 'Interner Fehler')
    if (!t.monitoring().enabled) return problem(409, 'monitoring_off', 'Monitoring ist ausgeschaltet')
    return null
  }
  const siteOf = (url: URL) => {
    const s = url.searchParams.get('site')
    if (!s) return { site: undefined, err: null }
    if (!t.monitoring().sites.some(x => x.id === s)) return { site: undefined, err: problem(400, 'invalid', 'Unbekannte Website', [{ pointer: '#/query/site', detail: 'unknown site' }]) }
    return { site: s, err: null }
  }

  return [
    http.get(`${base}/monitoring/now`, guard('read', ({ request }) => {
      const g = gate()
      if (g) return g
      const url = new URL(request.url)
      const { site, err } = siteOf(url)
      if (err) return err
      const cluster = t.cluster?.(url.searchParams.get('node'))
      if (cluster === 'invalid') return problem(400, 'invalid', 'Unbekannter Server', [{ pointer: '#/query/node', detail: 'no such node of the group' }])
      return json({ ...monitoringNow(t.monitoring(), t.now(), site), ...(cluster ? { cluster } : {}) })
    })),
    http.get(`${base}/monitoring/stream`, guard('read', ({ request }) => {
      const g = gate()
      if (g) return g
      const m = t.monitoring()
      const { site, err } = siteOf(new URL(request.url))
      if (err) return err
      const enc = new TextEncoder()
      const every = t.tickMs ?? 1000
      let timer: ReturnType<typeof setInterval> | undefined
      let last = Math.floor(t.now() / 1000) - 1
      const lastId = Number(request.headers.get('Last-Event-ID') ?? '')
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          const send = (sec: number) => controller.enqueue(enc.encode(`id: ${sec}\nevent: tick\ndata: ${JSON.stringify(liveTick(m, sec, site))}\n\n`))
          controller.enqueue(enc.encode(': schild mock monitoring\nretry: 3000\n\n'))
          // Replay from Last-Event-ID (at most 300 s), else start with the last 60 s so the tiles fill at once.
          const fromSec = Number.isFinite(lastId) && lastId > last - 300 && lastId <= last ? lastId + 1 : last - 59
          for (let s = fromSec; s <= last; s++) send(s)
          timer = setInterval(() => {
            const nowSec = Math.floor(t.now() / 1000) - 1
            // In tests the clock may not advance: emit the next second anyway.
            const target = Math.max(nowSec, last + 1)
            for (let s = last + 1; s <= target; s++) send(s)
            last = target
          }, every)
          request.signal?.addEventListener('abort', () => {
            clearInterval(timer)
            try {
              controller.close()
            }
            catch { /* already closed */ }
          })
        },
        cancel() {
          clearInterval(timer)
        },
      })
      return new HttpResponse(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' } })
    })),
    http.get(`${base}/monitoring/series`, guard('read', ({ request }) => {
      const g = gate()
      if (g) return g
      const m = t.monitoring()
      const url = new URL(request.url)
      const q = url.searchParams
      const { site, err } = siteOf(url)
      if (err) return err
      const metrics = q.getAll('metric')
      if (!metrics.length || metrics.length > 16) return problem(400, 'invalid', 'Ungültige Abfrage', [{ pointer: '#/query/metric', detail: '1 to 16 metrics' }])
      const now = t.now()
      const to = q.get('to') ? Date.parse(q.get('to')!) : now
      const from = q.get('from') ? Date.parse(q.get('from')!) : to - 3600_000
      if (!(from < to)) return problem(400, 'invalid', 'Ungültiger Zeitraum', [{ pointer: '#/query/from', detail: 'from must be before to' }])
      let res = q.get('resolution') ?? 'auto'
      const pts = (r: string, step = STEPS[r]!) => Math.floor((to - 1) / 1000 / step) - Math.floor(from / 1000 / step) + 1
      // D36: auto over the coarsest ring merges 3, 6, 18, ... buckets per point instead of too_many_points.
      let bpp = 1
      if (res === 'auto') {
        res = (['10s', '1m', '10m'] as const).find((r, i) => pts(r) <= 1000 && from >= now - m.keep[i]! * 1000) ?? '10m'
        if (res === '10m') bpp = [1, 3, 6, 18, 36, 72, 144].find(b => pts('10m', 600 * b) <= 1000) ?? 144
      }
      if (!STEPS[res]) return problem(400, 'invalid', 'Ungültige Auflösung', [{ pointer: '#/query/resolution', detail: 'auto, 10s, 1m or 10m' }])
      const stepS = STEPS[res]! * bpp
      const points = pts(res, stepS)
      if (points > 1000) return problem(400, 'too_many_points', 'Mehr als 1000 Punkte', [{ pointer: '#/query/resolution', detail: 'more than 1000 points' }])
      const filters = q.getAll('filter')
      const inRequestRing = m.requestRing && now - from <= REQUEST_RING_MS + 600_000
      if (needsRequestRing(filters) && !inRequestRing) return problem(409, 'filter_unavailable', 'Kombinierte Filter brauchen die einzelnen Anfragen')
      if (filters.length && !inRequestRing && metrics.some(x => !FILTERABLE.has(x.split(':')[0]!))) return problem(409, 'filter_unavailable', 'Dieser Wert lässt sich nur in den letzten 48 Stunden filtern')
      // As the gateway: per-website top lists live in the 10 min ring only.
      if (filters.length && !inRequestRing && site && res !== '10m') return problem(409, 'filter_unavailable', 'Mit Filter gibt es pro Website nur die 10-Minuten-Werte')
      const share = filters.length ? filtersShare(filters, site) : null
      const start = Math.floor(from / 1000 / stepS) * stepS * 1000
      const ringIdx = res === '10s' ? 0 : res === '1m' ? 1 : 2
      const oldest = now - m.keep[ringIdx]! * 1000
      const out: MetricSeries[] = []
      for (const metric of metrics) {
        const r = seriesFor(m, metric, start, stepS, points, now, site, q.get('object') ?? undefined)
        if (typeof r === 'string') return problem(400, 'invalid', 'Ungültige Metrik', [{ pointer: '#/query/metric', detail: r }])
        // Older than the ring: null.
        for (const s of r) s.values = s.values.map((v, i) => start + i * stepS * 1000 < oldest ? null : v)
        if (share) {
          const id = metric.split(':')[0]!
          const k = id === 'traffic.latency_total' || id.startsWith('traffic.latency') ? 1 : BAD_METRICS.has(id) ? share.bad : share.clean
          for (const s of r) {
            s.values = s.values.map(v => v === null ? null : v * k)
            if (!share.exact) s.exact = false
          }
        }
        out.push(...r)
      }
      const partial = Array.from({ length: points }, (_, i) => {
        const a = start + i * stepS * 1000
        const b = a + stepS * 1000
        return b > now || m.restarts.some(r => r >= a && r < b)
      })
      return json({
        from: iso(start),
        to: iso(start + points * stepS * 1000),
        resolution: res,
        step_s: stepS,
        ...(bpp > 1 ? { buckets_per_point: bpp } : {}),
        points,
        ...(partial.some(Boolean) ? { partial } : {}),
        ...(filters.length ? { filters, source: inRequestRing && needsRequestRing(filters) ? 'requests' : 'rings' } : {}),
        ...(site ? { site } : {}),
        series: out,
        restarts: m.restarts.filter(r => r >= start && r < start + points * stepS * 1000).map(iso),
      })
    })),
    http.get(`${base}/monitoring/traffic/breakdown`, guard('read', ({ request }) => {
      const g = gate()
      if (g) return g
      const url = new URL(request.url)
      const q = url.searchParams
      const { site, err } = siteOf(url)
      if (err) return err
      const by = q.get('by') as BreakdownDimension | null
      const dims = ['path', 'country', 'asn', 'net_class', 'ua_class', 'method', 'status_class', 'site', 'referrer', 'browser', 'os', 'device', 'bot_category', 'rule', 'ip', 'user_agent']
      if (!by || !dims.includes(by)) return problem(400, 'invalid', 'Ungültige Dimension', [{ pointer: '#/query/by', detail: 'unknown dimension' }])
      const now = t.now()
      const to = q.get('to') ? Date.parse(q.get('to')!) : now
      const from = q.get('from') ? Date.parse(q.get('from')!) : to - 3600_000
      const top = Math.min(100, Math.max(1, Number(q.get('top') ?? 20) || 20))
      const filters = q.getAll('filter')
      // A breakdown under a filter, and addresses and User-Agents at all (D65), come from the request ring (48 h, D36).
      if ((filters.length || by === 'ip' || by === 'user_agent') && (!t.monitoring().requestRing || now - from > REQUEST_RING_MS + 600_000)) return problem(409, 'filter_unavailable', 'Gefilterte Aufschlüsselung braucht die einzelnen Anfragen')
      return json(breakdown(t.monitoring(), by, from, to, site, top, now, filters))
    })),
    http.get(`${base}/monitoring/server`, guard('read', () => {
      const g = gate()
      if (g) return g
      return json(snapshot(t.monitoring(), t.now()))
    })),
    http.get(`${base}/monitoring/catalogue`, guard('read', () => {
      const g = gate()
      if (g) return g
      return json(catalogue(t.monitoring()))
    })),
    http.get(`${base}/monitoring/buckets`, guard('read', ({ request }) => {
      const g = gate()
      if (g) return g
      const res = new URL(request.url).searchParams.get('resolution') ?? '1m'
      // Only the newest finished 10-minute buckets (Bot-Clients of the overview, D36 amendment).
      if (res !== '10m') return json({ resolution: res, items: [], next_cursor: null })
      return json({ resolution: '10m', items: tenMinuteBuckets(t.monitoring(), t.now()), next_cursor: null })
    })),
  ]
}
