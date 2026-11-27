/**
 * Mock of the "websites" tag (contracts v0.5, D36): four apps on one server (web-1) built on the
 * monitoring model, so cards, KPIs, charts, annotations and "Letzte Alarme" tell the same story:
 * a distributed login attack on verein.example (with a 7-day block of a data-centre address), a
 * newsletter spike on praxis.example and a slow app on shop.example. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { AccessProtection, AccessProtectionInput, AccessProtectionState } from '@/api/access'
import type { MockState, StoredEvent } from './data'
import type { MockSite, MonitoringMock } from './monitoring'
import type { HealthHint, TrafficCounters, TrafficNow } from '@/api/monitoring'
import type { Incident } from '@/api/types'
import type { AlertItem, Annotation, FalsePositiveHint, KpiSet, KpiValue, ServerHealth, WebsiteStatusReason, WebsiteSummary } from '@/api/websites'
import { http, HttpResponse } from 'msw'
import { ruleCategoryOf } from '@/lib/websites'
import { buildDetail, gatewayMode, iso } from './data'
import { countersAt, filtersShare, hints, latency, needsRequestRing, REQUEST_RING_MS, tickCounters } from './monitoring'

/**
 * Hints about schild's own event store and its audit log mark only the server, never its websites (D36 amendment,
 * D38 and D108, contract/websites.ServerOnlyHintCodes): shown on the server page, left out at every website.
 */
const SERVER_ONLY_HINTS: ReadonlySet<HealthHint['code']> = new Set<HealthHint['code']>(['store_near_cap', 'store_cap_unreachable', 'storage_budget', 'audit_stuck', 'audit_size'])

export const NODE = 'web-1'
/** Incident of the 7-day block after the wave (block_long annotation, ref). */
export const LONG_BLOCK_INCIDENT = 'R4ZC-9HTK'
const WAVE_ID = '6f1c2a9e-3b7d-4c55-9a10-2e8f4d6b7c31'

const isoS = (ms: number) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')

function hex(seed: string, n: number): string {
  let h = 2166136261
  let out = ''
  for (let k = 0; out.length < n; k++) {
    for (const ch of `${seed}:${k}`) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0
    out += h.toString(16).padStart(8, '0')
  }
  return out.slice(0, n)
}
/** Keyed client pseudonym like the agent API (p1-<16 hex>); the address itself stays in the event. */
export const pseudonymOf = (ip: string) => `p1-${hex(`pseudonym:${ip}`, 16)}`

// ------------------------------------------------------------------ seeding (createState)

/**
 * Give stored events and incidents their website, add the events of the wave and the long block, and
 * which websites each blocked client touched (sites_affected). Called once by createState.
 */
export function seedWebsites(st: MockState): void {
  const m = st.monitoring
  const sites = m.sites
  const total = Math.max(1, sites.filter(s => s.id).length)
  for (const e of st.events) {
    if (!e.summary.site) e.summary.site = sites.some(s => s.id === e.summary.host) ? e.summary.host : sites[0]?.id
  }
  const wave = m.events['verein.example']?.wave
  if (wave) {
    // A distributed login attack: many hosting addresses, a few requests each, stopped by behaviour and limits.
    const addresses = ['203.0.113.42', '203.0.113.43', '203.0.113.77', '203.0.113.78', '203.0.113.150', '192.0.2.200', '2001:db8::17', '2001:db8:7::1']
    const geos = [
      { country: 'NL', city: 'Amsterdam', asn: 64500, as_org: 'Example Hosting B.V.', net_class: 'hosting' },
      { country: 'US', city: 'Ashburn', asn: 64501, as_org: 'Example Cloud Inc.', net_class: 'hosting' },
      { country: 'SG', city: 'Singapur', asn: 64505, as_org: 'Example VPS Asia', net_class: 'hosting' },
    ] as const
    for (let i = 0; i < 18; i++) {
      const at = wave.from + Math.floor(((i + 0.5) / 18) * (wave.to - wave.from))
      const id = `${hex(`wave:${i}`, 8)}-${hex(`wave-b:${i}`, 4)}-4${hex(`wave-c:${i}`, 3)}-a${hex(`wave-d:${i}`, 3)}-${hex(`wave-e:${i}`, 12)}`
      const ip = addresses[i % addresses.length]!
      const geo = geos[i % geos.length]!
      const blocked = st.settings.profile !== 'test'
      const summary = {
        id, time: iso(at), type: blocked ? 'schild.request.blocked.v1' : 'schild.request.evaluated.v1', outcome: blocked ? 'blocked' as const : 'would_block' as const,
        ip, geo: { ...geo }, method: 'POST', host: 'verein.example', site: 'verein.example', path: '/wp-login.php', status: blocked ? 403 : 200, score: 72,
        rules: ['930120'], session_id: `s_${hex(`wave-s:${i}`, 10)}`,
        ...(blocked && i === 5 ? { incident: LONG_BLOCK_INCIDENT } : {}),
      }
      const stored: StoredEvent = { summary, detail: buildDetail(summary, { mode: gatewayMode(st.settings), ua: 'Mozilla/5.0 (compatible; wp-login-check/1.0)', rules: [{ id: 930120, repository: 'crs', msg: 'OS File Access Attempt', severity: 'critical' }] }) }
      st.events.push(stored)
      if (summary.incident) {
        st.incidents.set(LONG_BLOCK_INCIDENT, {
          incident: LONG_BLOCK_INCIDENT, status: 'blocked', time: summary.time, request: summary,
          reason: 'Wiederholt auffällig: Login-Versuche aus einem Rechenzentrum (login_bruteforce, Stufe 4)',
          unblocked_at: null, allowlist_entry: null,
          site: 'verein.example',
          sites_affected: { sites: ['verein.example', 'shop.example', 'blog.example'], count: 3, total },
          // D36 amendment: the timed block behind the incident (7 days: data centre, fourth time).
          block: { source: 'behaviour:login_bruteforce', until: isoS(at + 7 * 86400_000), level: 4, net_class: 'hosting', duration_s: 7 * 86400, persisted: true, incident: LONG_BLOCK_INCIDENT },
        })
      }
    }
    st.events.sort((a, b) => Date.parse(b.summary.time) - Date.parse(a.summary.time))
  }
  if (sites.some(s => s.id === 'verein.example') && m.scenario !== 'empty') {
    // Normal members sending the join form trip rule 942100: the false-positive hint of verein.example
    // (possible_false_positive on these alerts).
    for (let i = 0; i < 3; i++) {
      const at = m.anchor - (40 + i * 70) * 60_000
      const id = `${hex(`fp:${i}`, 8)}-${hex(`fp-b:${i}`, 4)}-4${hex(`fp-c:${i}`, 3)}-b${hex(`fp-d:${i}`, 3)}-${hex(`fp-e:${i}`, 12)}`
      const summary = {
        id, time: iso(at), type: 'schild.request.evaluated.v1', outcome: 'would_block' as const,
        ip: `198.51.100.${60 + i}`, geo: { country: 'DE', city: 'Köln', asn: 64510, as_org: 'Example Telekom', net_class: 'residential' },
        method: 'POST', host: 'verein.example', site: 'verein.example', path: '/mitglied-werden', status: 200, score: 5,
        rules: ['942100'], session_id: `s_${hex(`fp-s:${i}`, 10)}`,
      }
      st.events.push({ summary, detail: buildDetail(summary, { mode: gatewayMode(st.settings), ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', rules: [{ id: 942100, repository: 'crs', msg: 'SQL Injection Attack Detected via libinjection', severity: 'critical' }] }) })
    }
    st.events.sort((a, b) => Date.parse(b.summary.time) - Date.parse(a.summary.time))
  }
  for (const [k, inc] of st.incidents) {
    if (inc.sites_affected) continue
    const site = inc.site ?? inc.request.site ?? sites[0]?.id
    const others = sites.map(s => s.id).filter(x => x !== site)
    // Scanners hit several apps: about a third of the incidents touched more than one website.
    const extra = sites.length > 1 ? Number.parseInt(hex(`aff:${k}`, 2), 16) % 3 : 0
    const touched = [site, ...others.slice(0, extra)].filter((x): x is string => !!x)
    st.incidents.set(k, { ...inc, ...(site ? { site } : {}), ...(site ? { sites_affected: { sites: touched, count: touched.length, total } } : {}) })
  }
}

// ------------------------------------------------------------------ numbers

function sumCounters(m: MonitoringMock, fromMs: number, toMs: number, site: string | undefined, stepS: number) {
  const z = { requests: 0, page_views: 0, stopped: 0, would_block: 0, s5xx: 0, clean: 0, latW: 0, latN: 0 }
  for (let t = fromMs; t < toMs; t += stepS * 1000) {
    const span = Math.min(stepS, (toMs - t) / 1000)
    const c = countersAt(m, t / 1000 + span / 2, site)
    z.requests += c.requests * span
    z.page_views += c.page_views * span
    z.stopped += c.stopped * span
    z.would_block += c.would_block * span
    z.s5xx += c.status.s5xx * span
    z.clean += (c.forwarded - c.would_block) * span
    const l = latency(m, t / 1000 + span / 2, site)
    z.latW += l.total.p95 * c.requests * span
    z.latN += c.requests * span
  }
  return z
}

function inRestartGap(m: MonitoringMock, from: number, to: number) {
  return m.restarts.some(r => r - 180_000 < to && r > from)
}

function kpiSet(m: MonitoringMock, fromMs: number, toMs: number, site: string, filters: string[], now: number): KpiSet {
  const len = toMs - fromMs
  const step = len <= 6 * 3600_000 ? 60 : 600
  const z = sumCounters(m, fromMs, toMs, site, step)
  const inRing = m.requestRing && now - fromMs <= REQUEST_RING_MS + 600_000
  const f = filters.length ? filtersShare(filters, site) : { clean: 1, bad: 1, exact: true }
  // Contracts v0.5 (D36 fix round 1): a restart gap in the range makes every value partial (gap_kind restart:
  // the mock's restarts are orderly deploys); exact only
  // says counted vs estimate.
  const gap = inRestartGap(m, fromMs, toMs)
  const v = (value: number | null, exact: boolean, extra: Partial<KpiValue> = {}): KpiValue => ({ value: value === null ? null : value, exact, ...(gap && value !== null ? { partial: true, gap_kind: 'restart' as const } : {}), ...extra })
  const needsRing = filters.length > 0 && !inRing
  const requests = z.clean * f.clean + (z.stopped + z.would_block) * f.bad
  return {
    visitors: needsRing ? v(null, false, { unavailable: 'filter_needs_requests' }) : v(Math.round(z.page_views * f.clean * 0.58 + z.requests * f.clean * 0.004), false, { error_bound: 0.033 }),
    page_views: needsRing ? v(null, false, { unavailable: 'filter_needs_requests' }) : v(Math.round(z.page_views * f.clean), !filters.length),
    requests: v(Math.round(requests), f.exact),
    stopped: v(Math.round(z.stopped * f.bad), f.exact),
    would_block: v(Math.round(z.would_block * f.bad), f.exact),
    latency_p95_ms: needsRing ? v(null, false, { unavailable: 'filter_needs_requests' }) : v(z.latN ? z.latW / z.latN : null, false, { error_bound: 0.25 }),
    error_rate: needsRing ? v(null, false, { unavailable: 'filter_needs_requests' }) : v(z.requests ? z.s5xx / z.requests : null, !filters.length),
  }
}

function trafficNow(m: MonitoringMock, now: number, site: string): TrafficNow {
  const sec = Math.floor(now / 1000) - 1
  const win: TrafficCounters[] = Array.from({ length: 60 }, (_, i) => tickCounters(m, sec - i, site))
  const sum = (k: (c: TrafficCounters) => number, n = 60) => win.slice(0, n).reduce((a, c) => a + k(c), 0)
  const req = sum(c => c.requests)
  const fwd = sum(c => c.forwarded)
  const l = latency(m, sec, site)
  return {
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
  }
}

/** Status rules of contract/websites.Status over the last 5 minutes (simplified for the mock). */
function statusOf(m: MonitoringMock, now: number, s: MockSite, server: ServerHealth): Pick<WebsiteSummary, 'status' | 'reasons'> {
  if (!m.enabled) return { status: 'unknown', reasons: [{ code: 'monitoring_off' }] }
  const reasons: WebsiteStatusReason[] = []
  let req = 0
  let fail = 0
  let fwd = 0
  let up = 0
  let s5 = 0
  for (let k = 0; k < 30; k++) {
    const c = countersAt(m, now / 1000 - 5 - k * 10, s.id)
    req += c.requests * 10
    fail += c.fail_closed * 10
    fwd += c.forwarded * 10
    up += (c.upstream_errors + c.upstream_timeouts) * 10
    s5 += c.status.s5xx * 10
  }
  if (req >= 10) {
    if (fail / req >= 0.05) reasons.push({ code: 'fail_closed' })
    if (fwd && up / fwd >= 0.2) reasons.push({ code: 'upstream_unreachable' })
    if (s5 / req >= 0.2) reasons.push({ code: 'errors_5xx' })
  }
  const disrupted = reasons.length > 0
  for (const h of hints(m, now, s.id).filter(h => h.site === s.id)) reasons.push({ code: 'site_hint', hint: h.code })
  // D36 amendment / D38: hints about schild's own event store mark only the server.
  for (const h of server.hints.filter(x => !SERVER_ONLY_HINTS.has(x.code))) reasons.push({ code: 'server_hint', node: server.node, hint: h.code, ...(h.object ? { object: h.object } : {}) })
  if (req === 0) return { status: reasons.length ? 'attention' : 'ok', reasons }
  return { status: disrupted ? 'disrupted' : reasons.length ? 'attention' : 'ok', reasons }
}

function serverHealth(m: MonitoringMock, now: number, baseline: 'active' | 'degraded' | 'off'): ServerHealth {
  const serverHints: HealthHint[] = m.enabled ? hints(m, now).filter(h => !h.site) : []
  return {
    node: NODE,
    this: true,
    status: baseline === 'off' ? 'disrupted' : serverHints.length || baseline === 'degraded' ? 'attention' : 'ok',
    baseline_protection: baseline,
    hints: serverHints,
  }
}

function baselineOf(st: MockState): 'active' | 'degraded' | 'off' {
  const g = (st.overview as { baseline?: { state?: string } }).baseline?.state
  return g === 'off' ? 'off' : g === 'degraded' ? 'degraded' : 'active'
}

/** AccessProtectionState of a website: its protection and its maintenance mode, two switches (D98). */
function accessStateOf(st: MockState, id: string): AccessProtectionState {
  const m = st.maintenance[id]
  return { website: id, protection: st.access[id] ?? null, maintenance: m ? { on: true, message: m.message, updated_at: m.updated_at, actor: 'dashboard' } : { on: false, message: '' } }
}

export function websiteSummary(st: MockState, s: MockSite, now: number): WebsiteSummary {
  const m = st.monitoring
  const server = serverHealth(m, now, baselineOf(st))
  const status = statusOf(m, now, s, server)
  return {
    id: s.id,
    label: s.label,
    hosts: s.hosts,
    hosts_total: s.hosts.length,
    source: 'caddyfile',
    protection: 'protected',
    tracked: true,
    ...status,
    now: m.enabled && !m.restarted ? trafficNow(m, now, s.id) : null,
    runs_on: [server],
  }
}

// ------------------------------------------------------------------ annotations, alerts, hints

function annotations(st: MockState, site: string, from: number, to: number): Annotation[] {
  const m = st.monitoring
  const out: Annotation[] = []
  const wave = m.events[site]?.wave
  if (wave) {
    out.push({ t: isoS(wave.from + 3 * 60_000), kind: 'wave_detected', detector: 'account_wave', count: 214, ref: WAVE_ID })
    out.push({ t: isoS(wave.from + 12 * 60_000), kind: 'block_long', ref: LONG_BLOCK_INCIDENT, net_class: 'hosting', duration_s: 7 * 86400, count: 4, until: isoS(wave.from + 12 * 60_000 + 7 * 86400_000) })
    out.push({ t: isoS(wave.to), kind: 'wave_ended', ref: WAVE_ID, detector: 'account_wave', duration_s: Math.round((wave.to - wave.from) / 1000) - 180 })
  }
  // Gateway-wide markers appear at every website.
  if (m.scenario !== 'empty') out.push({ t: isoS(m.anchor - 38 * 60_000), kind: 'config_changed', config_sha256: hex('config', 64) })
  for (const r of m.restarts) {
    out.push({ t: isoS(r - 180_000), until: isoS(r), kind: 'monitoring_gap', duration_s: 180 })
    out.push({ t: isoS(r), kind: 'restart' })
  }
  if (m.scenario !== 'empty') out.push({ t: isoS(m.anchor - 3 * 3600_000), kind: 'rule_repository_changed', repository: 'crowdsec', state_from: 'detect', state_to: 'block', actor: 'agent', token_label: 'coding-agent' })
  return out.filter(a => Date.parse(a.t) >= from && Date.parse(a.t) < to).sort((a, b) => Date.parse(a.t) - Date.parse(b.t))
}

const ALERT_OUTCOMES = new Set(['blocked', 'would_block'])

function alerts(st: MockState, site: string, from: number, to: number, filter: string | undefined, limit: number): AlertItem[] {
  const out: AlertItem[] = []
  // D36 amendment: the gateway marks WAF alerts whose rule and page have a false-positive hint (48 h ring).
  const fp = new Set(fpHints(st, site, Date.now()).map(h => `${h.rule_id}|${h.path}`))
  const ringFrom = Date.now() - REQUEST_RING_MS
  const [dim, ...rest] = (filter ?? '').split(':')
  const value = rest.join(':')
  for (const e of st.events) {
    const s = e.summary
    if (s.site !== site || !s.outcome || !ALERT_OUTCOMES.has(s.outcome) || !s.rules?.length) continue
    const t = Date.parse(s.time)
    if (t < from || t >= to) continue
    if (filter) {
      if (dim === 'path' && s.path !== value && !(s.path ?? '').startsWith(value.replace(/\{[^}]*\}.*$/, ''))) continue
      if (dim === 'country' && s.geo?.country !== value) continue
      if (dim === 'net_class' && s.geo?.net_class !== value) continue
      if (dim === 'asn' && String(s.geo?.asn) !== value) continue
      if (dim === 'rule' && !s.rules.includes(value)) continue
    }
    out.push({
      t: s.time,
      event_id: s.id,
      kind: 'waf',
      outcome: s.outcome as AlertItem['outcome'],
      category: ruleCategoryOf(s.rules[0]!),
      rules: s.rules.slice(0, 3),
      ...(s.path ? { path: s.path } : {}),
      ...(s.geo?.country ? { country: s.geo.country } : {}),
      ...(s.geo?.net_class ? { net_class: s.geo.net_class as AlertItem['net_class'] } : {}),
      ...(s.ip ? { client_pseudonym: pseudonymOf(s.ip) } : {}),
      ...(s.incident ? { incident: s.incident } : {}),
      ...(s.outcome === 'would_block' && s.would_block_reason ? { would_block_reason: s.would_block_reason } : {}),
      ...(t >= ringFrom && s.path && s.rules.some(r => fp.has(`${r}|${s.path}`)) ? { possible_false_positive: true } : {}),
    })
    if (out.length >= limit) break
  }
  return out
}

/** Possible false positives (MVP-22): one per website, with the exception limited to its hosts. */
export function fpHints(st: MockState, site: string | undefined, now: number): FalsePositiveHint[] {
  const defs: { site: string, rule: string, path: string, target: string, detections: number, clients: number, session: number }[] = [
    { site: 'verein.example', rule: '942100', path: '/mitglied-werden', target: 'ARGS:nachricht', detections: 23, clients: 17, session: 15 },
    { site: 'shop.example', rule: '941100', path: '/suche', target: 'ARGS:q', detections: 41, clients: 29, session: 26 },
  ]
  return defs
    .filter(d => st.monitoring.sites.some(s => s.id === d.site) && (!site || d.site === site))
    .map((d, i) => {
      const s = st.monitoring.sites.find(x => x.id === d.site)!
      const rx = s.hosts.map(h => h.replace(/\./g, '\\.')).join('|')
      const id = 1000101 + i
      return {
        rule_id: d.rule,
        path: d.path,
        target: d.target,
        detections: d.detections,
        clients_hit: d.clients,
        clients_in_session: d.session,
        since: isoS(now - (i + 2) * 86400_000),
        site: d.site,
        exception: {
          language: 'seclang',
          scope: 'website',
          file: `rules.d/50-exceptions-${d.site}.conf`,
          snippet: `# schild: exception for rule ${d.rule} on ${d.path}, website ${d.site} only\nSecRule REQUEST_HEADERS:Host "@rx ^(?:${rx})(?::[0-9]{1,5})?$" "id:${id},phase:1,pass,nolog,t:none,t:lowercase,chain"\n    SecRule REQUEST_FILENAME "@streq ${d.path}" "t:none,ctl:ruleRemoveTargetById=${d.rule};${d.target}"\n`,
        },
      }
    })
}

// ------------------------------------------------------------------ handlers

type Params = Record<string, string | readonly string[] | undefined>
type Fn = (args: { request: Request, params: Params }) => Promise<Response> | Response

export interface WebsiteHandlerTools {
  base: string
  state: () => MockState
  now: () => number
  guard: (kind: 'read' | 'write', fn: Fn) => (args: { request: Request, params: Params }) => Promise<Response>
  problem: (status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) => Response
}

export function websiteHandlers(t: WebsiteHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const range = (q: URLSearchParams, defLen = 86400_000) => {
    const now = t.now()
    const to = q.get('to') ? Date.parse(q.get('to')!) : now
    const from = q.get('from') ? Date.parse(q.get('from')!) : to - defLen
    return { from, to, now }
  }
  const findSite = (id: unknown) => t.state().monitoring.sites.find(s => s.id === id)
  const err = () => t.state().scenario === 'error' ? problem(503, 'internal', 'Interner Fehler') : null
  const monOff = () => !t.state().monitoring.enabled ? problem(409, 'monitoring_off', 'Monitoring ist ausgeschaltet') : null

  return [
    http.get(`${base}/websites`, guard('read', () => {
      const e = err()
      if (e) return e
      const st = t.state()
      const now = t.now()
      return json({
        generated_at: isoS(now),
        node: NODE,
        server: serverHealth(st.monitoring, now, baselineOf(st)),
        websites: st.monitoring.sites.map(s => websiteSummary(st, s, now)),
      })
    })),
    http.get(`${base}/websites/:website`, guard('read', ({ params }) => {
      const e = err()
      if (e) return e
      const st = t.state()
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const now = t.now()
      let traffic24: TrafficCounters | null = null
      if (st.monitoring.enabled) {
        const z = { ...countersAt(st.monitoring, now / 1000, s.id) }
        const keys = ['requests', 'forwarded', 'stopped', 'blocked_waf', 'blocked_behaviour', 'rate_limited', 'rejected_limit', 'challenged', 'fail_closed', 'would_block', 'would_rate_limit', 'page_views', 'detections', 'upstream_errors', 'upstream_timeouts', 'bytes_in', 'bytes_out'] as const
        const acc: Record<string, number> = Object.fromEntries(keys.map(k => [k, 0]))
        const status = { s1xx: 0, s2xx: 0, s3xx: 0, s4xx: 0, s5xx: 0 }
        for (let x = now - 86400_000; x < now; x += 600_000) {
          const c = countersAt(st.monitoring, x / 1000 + 300, s.id)
          for (const k of keys) acc[k]! += c[k] * 600
          for (const k of Object.keys(status) as (keyof typeof status)[]) status[k] += c.status[k] * 600
        }
        traffic24 = { ...z, ...Object.fromEntries(keys.map(k => [k, Math.round(acc[k]!)])), fail_closed_by: { waf_timeout: 0, waf_busy: Math.round(acc.fail_closed!), not_ready: 0, panic: 0 }, status: Object.fromEntries(Object.entries(status).map(([k, v]) => [k, Math.round(v)])) as TrafficCounters['status'] } as TrafficCounters
      }
      const incidents24 = [...st.incidents.values()].filter(i => i.site === s.id && Date.parse(i.time) >= now - 86400_000).length
      // D36 open items: counted from the schild start when that is inside the window; a restart gap or a
      // degraded sampler (scenario degraded) leaves the window partial without a later start.
      const m = st.monitoring
      const since = m.startedAt > now - 86400_000 ? isoS(m.startedAt) : undefined
      const partial = !!since || m.restarts.some(r => r > now - 86400_000 && r - 180_000 < now) || m.scenario === 'degraded'
      return json({
        generated_at: isoS(now), website: websiteSummary(st, s, now), traffic_24h: traffic24,
        ...(traffic24 && partial ? { traffic_24h_partial: true } : {}),
        ...(traffic24 && since ? { traffic_24h_since: since } : {}),
        incidents_24h: incidents24,
      })
    })),
    // D56: Passwortschutz. Validation as the gateway does it, field errors by pointer; the password stays here.
    http.get(`${base}/websites/:website/human-check`, guard('read', ({ params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      return json({
        website: s.id,
        policy: { mode: 'off', under_attack: { scope: 'off' }, under_attack_active: false, clearance_ttl_s: 1800, difficulty: 50000 },
        counts: { served: 0, passed: 0, nojs: 0, invalid: 0 },
      })
    })),
    http.put(`${base}/websites/:website/human-check`, guard('write', async ({ request, params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const b = await request.json() as { mode?: string, under_attack?: { scope?: string, until?: string }, except?: string[] }
      const ua = b.under_attack ?? { scope: 'off' }
      const active = ua.scope === 'admin' || ua.scope === 'all'
      return json({
        website: s.id,
        policy: {
          mode: b.mode ?? 'off',
          under_attack: ua,
          under_attack_active: active,
          ...(b.except?.length ? { except: b.except } : {}),
          clearance_ttl_s: 1800,
          difficulty: 50000,
          updated_at: new Date().toISOString(),
          actor: 'dashboard',
        },
        counts: { served: 0, passed: 0, nojs: 0, invalid: 0 },
      })
    })),
    http.get(`${base}/websites/:website/access`, guard('read', ({ params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      return json(accessStateOf(t.state(), s.id))
    })),
    http.put(`${base}/websites/:website/maintenance`, guard('write', async ({ request, params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const b = await request.json() as { on: boolean, message?: string }
      if ((b.message ?? '').length > 500) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/message', detail: 'too long' }])
      const st = t.state()
      if (b.on) st.maintenance[s.id] = { message: b.message ?? '', updated_at: isoS(t.now()) }
      else delete st.maintenance[s.id]
      return json(accessStateOf(st, s.id))
    })),
    http.put(`${base}/websites/:website/access`, guard('write', async ({ request, params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const b = await request.json() as AccessProtectionInput
      const st = t.state()
      const old = st.access[s.id]
      const password = b.password ? true : b.remove_password ? false : !!old?.password
      const now = t.now()
      const bad = (pointer: string, detail: string) => problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer, detail }])
      if (b.scope === 'paths' && !b.paths?.length) return bad('/paths', 'at least one path')
      if (b.password !== undefined && (b.password.length < 8 || b.password.length > 128)) return bad('/password', '8 to 128 characters')
      if (!password && !b.addresses?.length && !b.own_networks) return bad('/password', 'a password, an address or own networks')
      const p: AccessProtection = {
        scope: b.scope,
        ...(b.scope === 'paths' ? { paths: b.paths } : {}),
        ...(b.scope === 'site' && b.except?.length ? { except: b.except } : {}),
        password,
        ...(b.addresses?.length ? { addresses: b.addresses } : {}),
        own_networks: b.own_networks,
        message: b.message ?? '',
        updated_at: isoS(now),
        actor: 'dashboard',
      }
      st.access[s.id] = p
      return json(accessStateOf(st, s.id))
    })),
    http.delete(`${base}/websites/:website/access`, guard('write', ({ params }) => {
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      delete t.state().access[s.id]
      return new HttpResponse(null, { status: 204 })
    })),
    http.get(`${base}/websites/:website/kpis`, guard('read', ({ request, params }) => {
      const e = err() ?? monOff()
      if (e) return e
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const q = new URL(request.url).searchParams
      const { from, to, now } = range(q)
      if (!(from < to)) return problem(400, 'invalid', 'Ungültiger Zeitraum', [{ pointer: '#/query/from', detail: 'from must be before to' }])
      const filters = q.getAll('filter')
      if (needsRequestRing(filters) && (!t.state().monitoring.requestRing || now - from > REQUEST_RING_MS + 600_000)) return problem(409, 'filter_unavailable', 'Kombinierte Filter brauchen die einzelnen Anfragen')
      const len = to - from
      const m = t.state().monitoring
      return json({
        site: s.id,
        from: isoS(from),
        to: isoS(to),
        previous_from: isoS(from - len),
        previous_to: isoS(from),
        ...(filters.length ? { filters } : {}),
        source: needsRequestRing(filters) ? 'requests' : 'rings',
        current: kpiSet(m, from, to, s.id, filters, now),
        previous: kpiSet(m, from - len, from, s.id, filters, now),
      })
    })),
    http.get(`${base}/websites/:website/realtime`, guard('read', ({ params }) => {
      const e = err() ?? monOff()
      if (e) return e
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const m = t.state().monitoring
      const now = t.now()
      const minute = Math.floor(now / 60_000) * 60_000
      const points = Array.from({ length: 31 }, (_, i) => {
        const a = minute - (30 - i) * 60_000
        let req = 0
        let stop = 0
        let would = 0
        const end = Math.min(a + 60_000, now)
        for (let x = a; x < end; x += 10_000) {
          const c = countersAt(m, x / 1000 + 5, s.id)
          const span = Math.min(10, (end - x) / 1000)
          req += c.requests * span
          stop += c.stopped * span
          would += c.would_block * span
        }
        return { t: isoS(a), requests: Math.round(req), stopped: Math.round(stop), would_block: Math.round(would), visitors: Math.round(req / 7), partial: a + 60_000 > now }
      })
      const last5 = points.slice(-6, -1)
      const sum = (k: 'requests' | 'stopped' | 'would_block') => last5.reduce((a, p) => a + p[k], 0)
      return json({ site: s.id, generated_at: isoS(now), visitors_5m: Math.round(sum('requests') / 11), requests_5m: sum('requests'), stopped_5m: sum('stopped'), would_block_5m: sum('would_block'), points })
    })),
    http.get(`${base}/websites/:website/annotations`, guard('read', ({ request, params }) => {
      const e = err()
      if (e) return e
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const { from, to } = range(new URL(request.url).searchParams)
      const items = annotations(t.state(), s.id, from, to)
      return json({ site: s.id, from: isoS(from), to: isoS(to), items: items.slice(-200), truncated: items.length > 200 })
    })),
    http.get(`${base}/websites/:website/alerts`, guard('read', ({ request, params }) => {
      const e = err()
      if (e) return e
      const s = findSite(params.website)
      if (!s) return problem(404, 'not_found', 'Website nicht gefunden')
      const q = new URL(request.url).searchParams
      const { from, to } = range(q)
      const filters = q.getAll('filter')
      if (filters.length > 1) return problem(400, 'invalid', 'Nur ein Filter', [{ pointer: '#/query/filter', detail: 'at most one filter' }])
      const f = filters[0]
      if (f && !/^(path|country|net_class|asn|rule|bot_category):/.test(f)) return problem(400, 'invalid', 'Filter nicht möglich', [{ pointer: '#/query/filter', detail: 'path, country, net_class, asn, rule or bot_category' }])
      const limit = Math.min(50, Math.max(1, Number(q.get('limit') ?? 50) || 50))
      return json({ site: s.id, ...(f ? { filters: [f] } : {}), items: alerts(t.state(), s.id, from, to, f, limit) })
    })),
    http.get(`${base}/incidents`, guard('read', ({ request }) => {
      const e = err()
      if (e) return e
      const q = new URL(request.url).searchParams
      const { from, to } = range(q, 7 * 86400_000)
      const site = q.get('site')
      if (site && !findSite(site)) return problem(400, 'invalid', 'Unbekannte Website', [{ pointer: '#/query/site', detail: 'unknown site' }])
      const status = q.get('status')
      const items = [...t.state().incidents.values()]
        .filter((i: Incident) => (!site || i.site === site) && (!status || i.status === status))
        .filter(i => Date.parse(i.time) >= from && Date.parse(i.time) < to)
        .sort((a, b) => Date.parse(b.time) - Date.parse(a.time))
      const limit = Math.min(500, Math.max(1, Number(q.get('limit') ?? 50) || 50))
      return json({ items: items.slice(0, limit), next_cursor: null })
    })),
    http.get(`${base}/requests/alerts/hints`, guard('read', ({ request }) => {
      const e = err()
      if (e) return e
      if (!t.state().monitoring.requestRing) return problem(409, 'requests_off', 'Der Anfrage-Speicher ist aus')
      const q = new URL(request.url).searchParams
      const { from, to, now } = range(q, REQUEST_RING_MS)
      const site = q.get('site') ?? undefined
      if (site && !findSite(site)) return problem(400, 'invalid', 'Unbekannte Website', [{ pointer: '#/query/site', detail: 'unknown site' }])
      return json({ from: isoS(from), to: isoS(to), items: fpHints(t.state(), site, now) })
    })),
  ]
}
