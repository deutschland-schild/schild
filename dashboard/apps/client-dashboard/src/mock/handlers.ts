/**
 * MSW handlers for every operation of contracts/api/client-dashboard.openapi.yaml, backed by the
 * in-memory MockState (mock mode and tests only). Enforces the API conventions the real server has:
 * session check (401), X-CSRF-Token on state changes (403 csrf), RFC 9457 problems with stable codes,
 * cursor pagination and an SSE stream with Last-Event-ID replay.
 */
import type { HttpHandler } from 'msw'
import type { MockState } from './data'
import type { RunningBlock } from '@/api/blocks'
import type {
  AllowlistEntry,
  AllowlistInput,
  EventSummary,
  Incident,
  LocalEvent,
  Settings,
  SettingsPatch,
  Ttl,
  UnblockRequest,
} from '@/api/types'
import { delay, http, HttpResponse } from 'msw'
import { finalize, generateRequest, iso } from './data'
import { agentApiHandlers } from './agentapi'
import { behaviourHandlers } from './behaviour'
import { crawlerHandlers } from './crawlers'
import { hostHandlers } from './hosts'
import { monitoringHandlers } from './monitoring'
import { requestHandlers } from './requests'
import { ruleHandlers } from './rules'
import { websiteHandlers } from './websites'

export interface HandlerOptions {
  prefix?: string
  /** Artificial latency so skeletons are visible (ms). */
  latency?: number
  /** Interval of new live events on the SSE stream (ms). */
  liveIntervalMs?: number
  /** Interval of monitoring ticks on /monitoring/stream (ms). */
  monitoringTickMs?: number
}

type Json = Record<string, unknown> | unknown[]

function problem(status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) {
  return HttpResponse.json(
    { type: `https://schild.invalid/problems/${code}`, title, detail: title, status, code, ...(errors ? { errors } : {}) },
    { status, headers: { 'Content-Type': 'application/problem+json' } },
  )
}

const encodeCursor = (n: number) => btoa(JSON.stringify({ o: n })).replace(/=+$/, '')
function decodeCursor(c: string | null): number {
  if (!c) return 0
  try {
    return Number(JSON.parse(atob(c)).o) || 0
  }
  catch {
    return 0
  }
}

function page<T>(items: T[], url: URL, defLimit = 50) {
  const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit') ?? defLimit) || defLimit))
  const offset = decodeCursor(url.searchParams.get('cursor'))
  const slice = items.slice(offset, offset + limit)
  return { items: slice, next_cursor: offset + limit < items.length ? encodeCursor(offset + limit) : null }
}

function ttlToExpires(ttl: Ttl | undefined, now: number): string {
  switch (ttl) {
    case '24h': return iso(now + 24 * 3600_000)
    case '7d': return iso(now + 7 * 24 * 3600_000)
    case '30d': return iso(now + 30 * 24 * 3600_000)
    default: return 'never'
  }
}

// ------------------------------------------------------------------ IP matching (exact or CIDR)

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  if (!m) return null
  const parts = m.slice(1).map(Number)
  if (parts.some(p => p > 255)) return null
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!
}

function expandIpv6(ip: string): string | null {
  if (!ip.includes(':')) return null
  const [head, tail] = ip.split('::')
  const h = head ? head.split(':') : []
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : []
  if (tail === undefined && h.length !== 8) return null
  const fill = Array.from({ length: 8 - h.length - t.length }, () => '0')
  return [...h, ...fill, ...t].map(x => x.padStart(4, '0')).join('')
}

export function ipMatches(ip: string | undefined, filter: string): boolean {
  if (!ip) return false
  if (!filter.includes('/')) return ip === filter
  const [net, bitsStr] = filter.split('/')
  const bits = Number(bitsStr)
  const a = ipv4ToInt(ip)
  const b = ipv4ToInt(net!)
  if (a !== null && b !== null) {
    if (bits === 0) return true
    const mask = bits >= 32 ? 0xFFFFFFFF : (~((1 << (32 - bits)) - 1)) >>> 0
    return ((a & mask) >>> 0) === ((b & mask) >>> 0)
  }
  const x = expandIpv6(ip)
  const y = expandIpv6(net!)
  if (!x || !y) return false
  const bin = (h: string) => h.split('').map(c => Number.parseInt(c, 16).toString(2).padStart(4, '0')).join('')
  return bin(x).slice(0, bits) === bin(y).slice(0, bits)
}

// ------------------------------------------------------------------ event filters

const BREAKDOWN_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT', 'TRACE'])

/** A rough UAClass of a stored user agent (the gateway uses the monitoring classifier). */
export function mockUaClass(ua: string | undefined): string {
  if (!ua) return 'none'
  if (/bot|crawler|spider|crawl/i.test(ua)) return 'bot_unverified'
  if (/^(curl|wget|python|go-http|libwww|okhttp|java)/i.test(ua)) return 'tool'
  if (/^Mozilla\//.test(ua)) return 'browser'
  return 'other'
}

export function filterEvents(st: MockState, q: URLSearchParams): EventSummary[] {
  const from = q.get('from') ? Date.parse(q.get('from')!) : null
  const to = q.get('to') ? Date.parse(q.get('to')!) : null
  const type = q.get('type')
  const ip = q.get('ip')
  const country = q.get('country')
  const asn = q.get('asn')
  const path = q.get('path')
  const rule = q.get('rule')
  const outcome = q.get('outcome')
  const session = q.get('session')
  const site = q.get('site')
  const text = q.get('q')?.toLowerCase()
  // D36 amendment: the filters a breakdown row links to.
  const netClass = q.get('net_class')
  const method = q.get('method')
  const uaClass = q.get('ua_class')
  return st.events.map(e => e.summary).filter((e) => {
    const t = Date.parse(e.time)
    if (from !== null && t < from) return false
    if (to !== null && t > to) return false
    if (type && e.type !== type) return false
    if (ip && !ipMatches(e.ip, ip)) return false
    if (country && e.geo?.country !== country) return false
    if (asn && String(e.geo?.asn) !== asn) return false
    if (path && !(e.path ?? '').startsWith(path)) return false
    if (rule && !(e.rules ?? []).includes(rule)) return false
    if (outcome && e.outcome !== outcome) return false
    if (session && e.session_id !== session) return false
    if (site && e.site !== site) return false
    if (netClass && e.geo?.net_class !== netClass) return false
    if (method === 'OTHER' && (!e.method || BREAKDOWN_METHODS.has(e.method))) return false
    if (method && method !== 'OTHER' && e.method !== method) return false
    if (uaClass && (!e.method || mockUaClass(st.events.find(x => x.summary.id === e.id)?.detail.data.user_agent) !== uaClass)) return false
    if (text) {
      const detail = st.events.find(x => x.summary.id === e.id)?.detail
      const hay = [e.path, e.incident, e.ip, e.host, detail?.data.user_agent, e.summary].filter(Boolean).join(' ').toLowerCase()
      if (!hay.includes(text)) return false
    }
    return true
  })
}

const VALID_IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i

// ------------------------------------------------------------------ handlers

export function createHandlers(st: MockState, opts: HandlerOptions = {}): HttpHandler[] {
  const base = `*${opts.prefix ?? '/api/v0'}`
  const latency = opts.latency ?? 0
  const liveMs = opts.liveIntervalMs ?? 2500
  const now = () => st.now()

  const authed = () => st.session.authenticated
  const csrfOk = (req: Request) => req.headers.get('X-CSRF-Token') === st.session.csrf_token && !!st.session.csrf_token

  /** Wrap a handler with latency, auth and (for writes) CSRF checks. */
  function guard(kind: 'read' | 'write', fn: (args: { request: Request, params: Record<string, string | readonly string[] | undefined> }) => Promise<Response> | Response) {
    return async ({ request, params }: { request: Request, params: Record<string, string | readonly string[] | undefined> }) => {
      if (latency) await delay(latency)
      if (!authed()) return problem(401, 'unauthenticated', 'Nicht angemeldet')
      if (kind === 'write' && !csrfOk(request)) return problem(403, 'csrf', 'CSRF-Token fehlt oder ist ungültig')
      if (kind === 'write' && st.session.role === 'readonly') return problem(403, 'forbidden', 'Nur Lesezugriff')
      return fn({ request, params })
    }
  }
  const json = (body: Json | object, status = 200) => HttpResponse.json(body as Json, { status })
  const read = async (req: Request) => {
    try {
      return await req.json() as Record<string, unknown>
    }
    catch {
      return {}
    }
  }

  return [
    // ---------------------------------------------------------------- auth
    http.get(`${base}/auth/session`, async () => {
      if (latency) await delay(latency)
      return json(st.session)
    }),
    http.post(`${base}/auth/setup`, async ({ request }) => {
      if (latency) await delay(latency)
      if (!st.session.first_run) return problem(409, 'conflict', 'Es gibt schon ein Passwort')
      const body = await read(request)
      const pw = body.password
      if (typeof pw !== 'string' || pw.length < 12) {
        return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/password', detail: 'at least 12 characters' }])
      }
      if (body.setup_code !== 'K7QM4XWD') {
        return problem(403, 'forbidden', 'Der Einrichtungscode stimmt nicht.', [{ pointer: '/setup_code', detail: 'wrong setup code' }])
      }
      st.password = pw
      st.session = { authenticated: true, first_run: false, user: 'admin', role: 'admin', csrf_token: 'mock-csrf-token-after-setup-1', expires_at: iso(now() + 12 * 3600_000), via: 'password' }
      return json(st.session)
    }),
    http.post(`${base}/auth/login`, async ({ request }) => {
      if (latency) await delay(latency)
      if (st.failedLogins >= 5) return problem(429, 'rate_limited', 'Zu viele Versuche')
      const body = await read(request)
      if (typeof body.password !== 'string' || body.password !== st.password) {
        st.failedLogins++
        return problem(401, 'unauthenticated', 'Passwort falsch')
      }
      st.failedLogins = 0
      st.session = { authenticated: true, first_run: false, user: 'admin', role: 'admin', csrf_token: 'mock-csrf-token-after-login-1', expires_at: iso(now() + 12 * 3600_000), via: 'password' }
      return json(st.session)
    }),
    http.post(`${base}/auth/logout`, guard('write', () => {
      st.session = { authenticated: false, first_run: false }
      return new HttpResponse(null, { status: 204 })
    })),
    http.post(`${base}/auth/password`, guard('write', async ({ request }) => {
      const body = await read(request)
      if (body.current_password !== st.password) return problem(401, 'unauthenticated', 'Passwort falsch', [{ pointer: '/current_password', detail: 'wrong password' }])
      if (typeof body.new_password !== 'string' || body.new_password.length < 12) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/new_password', detail: 'at least 12 characters' }])
      st.password = body.new_password
      return new HttpResponse(null, { status: 204 })
    })),

    // ---------------------------------------------------------------- overview
    http.get(`${base}/overview`, guard('read', () => {
      if (st.scenario === 'error') return problem(503, 'internal', 'Interner Fehler')
      finalize(st)
      return json(st.overview)
    })),

    // ---------------------------------------------------------------- events
    http.get(`${base}/events/stream`, guard('read', ({ request }) => {
      const url = new URL(request.url)
      const lastId = request.headers.get('Last-Event-ID')
      const enc = new TextEncoder()
      let timer: ReturnType<typeof setInterval> | undefined
      let keepAlive: ReturnType<typeof setInterval> | undefined
      const matches = (e: EventSummary) => filterEvents({ ...st, events: st.events.filter(x => x.summary.id === e.id) }, url.searchParams).length > 0
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          const send = (e: EventSummary) => controller.enqueue(enc.encode(`id: ${e.id}\nevent: event\ndata: ${JSON.stringify(e)}\n\n`))
          controller.enqueue(enc.encode(': schild mock stream\nretry: 3000\n\n'))
          if (lastId) {
            const idx = st.events.findIndex(e => e.summary.id === lastId)
            // Replay what was missed, oldest first; an unknown id starts fresh.
            if (idx > 0) for (const e of st.events.slice(0, idx).reverse()) if (matches(e.summary)) send(e.summary)
          }
          timer = setInterval(() => {
            const ev = generateRequest(st, now(), 0.45)
            st.events.unshift(ev)
            st.liveSeq++
            if (matches(ev.summary)) send(ev.summary)
          }, liveMs)
          keepAlive = setInterval(() => controller.enqueue(enc.encode(': keep-alive\n\n')), 15_000)
          request.signal?.addEventListener('abort', () => {
            clearInterval(timer)
            clearInterval(keepAlive)
            try {
              controller.close()
            }
            catch { /* already closed */ }
          })
        },
        cancel() {
          clearInterval(timer)
          clearInterval(keepAlive)
        },
      })
      return new HttpResponse(stream, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' } })
    })),
    http.get(`${base}/events`, guard('read', ({ request }) => {
      const url = new URL(request.url)
      const q = url.searchParams
      if (q.get('country') && !/^[A-Z]{2}$/.test(q.get('country')!)) return problem(400, 'invalid', 'Ungültiger Filter', [{ pointer: '#/query/country', detail: 'two upper-case letters' }])
      if (q.get('asn') && !/^\d+$/.test(q.get('asn')!)) return problem(400, 'invalid', 'Ungültiger Filter', [{ pointer: '#/query/asn', detail: 'integer' }])
      const all = filterEvents(st, q)
      return json({ ...page(all, url), total_estimate: all.length })
    })),
    http.get(`${base}/events/:id`, guard('read', ({ params }) => {
      const e = st.events.find(x => x.summary.id === params.id)
      if (!e) return problem(404, 'not_found', 'Ereignis nicht gefunden')
      const t = Date.parse(e.summary.time)
      const related = st.events
        .filter(x => x.summary.id !== e.summary.id && ((e.summary.session_id && x.summary.session_id === e.summary.session_id) || (e.summary.ip && x.summary.ip === e.summary.ip)))
        .filter(x => Math.abs(Date.parse(x.summary.time) - t) <= 6 * 3600_000)
        .slice(0, 20)
        .map(x => x.summary)
      return json({ event: e.detail, related })
    })),

    // ---------------------------------------------------------------- incidents
    http.get(`${base}/incidents/:incident`, guard('read', ({ params }) => {
      const inc = st.incidents.get(String(params.incident))
      if (!inc) return problem(404, 'not_found', 'Vorfall nicht gefunden')
      return json(inc)
    })),
    http.post(`${base}/incidents/:incident/export`, guard('write', ({ params }) => {
      const inc = st.incidents.get(String(params.incident))
      if (!inc) return problem(404, 'not_found', 'Vorfall nicht gefunden')
      return json({ incident: inc, exported_at: iso(now()), events: st.events.filter(e => e.summary.incident === inc.incident).map(e => e.detail), truncated: false })
    })),
    http.post(`${base}/incidents/:incident/unblock`, guard('write', async ({ request, params }) => {
      // D87: lifting a block from Sperren ends the running scenario block of that incident too.
      for (const h of st.behaviour.hits) {
        if (h.incident === params.incident && h.active) h.active = false
      }
      const inc = st.incidents.get(String(params.incident))
      if (!inc) return problem(404, 'not_found', 'Vorfall nicht gefunden')
      if (inc.status === 'unblocked') return problem(409, 'conflict', 'Schon freigeschaltet')
      const body = await read(request) as unknown as UnblockRequest
      if (typeof body.false_positive !== 'boolean') return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/false_positive', detail: 'required' }])
      const t = now()
      let allowId: string | null = null
      if (body.allow_ip && inc.request.ip) {
        const entry: AllowlistEntry = { id: `al-${st.rand.hex(6)}`, ip: inc.request.ip, label: `Vorfall ${inc.incident}`, level: 'no_block', expires: ttlToExpires(body.allow_ttl ?? '7d', t), expired: false, created_at: iso(t), source: 'dashboard' }
        st.allowlist.unshift(entry)
        allowId = entry.id
      }
      // Contracts v0.5: a lifted block carries ended_at.
      const updated: Incident = { ...inc, status: 'unblocked', unblocked_at: iso(t), allowlist_entry: allowId, ...(inc.block && !inc.block.ended_at ? { block: { ...inc.block, ended_at: iso(t) } } : {}) }
      st.incidents.set(inc.incident, updated)
      const id = st.rand.uuid()
      const ev: LocalEvent = { id, type: 'schild.request.unblocked.v1', time: new Date(t).toISOString(), source: 'schild://web-1', data: { incident: inc.incident, request_id: `req-${inc.request.id.slice(0, 8)}`, by: 'operator', false_positive: body.false_positive, ...(allowId ? { allowlist_entry: allowId } : {}) } }
      st.events.unshift({ summary: { id, time: iso(t), type: ev.type, incident: inc.incident, ip: inc.request.ip, summary: `incident ${inc.incident} unblocked` }, detail: ev })
      return json(updated)
    })),

    // ---------------------------------------------------------------- allowlist
    http.get(`${base}/allowlist/mine`, guard('read', () => {
      st.myIp.allowlisted = st.allowlist.some(a => a.ip === st.myIp.ip && !a.expired)
      return json(st.myIp)
    })),
    http.post(`${base}/allowlist/mine`, guard('write', async ({ request }) => {
      const body = await read(request)
      const label = typeof body.label === 'string' ? body.label.trim() : ''
      if (!label || label.length > 64) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/label', detail: '1 to 64 characters' }])
      const t = now()
      const entry: AllowlistEntry = { id: `al-${st.rand.hex(6)}`, ip: st.myIp.ip, label, level: 'no_block', expires: ttlToExpires((body.ttl as Ttl) ?? '7d', t), expired: false, created_at: iso(t), source: 'dashboard' }
      st.allowlist.unshift(entry)
      st.myIp.allowlisted = true
      return json(entry, 201)
    })),
    http.get(`${base}/allowlist`, guard('read', ({ request }) => json(page(st.allowlist, new URL(request.url))))),
    http.post(`${base}/allowlist`, guard('write', async ({ request }) => {
      const body = await read(request) as unknown as AllowlistInput
      const errors: { pointer: string, detail: string }[] = []
      const targets = [body.ip, body.cidr, body.host].filter(Boolean)
      if (targets.length !== 1) errors.push({ pointer: '/ip', detail: 'exactly one of ip, cidr, host' })
      if (body.ip && !VALID_IP.test(body.ip)) errors.push({ pointer: '/ip', detail: 'not an IP address' })
      if (body.cidr && !/^[0-9a-f:.]+\/\d{1,3}$/i.test(body.cidr)) errors.push({ pointer: '/cidr', detail: 'not a CIDR range' })
      if (body.host && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(body.host)) errors.push({ pointer: '/host', detail: 'not a host name' })
      if (!body.label?.trim()) errors.push({ pointer: '/label', detail: 'required' })
      if (body.level === 'bypass_waf' && body.confirm_bypass !== true) errors.push({ pointer: '/confirm_bypass', detail: 'required for bypass_waf' })
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const t = now()
      const entry: AllowlistEntry = {
        id: `al-${st.rand.hex(6)}`, ...(body.ip ? { ip: body.ip } : {}), ...(body.cidr ? { cidr: body.cidr } : {}),
        ...(body.host ? { host: body.host, resolved: ['192.0.2.55'] } : {}),
        label: body.label.trim(), level: body.level, expires: ttlToExpires(body.ttl, t), expired: false, created_at: iso(t), source: 'dashboard',
      }
      st.allowlist.unshift(entry)
      return json(entry, 201)
    })),
    http.delete(`${base}/allowlist/:id`, guard('write', ({ params }) => {
      const idx = st.allowlist.findIndex(a => a.id === params.id)
      if (idx < 0) return problem(404, 'not_found', 'Eintrag nicht gefunden')
      st.allowlist.splice(idx, 1)
      return new HttpResponse(null, { status: 204 })
    })),

    // ---------------------------------------------------------------- settings
    http.get(`${base}/settings`, guard('read', () => json(st.settings))),
    http.patch(`${base}/settings`, guard('write', async ({ request }) => {
      const patch = await read(request) as SettingsPatch & Record<string, unknown>
      const errors: { pointer: string, detail: string }[] = []
      // D89: there is no mode to set; like the server, an unknown field is refused.
      for (const k of Object.keys(patch)) {
        if (k !== 'retention') errors.push({ pointer: `/${k}`, detail: 'unbekanntes Feld' })
      }
      const r = patch.retention
      if (r?.raw_ip_days !== undefined && (r.raw_ip_days < 1 || r.raw_ip_days > 30)) errors.push({ pointer: '/retention/raw_ip_days', detail: 'between 1 and 30' })
      if (r?.events_days !== undefined && (r.events_days < 1 || r.events_days > 90)) errors.push({ pointer: '/retention/events_days', detail: 'between 1 and 90' })
      if (r?.summaries_days !== undefined && (r.summaries_days < 1 || r.summaries_days > 730)) errors.push({ pointer: '/retention/summaries_days', detail: 'between 1 and 730' })
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const s: Settings = structuredClone(st.settings)
      if (r) Object.assign(s.retention, r)
      st.settings = s
      return json(s)
    })),

    // ---------------------------------------------------------------- privacy
    http.get(`${base}/privacy/search`, guard('read', ({ request }) => {
      const ip = new URL(request.url).searchParams.get('ip') ?? ''
      if (!VALID_IP.test(ip)) return problem(400, 'invalid', 'Ungültige IP-Adresse', [{ pointer: '#/query/ip', detail: 'not an IP address' }])
      const evs = st.events.filter(e => e.summary.ip === ip)
      const times = evs.map(e => Date.parse(e.summary.time))
      const last = times.length ? Math.max(...times) : null
      return json({
        ip,
        events: evs.length,
        sessions: new Set(evs.map(e => e.summary.session_id).filter(Boolean)).size,
        incidents: [...new Set(evs.map(e => e.summary.incident).filter(Boolean) as string[])],
        first_seen: times.length ? iso(Math.min(...times)) : null,
        last_seen: last ? iso(last) : null,
        ip_truncated_after: last ? iso(last + st.settings.retention.raw_ip_days * 24 * 3600_000) : null,
        allowlisted: st.allowlist.some(a => a.ip === ip),
      })
    })),
    http.post(`${base}/privacy/export`, guard('write', async ({ request }) => {
      const body = await read(request)
      const ip = String(body.ip ?? '')
      return json({ ip, exported_at: iso(now()), events: st.events.filter(e => e.summary.ip === ip).map(e => e.detail) })
    })),
    http.post(`${base}/privacy/delete`, guard('write', async ({ request }) => {
      const body = await read(request)
      if (body.confirm !== true) return problem(400, 'invalid', 'Ungültige Eingabe', [{ pointer: '/confirm', detail: 'must be true' }])
      const ip = String(body.ip ?? '')
      const keep = body.keep_incidents === true
      const victims = st.events.filter(e => e.summary.ip === ip && !(keep && e.summary.incident))
      const sessions = new Set(victims.map(e => e.summary.session_id).filter(Boolean)).size
      st.events = st.events.filter(e => !victims.includes(e))
      const before = st.allowlist.length
      st.allowlist = st.allowlist.filter(a => a.ip !== ip)
      if (!keep) for (const [k, inc] of st.incidents) if (inc.request.ip === ip) st.incidents.delete(k)
      return json({ ip, deleted_events: victims.length, deleted_sessions: sessions, deleted_allowlist_entries: before - st.allowlist.length })
    })),

    // ---------------------------------------------------------------- v0.3 hosts and agents (mock/hosts.ts)
    ...hostHandlers({ base, hosts: () => st.hosts, scenario: () => st.scenario, now, hex: n => st.rand.hex(n), uuid: () => st.rand.uuid(), guard, problem, page, read }),

    // ---------------------------------------------------------------- D87: the address blocks that run
    // From the scenario hits whose block runs and whose incident was not lifted; the firewall as st.firewall says.
    http.get(`${base}/blocks`, guard('read', () => {
      const t = now()
      const fw = st.firewall
      const items: RunningBlock[] = st.behaviour.hits
        .filter(h => h.kind === 'scenario' && h.active && h.ip && h.until && Date.parse(h.until) > t && st.incidents.get(h.incident ?? '')?.status !== 'unblocked')
        .map(h => ({
          client: h.ip!,
          source: 'scenario' as const,
          ...(h.scenario ? { scenario: h.scenario } : {}),
          since: h.time,
          until: h.until!,
          duration_s: h.duration_s ?? 900,
          level: h.level ?? 1,
          net_class: h.geo?.net_class ?? 'unknown',
          incident: h.incident ?? '',
          kept: (h.duration_s ?? 0) > 86400,
          firewall: fw.state === 'ok' ? (fw.banned.includes(h.ip!) ? 'banned' as const : 'pending' as const) : fw.state === 'off' ? 'off' as const : 'stale' as const,
        }))
      st.manualBlocks = st.manualBlocks.filter(b => Date.parse(b.until) > t && st.incidents.get(b.incident)?.status !== 'unblocked')
      items.unshift(...st.manualBlocks)
      return json({ generated_at: iso(t), items, total: items.length, firewall: { state: fw.state, table: 'inet schild', ...(fw.state === 'off' ? {} : { synced_at: iso(t - 20_000), banned: fw.banned.length }) } })
    })),

    // D88: an address blocked by hand: refused like the gateway refuses, else a block with an incident.
    http.post(`${base}/blocks`, guard('write', async ({ request }) => {
      const body = await read(request) as { address?: string, duration_s?: number, reason?: string, shared_ok?: boolean }
      const addr = String(body.address ?? '').trim()
      const errors: { pointer: string, detail: string }[] = []
      if (!/^[\d.]+$|^[\da-f:]+$/i.test(addr) || addr.includes('/')) errors.push({ pointer: '/address', detail: 'one IP address' })
      if (![3600, 86400, 604800].includes(Number(body.duration_s))) errors.push({ pointer: '/duration_s', detail: '1 h, 24 h or 7 days' })
      if (!String(body.reason ?? '').trim()) errors.push({ pointer: '/reason', detail: 'required' })
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      if (/^(10\.|127\.|192\.168\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(addr)) return problem(409, 'private_address', 'Das ist keine öffentliche Adresse.')
      if (st.allowlist.some(e => e.ip === addr)) return problem(409, 'own_address', 'Diese Adresse steht unter „Eigene IPs“.')
      if (addr.startsWith('198.51.100.2') && !body.shared_ok) return problem(409, 'shared_address', 'Diese Adresse teilen sich viele Menschen (Mobilfunk, CGNAT oder Tor). Eine Sperre trifft sie alle. Bestätige, wenn du sie trotzdem sperren willst.')
      if (st.manualBlocks.some(b => b.client === addr)) return problem(409, 'already_blocked', 'Diese Adresse ist schon gesperrt.')
      const t = now()
      const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
      const pick = () => Array.from({ length: 4 }, () => letters[Number.parseInt(st.rand.hex(2), 16) % letters.length]).join('')
      const incident = `${pick()}-${pick()}`
      const any = [...st.incidents.values()][0]!
      st.incidents.set(incident, { ...any, incident, status: 'blocked', time: iso(t), unblocked_at: null, allowlist_entry: null, reason: `dashboard: ${body.reason}`, request: { ...any.request, ip: addr, incident } })
      const b: RunningBlock = { client: addr, source: 'dashboard', since: iso(t), until: iso(t + Number(body.duration_s) * 1000), duration_s: Number(body.duration_s), level: 1,
        net_class: 'hosting', incident, kept: Number(body.duration_s) > 86400, firewall: st.firewall.state === 'ok' ? 'pending' : st.firewall.state === 'off' ? 'off' : 'stale' }
      st.manualBlocks.unshift(b)
      return json(b)
    })),

    // ---------------------------------------------------------------- v0.4 behaviour and rate limits (mock/behaviour.ts)
    ...behaviourHandlers({ base, behaviour: () => st.behaviour, allowlist: () => st.allowlist, scenario: () => st.scenario, now, hex: n => st.rand.hex(n), guard, problem, page, read }),

    // ---------------------------------------------------------------- v0.4 monitoring (mock/monitoring.ts, MVP-21)
    ...monitoringHandlers({ base, monitoring: () => st.monitoring, scenario: () => st.scenario, now, guard, problem, tickMs: opts.monitoringTickMs }),

    // ---------------------------------------------------------------- v0.5 websites (mock/websites.ts, D36)
    ...websiteHandlers({ base, state: () => st, now, guard, problem }),
    ...crawlerHandlers({ base, state: () => st, now, guard, problem }),
    ...ruleHandlers({ base, state: () => st, now, guard, problem }),

    // ---------------------------------------------------------------- v0.5 request ring (mock/requests.ts, MVP-22)
    ...requestHandlers({ base, state: () => st, now, guard, problem }),

    // ---------------------------------------------------------------- D103: the switch of the agent API (mock/agentapi.ts)
    ...agentApiHandlers({ base, state: () => st, now, guard, problem }),

    // Anything else under the API prefix.
    http.all(`${base}/*`, () => problem(404, 'not_found', 'Unbekannter Pfad')),
  ]
}
