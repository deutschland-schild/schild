/**
 * Mock backend of "Verhalten & Limits" (contracts v0.4, MVP-17): behaviour hits, per-scenario modes,
 * rate limit CRUD with a Probelauf and the release of a client. Seeded from the contract fixtures,
 * shifted so the running block of the fixture still runs. Documentation addresses only. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { Scenario } from './data'
import type { DistributedMock } from './distributed'
import type { BehaviourHit, BehaviourHitDetail, BehaviourMode, BehaviourSettings, RateLimit, RateLimitDryRun, ScenarioId } from '@/api/behaviour'
import type { AllowlistEntry, EventSummary } from '@/api/types'
import { http, HttpResponse } from 'msw'
import { THRESHOLD_BOUNDS } from '@/lib/behaviour'
import hitDetailFixture from '../../../../../contracts/api/fixtures/client/getBehaviourHit.json'
import settingsFixture from '../../../../../contracts/api/fixtures/client/getBehaviourSettings.json'
import dryRunFixture from '../../../../../contracts/api/fixtures/client/dryRunRateLimit.json'
import hitsFixture from '../../../../../contracts/api/fixtures/client/listBehaviourHits.json'
import limitsFixture from '../../../../../contracts/api/fixtures/client/listRateLimits.json'
import { createDistributedState, distributedHandlers } from './distributed'

/** The behaviour fixtures are written around this instant (the running block ends at 09:29:02). */
const FIXTURE_NOW = Date.parse('2026-10-28T09:20:00Z')
const SCENARIO_IDS: ScenarioId[] = ['login_bruteforce', 'credential_stuffing', 'path_probing', 'aggressive_crawl', 'waf_repeat']
const MODES: BehaviourMode[] = ['off', 'observe', 'block']
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

export interface BehaviourMock {
  hits: BehaviourHit[]
  /** Recent requests per hit id (the fixture's for the first hit, generated for the others). */
  requests: Map<string, EventSummary[]>
  settings: BehaviourSettings
  limits: RateLimit[]
  /** Narrow exceptions from "Ausnahme nur für dieses Szenario/Limit": ip -> sources with expiry. */
  exceptions: { ip: string, sources: string[], until: number }[]
  seq: number
  /** MVP-18: distributed attacks (mock/distributed.ts). */
  distributed: DistributedMock
}

function iso(ms: number) {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z')
}

function shiftTimes<T>(value: T, delta: number): T {
  return JSON.parse(JSON.stringify(value), (_k, v) => {
    if (typeof v === 'string' && /^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(v)) return iso(Date.parse(v) + delta)
    return v
  }) as T
}

export function createBehaviourState(scenario: Scenario, t0: number): BehaviourMock {
  const delta = t0 - FIXTURE_NOW
  const distributed = createDistributedState(scenario, v => shiftTimes(v, delta), t0)
  const settings = shiftTimes(settingsFixture as BehaviourSettings, delta)
  // D29 amendment: the gateway sends the hosting ladder; the contract fixture predates it.
  settings.hosting_block_steps_s ??= [900, 3600, 86400, 604800]
  settings.hosting_block_cap_s ??= 604800
  const limits = shiftTimes(limitsFixture.items as RateLimit[], delta)
  if (scenario === 'empty') {
    // Fresh install: presets only, every scenario on its recommended mode (D92), nothing counted yet.
    for (const s of settings.scenarios) Object.assign(s, { mode: s.recommended, effective_mode: s.recommended, hits_24h: 0, would_block_24h: 0, blocks_active: 0 })
    return { hits: [], requests: new Map(), settings, limits: limits.filter(l => l.source === 'preset').map(l => ({ ...l, matched_24h: 0, exceeded_24h: 0, clients_24h: 0 })), exceptions: [], seq: 1, distributed }
  }
  const hits = shiftTimes(hitsFixture.items as BehaviourHit[], delta)
  const detail = shiftTimes(hitDetailFixture as BehaviourHitDetail, delta)
  const requests = new Map<string, EventSummary[]>()
  requests.set(detail.hit.id, detail.requests)
  for (const h of hits) if (!requests.has(h.id)) requests.set(h.id, sampleRequests(h))
  return { hits, requests, settings, limits, exceptions: [], seq: 1, distributed }
}

/** A few stored requests around a hit, so the detail panel has something to show. */
function sampleRequests(h: BehaviourHit): EventSummary[] {
  if (!h.ip) return []
  const t = Date.parse(h.time)
  const probe = ['/.env', '/.git/config', '/wp-config.php.bak', '/phpmyadmin/']
  return Array.from({ length: 4 }, (_, i) => {
    const path = h.scenario === 'path_probing' ? probe[i]! : (h.route ?? '/')
    const status = h.scenario === 'path_probing' ? 404 : h.scenario === 'waf_repeat' ? 403 : 200
    return {
      id: `${h.id.slice(0, 30)}${String(i).padStart(6, '0')}`,
      time: iso(t - i * 4000),
      type: 'schild.request.evaluated.v1',
      outcome: status === 403 ? 'blocked' : 'passed',
      ip: h.ip!,
      ...(h.geo ? { geo: h.geo } : {}),
      method: h.kind === 'rate_limit' || h.scenario === 'login_bruteforce' ? 'POST' : 'GET',
      host: h.host ?? 'verein.example',
      path,
      status,
      score: 0,
      rules: [],
    } as EventSummary
  })
}

type Params = Record<string, string | readonly string[] | undefined>
type Fn = (args: { request: Request, params: Params }) => Promise<Response> | Response

export interface BehaviourHandlerTools {
  base: string
  behaviour: () => BehaviourMock
  allowlist: () => AllowlistEntry[]
  scenario: () => Scenario
  now: () => number
  hex: (n: number) => string
  guard: (kind: 'read' | 'write', fn: Fn) => (args: { request: Request, params: Params }) => Promise<Response>
  problem: (status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) => Response
  page: <T>(items: T[], url: URL, defLimit?: number) => { items: T[], next_cursor: string | null }
  read: (req: Request) => Promise<Record<string, unknown>>
}

export function behaviourHandlers(t: BehaviourHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const unavailable = () => t.scenario() === 'error' ? problem(503, 'internal', 'Interner Fehler') : null
  /** Blocks end by themselves. */
  const state = () => {
    const b = t.behaviour()
    const now = t.now()
    for (const h of b.hits) if (h.active && h.until && Date.parse(h.until) <= now) h.active = false
    for (const s of b.settings.scenarios) s.blocks_active = b.hits.filter(h => h.active && h.scenario === s.id).length
    return b
  }

  function validateLimit(body: Record<string, unknown>, draft: boolean) {
    const errors: { pointer: string, detail: string }[] = []
    const route = typeof body.route === 'string' ? body.route.trim() : ''
    if (!route || route.length > 256 || !route.startsWith('/')) errors.push({ pointer: '/route', detail: 'path starting with /' })
    if (!Number.isInteger(body.limit) || (body.limit as number) < 1 || (body.limit as number) > 100000) errors.push({ pointer: '/limit', detail: 'between 1 and 100000' })
    if (typeof body.per !== 'string' || !/^(([1-9]|[1-5]\d)[sm]|([1-9]|1\d|2[0-4])h)$/.test(body.per)) errors.push({ pointer: '/per', detail: 'e.g. 1m, 10m, 1h' })
    if (body.burst !== undefined && (!Number.isInteger(body.burst) || (body.burst as number) < 1 || (body.burst as number) > 100000)) errors.push({ pointer: '/burst', detail: 'between 1 and 100000' })
    if (body.methods !== undefined && (!Array.isArray(body.methods) || body.methods.some(m => !METHODS.includes(String(m))))) errors.push({ pointer: '/methods', detail: 'HTTP methods' })
    if (!draft) {
      if (body.mode !== undefined && !['off', 'observe', 'block'].includes(String(body.mode))) errors.push({ pointer: '/mode', detail: 'off, observe or block' })
      if (body.label !== undefined && (typeof body.label !== 'string' || !body.label.trim() || body.label.length > 64)) errors.push({ pointer: '/label', detail: '1 to 64 characters' })
      if (/^[/*]+$/.test(route) && body.confirm_site_wide !== true) errors.push({ pointer: '/confirm_site_wide', detail: 'required for a limit on the whole site' })
    }
    return errors
  }

  function toLimit(id: string, body: Record<string, unknown>, prev?: RateLimit): RateLimit {
    const route = String(body.route).trim()
    const limit = body.limit as number
    return {
      id,
      ...(typeof body.label === 'string' && body.label.trim() ? { label: body.label.trim() } : {}),
      route,
      ...(Array.isArray(body.methods) && body.methods.length ? { methods: body.methods as string[] } : {}),
      limit,
      per: String(body.per),
      burst: (body.burst as number | undefined) ?? limit,
      mode: (body.mode as RateLimit['mode'] | undefined) ?? 'observe',
      ...(typeof body.site === 'string' && body.site ? { site: body.site } : {}),
      ...(body.confirm_site_wide === true ? { confirm_site_wide: true } : {}),
      source: 'dashboard',
      matched_24h: prev?.matched_24h ?? 0,
      exceeded_24h: prev?.exceeded_24h ?? 0,
      clients_24h: prev?.clients_24h ?? 0,
    }
  }

  return [
    http.get(`${base}/behaviour/hits`, guard('read', ({ request }) => {
      const err = unavailable()
      if (err) return err
      const url = new URL(request.url)
      const q = url.searchParams
      const from = q.get('from') ? Date.parse(q.get('from')!) : null
      const to = q.get('to') ? Date.parse(q.get('to')!) : null
      const kind = q.get('kind')
      if (kind && kind !== 'scenario' && kind !== 'rate_limit') return problem(400, 'invalid', 'Ungültiger Filter', [{ pointer: '#/query/kind', detail: 'scenario or rate_limit' }])
      const items = state().hits.filter((h) => {
        const time = Date.parse(h.time)
        if (from !== null && time < from) return false
        if (to !== null && time > to) return false
        if (kind && h.kind !== kind) return false
        if (q.get('scenario') && h.scenario !== q.get('scenario')) return false
        if (q.get('ip') && h.ip !== q.get('ip')) return false
        if (q.get('active') === 'true' && !h.active) return false
        if (q.get('active') === 'false' && h.active) return false
        return true
      })
      return json(t.page(items, url))
    })),
    http.get(`${base}/behaviour/hits/:id`, guard('read', ({ params }) => {
      const b = state()
      const hit = b.hits.find(h => h.id === params.id)
      if (!hit) return problem(404, 'not_found', 'Treffer nicht gefunden')
      const blocks = b.hits
        .filter(h => h.active && h.ip && h.ip === hit.ip && h.until)
        .map(h => ({ source: h.kind === 'rate_limit' ? `ratelimit:${h.limit_id}` : `behaviour:${h.scenario}`, until: h.until!, level: h.level ?? 1, ...(h.incident ? { incident: h.incident } : {}) }))
      const allowlisted = !!hit.ip && t.allowlist().some(a => a.ip === hit.ip && !a.expired)
      return json({ hit, requests: b.requests.get(hit.id) ?? [], blocks, allowlisted } satisfies BehaviourHitDetail)
    })),

    http.get(`${base}/behaviour/settings`, guard('read', () => unavailable() ?? json(state().settings))),
    http.patch(`${base}/behaviour/settings`, guard('write', async ({ request }) => {
      const body = await t.read(request)
      const errors: { pointer: string, detail: string }[] = []
      const scenarios = (body.scenarios ?? {}) as Record<string, unknown>
      for (const [id, mode] of Object.entries(scenarios)) {
        if (!SCENARIO_IDS.includes(id as ScenarioId)) errors.push({ pointer: `/scenarios/${id}`, detail: 'unknown scenario' })
        else if (!MODES.includes(mode as BehaviourMode)) errors.push({ pointer: `/scenarios/${id}`, detail: 'off, observe or block' })
      }
      const limitModes = (body.preset_limit_modes ?? {}) as Record<string, unknown>
      for (const [id, mode] of Object.entries(limitModes)) {
        if (!state().limits.some(l => l.id === id && l.source === 'preset')) errors.push({ pointer: `/preset_limit_modes/${id}`, detail: 'no preset limit' })
        else if (!MODES.includes(mode as BehaviourMode)) errors.push({ pointer: `/preset_limit_modes/${id}`, detail: 'off, observe or block' })
      }
      const thresholds = (body.thresholds ?? {}) as Record<string, Record<string, number>>
      for (const [id, t] of Object.entries(thresholds)) {
        const bounds = THRESHOLD_BOUNDS[id as ScenarioId]
        if (!bounds) errors.push({ pointer: `/thresholds/${id}`, detail: 'unknown scenario' })
        else if (t.count !== undefined && (t.count < bounds.minCount || t.count > 100000)) errors.push({ pointer: `/thresholds/${id}/count`, detail: `${bounds.minCount} bis 100000` })
        else if (t.window_s !== undefined && (t.window_s < bounds.minWindowS || t.window_s > bounds.maxWindowS)) errors.push({ pointer: `/thresholds/${id}/window_s`, detail: `${bounds.minWindowS} bis ${bounds.maxWindowS} Sekunden` })
      }
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const b = state()
      // D93: an entry replaces the thresholds, what it leaves out is the built-in value again.
      for (const s of b.settings.scenarios) if (thresholds[s.id]) s.thresholds = { ...s.defaults, ...thresholds[s.id] }
      for (const s of b.settings.scenarios) {
        const mode = scenarios[s.id] as BehaviourMode | undefined
        if (!mode) continue
        s.mode = mode
        s.effective_mode = mode
      }
      for (const l of b.limits) if (limitModes[l.id]) l.mode = limitModes[l.id] as RateLimit['mode']
      return json(b.settings)
    })),

    http.get(`${base}/behaviour/rate-limits`, guard('read', ({ request }) => unavailable() ?? json(t.page(state().limits, new URL(request.url), 100)))),
    http.post(`${base}/behaviour/rate-limits/dry-run`, guard('write', async ({ request }) => {
      const body = await t.read(request)
      const errors = validateLimit(body, true)
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      // Deterministic, plausible numbers: the stricter the limit, the more it would have caught.
      const d = dryRunFixture as RateLimitDryRun
      const factor = 10 / Math.max(1, body.limit as number)
      const wouldLimit = Math.round(d.would_limit * factor)
      return json({ ...d, would_limit: wouldLimit, clients: wouldLimit ? Math.max(1, Math.round(d.clients * Math.min(factor, 3))) : 0 } satisfies RateLimitDryRun)
    })),
    http.post(`${base}/behaviour/rate-limits`, guard('write', async ({ request }) => {
      const body = await t.read(request)
      const errors = validateLimit(body, false)
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const b = state()
      const id = `limit-${t.hex(6)}`
      const limit = toLimit(id, body)
      b.limits.push(limit)
      return json(limit, 201)
    })),
    http.patch(`${base}/behaviour/rate-limits/:limit_id`, guard('write', async ({ request, params }) => {
      const body = await t.read(request)
      const b = state()
      const idx = b.limits.findIndex(l => l.id === params.limit_id)
      if (idx < 0) return problem(404, 'not_found', 'Limit nicht gefunden')
      if (b.limits[idx]!.source !== 'dashboard') return problem(409, 'config_limit', 'Dieses Limit steht in schild.yaml oder einer Voreinstellung')
      const errors = validateLimit(body, false)
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      b.limits[idx] = toLimit(b.limits[idx]!.id, body, b.limits[idx])
      return json(b.limits[idx]!)
    })),
    http.delete(`${base}/behaviour/rate-limits/:limit_id`, guard('write', async ({ params }) => {
      const b = state()
      const idx = b.limits.findIndex(l => l.id === params.limit_id)
      if (idx < 0) return problem(404, 'not_found', 'Limit nicht gefunden')
      if (b.limits[idx]!.source !== 'dashboard') return problem(409, 'config_limit', 'Dieses Limit steht in schild.yaml oder einer Voreinstellung')
      b.limits.splice(idx, 1)
      return new HttpResponse(null, { status: 204 })
    })),

    http.post(`${base}/behaviour/release`, guard('write', async ({ request }) => {
      const body = await t.read(request)
      const ip = typeof body.ip === 'string' ? body.ip.trim() : ''
      const allow = (body.allow as string | undefined) ?? 'none'
      const ttl = (body.ttl as string | undefined) ?? '7d'
      const errors: { pointer: string, detail: string }[] = []
      if (!ip || ip.length > 64) errors.push({ pointer: '/ip', detail: 'required' })
      if (!['none', 'exception', 'permanent'].includes(allow)) errors.push({ pointer: '/allow', detail: 'none, exception or permanent' })
      if (!['24h', '7d', '30d'].includes(ttl)) errors.push({ pointer: '/ttl', detail: '24h, 7d or 30d' })
      if (allow === 'exception' && !body.scenario && !body.limit_id) errors.push({ pointer: '/scenario', detail: 'scenario or limit_id required for an exception' })
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const b = state()
      const now = t.now()
      let ended = 0
      for (const h of b.hits) {
        if (h.ip !== ip) continue
        if (h.active) ended++
        h.active = false
        h.released = true
      }
      let exceptionUntil: string | null = null
      let sources: string[] = []
      if (allow === 'exception') {
        const ms = ttl === '24h' ? 24 * 3600_000 : ttl === '30d' ? 30 * 24 * 3600_000 : 7 * 24 * 3600_000
        sources = [body.scenario ? `behaviour:${String(body.scenario)}` : `ratelimit:${String(body.limit_id)}`]
        b.exceptions.push({ ip, sources, until: now + ms })
        exceptionUntil = iso(now + ms)
      }
      let entryId: string | null = null
      if (allow === 'permanent') {
        const existing = t.allowlist().find(a => a.ip === ip && !a.expired)
        if (existing) {
          entryId = existing.id
        }
        else {
          const label = typeof body.label === 'string' && body.label.trim() ? body.label.trim() : 'Freigegeben bei Sperren'
          const entry: AllowlistEntry = { id: `al-${t.hex(6)}`, ip, label, level: 'no_block', expires: 'never', expired: false, created_at: iso(now), source: 'dashboard' }
          t.allowlist().unshift(entry)
          entryId = entry.id
        }
      }
      state()
      return json({ ip, blocks_ended: ended, exception_until: exceptionUntil, exception_sources: sources, allowlist_entry: entryId })
    })),

    // MVP-18: distributed attacks.
    ...distributedHandlers({ base, distributed: () => t.behaviour().distributed, scenario: t.scenario, now: t.now, iso, guard, problem, page: t.page, read: t.read }),
  ]
}
