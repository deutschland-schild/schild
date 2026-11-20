/**
 * Mock backend of the "Wellen" tab (contracts v0.4, MVP-18): distributed attacks, per-detector
 * switches and ending a response early. Seeded from the contract fixtures and shifted like the
 * behaviour mock, so the running wave of the fixture still runs. Mock mode and tests only.
 */
import type { HttpHandler } from 'msw'
import type { Scenario } from './data'
import type { DetectorId, DistributedMode, DistributedSettings, Wave, WaveDetail } from '@/api/distributed'
import type { EventSummary } from '@/api/types'
import { http, HttpResponse } from 'msw'
import waveFixture from '../../../../../contracts/api/fixtures/client/getWave.json'
import settingsFixture from '../../../../../contracts/api/fixtures/client/getDistributedSettings.json'
import wavesFixture from '../../../../../contracts/api/fixtures/client/listWaves.json'

const DETECTOR_IDS: DetectorId[] = ['route_wave', 'account_wave', 'shape_wave', 'fingerprint_cluster', 'inconsistency']
const MODES: DistributedMode[] = ['off', 'observe', 'respond']

export interface DistributedMock {
  waves: Wave[]
  /** Recent requests per wave id (the fixture's for the running wave, generated for the others). */
  requests: Map<string, EventSummary[]>
  settings: DistributedSettings
  /** Fresh install: every detector observes until learning_until. */
  learning: boolean
}

type Shift = <T>(value: T) => T

export function createDistributedState(scenario: Scenario, shift: Shift, t0: number): DistributedMock {
  const settings = shift(settingsFixture as DistributedSettings)
  if (scenario === 'empty') {
    for (const d of settings.detectors) Object.assign(d, { effective_mode: d.mode === 'respond' ? 'observe' : d.mode, waves_24h: 0 })
    settings.learning_until = new Date(t0 + 14 * 86400_000).toISOString().replace(/\.\d+Z$/, 'Z')
    return { waves: [], requests: new Map(), settings, learning: true }
  }
  const waves = shift(wavesFixture.items as Wave[])
  const detail = shift(waveFixture as WaveDetail)
  if (scenario === 'observe') {
    // The gateway observes: detectors only show what they would have done.
    settings.gateway_observe = true
    for (const d of settings.detectors) if (d.mode === 'respond') d.effective_mode = 'observe'
    for (const w of waves) {
      if (w.action !== 'respond') continue
      Object.assign(w, { action: 'observe', reason: 'gateway_observe', active: false, until: null, stopped: 0 })
      delete w.ended_at
      delete w.end_reason
    }
  }
  const requests = new Map<string, EventSummary[]>()
  requests.set(detail.wave.id, detail.requests)
  return { waves, requests, settings, learning: false }
}

type Params = Record<string, string | readonly string[] | undefined>
type Fn = (args: { request: Request, params: Params }) => Promise<Response> | Response

export interface DistributedHandlerTools {
  base: string
  distributed: () => DistributedMock
  scenario: () => Scenario
  now: () => number
  iso: (ms: number) => string
  guard: (kind: 'read' | 'write', fn: Fn) => (args: { request: Request, params: Params }) => Promise<Response>
  problem: (status: number, code: string, title: string, errors?: { pointer: string, detail: string }[]) => Response
  page: <T>(items: T[], url: URL, defLimit?: number) => { items: T[], next_cursor: string | null }
  read: (req: Request) => Promise<Record<string, unknown>>
}

export function distributedHandlers(t: DistributedHandlerTools): HttpHandler[] {
  const { base, guard, problem } = t
  const json = (body: object, status = 200) => HttpResponse.json(body as Record<string, unknown>, { status })
  const unavailable = () => t.scenario() === 'error' ? problem(503, 'internal', 'Interner Fehler') : null
  /** Responses end by themselves. */
  const state = () => {
    const d = t.distributed()
    const now = t.now()
    for (const w of d.waves) {
      if (w.active && w.until && Date.parse(w.until) <= now) Object.assign(w, { active: false, ended_at: w.until, end_reason: 'expired' })
    }
    return d
  }
  const effective = (d: DistributedMock, mode: DistributedMode): DistributedMode =>
    mode === 'respond' && (d.settings.gateway_observe || d.learning) ? 'observe' : mode

  return [
    http.get(`${base}/distributed/waves`, guard('read', ({ request }) => {
      const err = unavailable()
      if (err) return err
      const url = new URL(request.url)
      const q = url.searchParams
      const detector = q.get('detector')
      if (detector && !DETECTOR_IDS.includes(detector as DetectorId)) return problem(400, 'invalid', 'Ungültiger Filter', [{ pointer: '#/query/detector', detail: 'unknown detector' }])
      const from = q.get('from') ? Date.parse(q.get('from')!) : null
      const to = q.get('to') ? Date.parse(q.get('to')!) : null
      const items = state().waves.filter((w) => {
        const time = Date.parse(w.time)
        if (from !== null && time < from) return false
        if (to !== null && time > to) return false
        if (detector && w.detector !== detector) return false
        if (q.get('active') === 'true' && !w.active) return false
        if (q.get('active') === 'false' && w.active) return false
        return true
      })
      return json(t.page(items, url))
    })),
    http.get(`${base}/distributed/waves/:wave_id`, guard('read', ({ params }) => {
      const d = state()
      const wave = d.waves.find(w => w.id === params.wave_id)
      if (!wave) return problem(404, 'not_found', 'Welle nicht gefunden')
      return json({ wave, requests: d.requests.get(wave.id) ?? [] } satisfies WaveDetail)
    })),
    http.post(`${base}/distributed/waves/:wave_id/end`, guard('write', async ({ params }) => {
      const d = state()
      const wave = d.waves.find(w => w.id === params.wave_id)
      if (!wave) return problem(404, 'not_found', 'Welle nicht gefunden')
      if (!wave.active) return problem(409, 'not_active', 'Diese Reaktion läuft nicht mehr')
      Object.assign(wave, { active: false, ended_at: t.iso(t.now()), end_reason: 'operator' })
      return json(wave)
    })),
    http.get(`${base}/distributed/settings`, guard('read', () => unavailable() ?? json(state().settings))),
    http.patch(`${base}/distributed/settings`, guard('write', async ({ request }) => {
      const body = await t.read(request)
      const detectors = (body.detectors ?? {}) as Record<string, unknown>
      const errors: { pointer: string, detail: string }[] = []
      for (const [id, mode] of Object.entries(detectors)) {
        if (!DETECTOR_IDS.includes(id as DetectorId)) errors.push({ pointer: `/detectors/${id}`, detail: 'unknown detector' })
        else if (!MODES.includes(mode as DistributedMode)) errors.push({ pointer: `/detectors/${id}`, detail: 'off, observe or respond' })
      }
      const thresholds = (body.thresholds ?? {}) as Record<string, Record<string, number>>
      for (const [id, t] of Object.entries(thresholds)) {
        if (!DETECTOR_IDS.includes(id as DetectorId)) errors.push({ pointer: `/thresholds/${id}`, detail: 'unknown detector' })
        else if (t.count !== undefined && (t.count < 3 || t.count > 100000)) errors.push({ pointer: `/thresholds/${id}/count`, detail: '3 bis 100000' })
        else if (t.window_s !== undefined && (t.window_s < 30 || t.window_s > 3600)) errors.push({ pointer: `/thresholds/${id}/window_s`, detail: '30 bis 3600 Sekunden' })
      }
      if (errors.length) return problem(400, 'invalid', 'Ungültige Eingabe', errors)
      const d = state()
      // D97: an entry replaces the thresholds, what it leaves out is the built-in value again.
      for (const s of d.settings.detectors) if (thresholds[s.id]) s.thresholds = { ...s.defaults, ...thresholds[s.id] }
      for (const s of d.settings.detectors) {
        const mode = detectors[s.id] as DistributedMode | undefined
        if (!mode) continue
        s.mode = mode
        s.effective_mode = effective(d, mode)
      }
      return json(d.settings)
    })),
  ]
}
