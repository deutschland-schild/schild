import type { BehaviourHit } from '../src/api/behaviour'
import type { Wave } from '../src/api/distributed'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { resetMonitoringProbe } from '../src/api/monitoring'
import type { SeriesResolution, WebsiteRangeKey } from '../src/api/websites'
import { seriesResolutionFor, WEBSITE_RANGE_KEYS, WEBSITE_RANGES } from '../src/api/websites'
import { LONG_BLOCK_INCIDENT } from '../src/mock/websites'
import { blockRunning, hitBlockRunning, hitOutcome, incidentReason, incidentState } from '../src/lib/behaviour'
import { waveOutcome } from '../src/lib/distributed'
import { TEST_BUILD_TEXT, versionText } from '../src/lib/labels'
import { ALERT_OUTCOMES } from '../src/lib/websites'
import { bodyText, byTestId, cleanup, mockServer, mountApp, settle, waitFor, click } from './helpers'

/** UI findings of the independent measurement results/messung-2026-10-29-abend.md (4.4, 4.5). */
const mock = mockServer()
const answers: { path: string, resolution: string | null, status: number }[] = []
beforeAll(() => {
  mock.server.listen({ onUnhandledRequest: 'error' })
  mock.server.events.on('response:mocked', ({ request, response }) => {
    const u = new URL(request.url)
    answers.push({ path: u.pathname, resolution: u.searchParams.get('resolution'), status: response.status })
  })
})
beforeEach(() => {
  answers.length = 0
  resetMonitoringProbe()
})
afterEach(() => {
  cleanup()
  document.body.innerHTML = ''
  mock.reset({})
  resetMonitoringProbe()
})
afterAll(() => mock.server.close())

/** The API answers an explicit resolution with more than this many points with 400 too_many_points. */
const MAX_SERIES_POINTS = 1000
const RESOLUTION_STEP_S: Record<Exclude<SeriesResolution, 'auto'>, number> = { '10s': 10, '1m': 60, '10m': 600 }
/** Points a resolution yields over a range; auto never yields more than 1000 (the gateway merges). */
function seriesPoints(range: WebsiteRangeKey, resolution: SeriesResolution): number {
  if (resolution === 'auto') return Math.min(MAX_SERIES_POINTS, Math.ceil(WEBSITE_RANGES[range].seconds / WEBSITE_RANGES[range].stepS))
  return Math.ceil(WEBSITE_RANGES[range].seconds / RESOLUTION_STEP_S[resolution])
}

describe('series resolution under a filter (4.4, 4.5: 400 too_many_points at 7 and 14 days)', () => {
  it('every range, with and without filter and request ring, asks for at most 1000 points', () => {
    for (const range of WEBSITE_RANGE_KEYS) {
      for (const filtered of [false, true]) {
        for (const ringAnswers of [false, true]) {
          const res = seriesResolutionFor(range, filtered, ringAnswers)
          expect(seriesPoints(range, res), `${range} filtered=${filtered} ring=${ringAnswers}: ${res}`).toBeLessThanOrEqual(MAX_SERIES_POINTS)
        }
      }
    }
    // An explicit 10m over 7 days was the bug: 1008 points.
    expect(seriesPoints('7d', '10m')).toBe(1008)
    expect(seriesResolutionFor('7d', true, false)).toBe('auto')
    expect(seriesResolutionFor('14d', true, false)).toBe('auto')
    // Up to 48 h a filter without the ring still reads the 10 min ring (no 409 per click).
    expect(seriesResolutionFor('6h', true, false)).toBe('10m')
    expect(seriesResolutionFor('48h', true, false)).toBe('10m')
    expect(seriesResolutionFor('6h', false, false)).toBe(WEBSITE_RANGES['6h'].resolution)
  })

  for (const time of ['7d', '14d']) {
    it(`a filter at ${time} on /w/<site> loads the series (no 400)`, async () => {
      mock.reset({ requestRing: false })
      await mountApp(`/w/verein.example?time=${time}&filter=country:DE`)
      await settle(12)
      const series = answers.filter(a => a.path === '/api/v0/monitoring/series')
      expect(series.length).toBeGreaterThan(0)
      expect(series.filter(a => a.status === 400)).toEqual([])
      expect(series.every(a => a.resolution === 'auto')).toBe(true)
    })
  }
})

describe('copy (4.5: "Erkannt", CRS tooltips, build marker)', () => {
  it('says "Erkannt" for detections in observe mode, never "hätte gesperrt/begrenzt/geprüft/reagiert/gebremst"', () => {
    expect(ALERT_OUTCOMES.would_block!.label).toBe('Erkannt')
    expect(ALERT_OUTCOMES.would_rate_limit!.label).toBe('Erkannt (Limit)')
    const base = { id: 'h', kind: 'scenario', scenario: 'path_probing', time: new Date().toISOString(), mode: 'observe', action: 'observe', active: false } as unknown as BehaviourHit
    expect(hitOutcome({ ...base, would_action: 'block' }).label).toBe('Erkannt (Probelauf)')
    expect(hitOutcome({ ...base, kind: 'rate_limit', would_action: 'block' }).label).toBe('Erkannt (Probelauf)')
    expect(waveOutcome({ action: 'observe' } as unknown as Wave).label).toBe('Erkannt (Probelauf)')
  })

  it('leaves no "Hätte gesp." column, no "Probelauf: hätte …", no "Erkannt über" in the shipped sources', () => {
    const stale = /Hätte gesp|Probelauf: hätte|[Hh]ätte gebremst|Erkannt \(hätte|Erkannt über|\(hätte begrenzt\)/
    const found: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name)
        if (statSync(p).isDirectory()) {
          if (name !== 'mock' && name !== 'generated') walk(p)
        }
        else if (/\.(?:vue|ts)$/.test(name) && stale.test(readFileSync(p, 'utf8'))) {
          found.push(p)
        }
      }
    }
    walk(join(import.meta.dirname, '../src'))
    expect(found).toEqual([])
  })

  it('names the source of the IP "IP-Quelle", not "Erkannt über"', async () => {
    const ev = mock.state.events.find(e => e.summary.type === 'schild.request.evaluated.v1' && e.summary.outcome === 'would_block')
      ?? mock.state.events.find(e => e.summary.type === 'schild.request.evaluated.v1')!
    await mountApp(`/events?event=${ev.summary.id}`)
    await waitFor(() => bodyText().includes('IP-Quelle'))
    expect(bodyText()).not.toContain('Erkannt über')
  })

  it('shows CRS rule tooltips in German first, the English CRS text only in brackets', () => {
    expect(incidentReason('930130 Restricted File Access Attempt')!.tooltip).toBe('Versuchter Dateizugriff · 930130 (CRS: Restricted File Access Attempt)')
    expect(incidentReason('949110, 942100 Inbound Anomaly Score Exceeded')!.tooltip).toBe('SQL-Injection-Versuch · 949110, 942100 (CRS: Inbound Anomaly Score Exceeded)')
    expect(incidentReason('913100')!.tooltip).toBe('Scanner · 913100')
    expect(incidentReason('100001 Own rule')!.tooltip).toBe('Eigene Regel · 100001 (Own rule)')
    expect(incidentReason('behaviour waf_repeat: 5 blocked requests')!.tooltip).toBeNull()
  })

  it('the incident list on /w/<site>/events has no English-first tooltip', async () => {
    for (const inc of mock.state.incidents.values()) {
      if (!inc.block) inc.reason = '930130 Restricted File Access Attempt'
    }
    await mountApp('/w/verein.example/events')
    await waitFor(() => document.querySelectorAll('[data-testid="incident-reason"]').length > 0)
    const titles = [...document.querySelectorAll('[data-testid="incident-reason"]')].map(e => e.getAttribute('title') ?? '').filter(Boolean)
    expect(titles).toContain('Versuchter Dateizugriff · 930130 (CRS: Restricted File Access Attempt)')
    for (const t of titles) expect(t).toMatch(/^[A-ZÄÖÜ][^·(]* · \d/)
  })

  it('renders the build marker of the version in calm German', async () => {
    expect(versionText('schild 0.1.0-alpha (non-release: test keys and test profile allowed)')).toBe(`schild 0.1.0-alpha · ${TEST_BUILD_TEXT}`)
    expect(TEST_BUILD_TEXT).toBe('Testversion: Testschlüssel und Testprofil erlaubt')
    expect(versionText('schild 1.0.0 (release)')).toBe('schild 1.0.0')
    expect(versionText('schild 0.1.0-alpha')).toBe('schild 0.1.0-alpha')
    mock.state.overview.version = 'schild 0.1.0-alpha (non-release: test keys and test profile allowed)'
    await mountApp('/settings')
    await waitFor(() => !!byTestId('version'))
    expect(byTestId('version')!.textContent).toContain(TEST_BUILD_TEXT)
    // The sidebar names it short and explains it on hover.
    expect(byTestId('sidebar-version')!.textContent!.trim()).toBe('Version 0.1.0-alpha · Testversion')
    expect(byTestId('sidebar-version')!.getAttribute('title')).toBe(`schild 0.1.0-alpha · ${TEST_BUILD_TEXT}`)
    // The header shows only the mode; the version stays on the server overview.
    expect(document.querySelector('[data-slot="shell-context"]')).toBeNull()
    expect(bodyText()).not.toMatch(/non-release|test keys/)
  })
})

describe('blocks that ended with a restart (4.4 D29 rest, contracts v0.5 ended_at)', () => {
  const past = () => new Date(Date.now() - 20 * 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z')
  const endBlock = () => {
    const inc = mock.state.incidents.get(LONG_BLOCK_INCIDENT)!
    // What the gateway reports for a block ended by a restart: status still blocked, ended_at the start time.
    inc.status = 'blocked'
    inc.block = { ...inc.block!, ended_at: past() }
    return inc
  }

  it('a block runs exactly while ended_at is absent, whatever until says', () => {
    const block = { source: 'behaviour:login_bruteforce', level: 1, net_class: 'residential', duration_s: 900, persisted: true }
    const future = { ...block, until: new Date(Date.now() + 3600_000).toISOString() }
    const longAgo = '2020-01-01T00:00:00Z'
    const stale = { ...block, until: longAgo }
    expect(incidentState({ status: 'blocked', block: { ...future, ended_at: longAgo } })).toBe('ended')
    // An until in the past without ended_at still runs: the clock of the browser does not decide.
    expect(incidentState({ status: 'blocked', block: stale })).toBe('blocked')
    // A rule stopped one request: no block, the address is not blocked (review 2026-11-19).
    expect(incidentState({ status: 'blocked' })).toBe('stopped')
    expect(incidentState({ status: 'unblocked', block: { ...stale, ended_at: longAgo } })).toBe('unblocked')
    expect(blockRunning({ ended_at: longAgo })).toBe(false)
    expect(blockRunning({})).toBe(true)
    expect(blockRunning(null)).toBe(false)
    expect(hitBlockRunning({ active: true })).toBe(true)
    expect(hitBlockRunning({ active: false })).toBe(false)
  })

  it('the incident page shows "Abgelaufen", no "Sperre aufheben", and offers to block again', async () => {
    const inc = endBlock()
    await mountApp(`/incidents/${LONG_BLOCK_INCIDENT}`)
    await waitFor(() => !!byTestId('incident-status'))
    expect(byTestId('incident-status')!.textContent!.trim()).toBe('Abgelaufen')
    expect(byTestId('incident-unblock')).toBeNull()
    expect(byTestId('block-ended')!.getAttribute('datetime')).toBe(inc.block!.ended_at)
    expect(byTestId('incident-block-ip')).not.toBeNull()
    expect(byTestId('block-duration')!.textContent).toContain('beendet um')
    expect(byTestId('block-duration')!.textContent).not.toContain(' bis ')
  })

  it('a running block still shows "Gesperrt" and "Sperre aufheben", nothing to block again', async () => {
    await mountApp(`/incidents/${LONG_BLOCK_INCIDENT}`)
    await waitFor(() => !!byTestId('incident-status'))
    expect(byTestId('incident-status')!.textContent!.trim()).toBe('Gesperrt')
    expect(byTestId('incident-unblock')!.textContent).toContain('Sperre aufheben')
    expect(byTestId('incident-block-ip')).toBeNull()
    expect(byTestId('incident-more')).toBeNull()
  })

  it('a request a rule stopped is "Anfrage gestoppt": let it through, or block the address', async () => {
    const stopped = [...mock.state.incidents.values()].find(i => i.status === 'blocked' && !i.block && i.request.ip)!
    expect(stopped).toBeTruthy()
    await mountApp(`/incidents/${stopped.incident}`)
    await waitFor(() => !!byTestId('incident-status'))
    expect(byTestId('incident-status')!.textContent!.trim()).toBe('Anfrage gestoppt')
    expect(byTestId('incident-unblock')!.textContent).toContain('Durchlassen')
    expect(byTestId('incident-block-ip')!.textContent).toMatch(/IP für (7 Tage|24 Stunden) sperren/)
    await click(byTestId('incident-unblock'))
    await waitFor(() => !!byTestId('unblock-scope'))
    expect(byTestId('unblock-scope')!.textContent).toContain('auf allen Websites dieses Servers')
  })

  it('a lifted behaviour block reads "Aufgehoben"', async () => {
    const inc = mock.state.incidents.get(LONG_BLOCK_INCIDENT)!
    inc.status = 'unblocked'
    inc.block = { ...inc.block!, ended_at: past() }
    await mountApp(`/incidents/${LONG_BLOCK_INCIDENT}`)
    await waitFor(() => !!byTestId('incident-status'))
    expect(byTestId('incident-status')!.textContent!.trim()).toBe('Aufgehoben')
    expect(byTestId('incident-unblock')).toBeNull()
  })

  it('the event of an ended block offers no "Vorfall freischalten"', async () => {
    const inc = endBlock()
    await mountApp(`/events?event=${inc.request.id}`)
    await waitFor(() => !!byTestId('event-incident-ended'))
    expect(byTestId('event-unblock')).toBeNull()
    expect(byTestId('event-false-positive')).toBeNull()
    expect(byTestId('event-allow-ip')).toBeNull()
  })

  it('Ereignisse lists the ended block as "Abgelaufen", not "Gesperrt"', async () => {
    endBlock()
    await mountApp('/w/verein.example/events')
    await waitFor(() => !!document.querySelector(`[data-incident="${LONG_BLOCK_INCIDENT}"]`))
    const row = document.querySelector(`[data-incident="${LONG_BLOCK_INCIDENT}"]`)!
    expect(row.querySelector('[data-testid="incident-list-status"]')!.textContent!.trim()).toBe('Abgelaufen')
    expect(row.querySelector('[data-testid="block-duration"]')!.textContent).toContain('Beendet um')
  })
})

describe('a re-checked request shows its checked paths (D33 amendment, contracts v0.5)', () => {
  const requestEvent = () => mock.state.events.find(e => e.detail.type.startsWith('schild.request.') && e.detail.data.client)!

  it('lists checked_paths in order as "Geprüfte Pfade"', async () => {
    const ev = requestEvent()
    ev.detail.data.checked_paths = ['/shop/login', '/login']
    await mountApp(`/events?event=${ev.detail.id}`)
    await waitFor(() => !!byTestId('checked-paths'))
    const items = [...byTestId('checked-paths')!.querySelectorAll('li')].map(li => li.textContent!.trim())
    expect(items).toEqual(['1. /shop/login', '2. /login'])
    expect(bodyText()).toContain('Geprüfte Pfade')
  })

  it('shows no row for a request checked once', async () => {
    const ev = requestEvent()
    delete ev.detail.data.checked_paths
    await mountApp(`/events?event=${ev.detail.id}`)
    await waitFor(() => !!byTestId('request-line'))
    expect(byTestId('checked-paths')).toBeNull()
  })
})
