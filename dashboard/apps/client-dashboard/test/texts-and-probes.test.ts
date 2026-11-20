import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { resetMonitoringProbe } from '../src/api/monitoring'
import { incidentReason } from '../src/lib/behaviour'
import { eventHeadline, eventTypeLabel, letThroughText, OUTCOMES } from '../src/lib/labels'
import { byTestId, cleanup, mockServer, mountApp, settle, waitFor } from './helpers'

/** D36 fix round 2: findings of the re-measurement (results/D36-nachmessung-2026-10-29.md). */
const mock = mockServer()
const answers: { path: string, status: number }[] = []
beforeAll(() => {
  mock.server.listen({ onUnhandledRequest: 'error' })
  mock.server.events.on('response:mocked', ({ request, response }) => {
    answers.push({ path: new URL(request.url).pathname, status: response.status })
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

const conflicts = () => answers.filter(a => a.status === 409)

describe('texts (D, initiator 2026-10-29)', () => {
  it('would_block is "Erkannt" and says why it was let through', () => {
    expect(OUTCOMES.would_block.label).toBe('Erkannt')
    expect(OUTCOMES.blocked.label).toBe('Gesperrt')
    // v0.5: the reasons are the contract enum WouldBlockReason (D36 open items).
    expect(letThroughText('gateway_observe')).toBe('Erkannt, aber durchgelassen: Testprofil')
    expect(letThroughText('allowlist')).toBe('Erkannt, aber durchgelassen: Freigabe')
    expect(letThroughText('shared_address')).toBe('Erkannt, aber durchgelassen: geteilte Adresse')
    expect(letThroughText(null)).toBe('Erkannt, aber durchgelassen. Schild hätte die Anfrage sonst gesperrt.')
  })

  it('names every event that is no request, a block with what happened', () => {
    const ev = (type: string, extra: object = {}) => ({ id: 'x', time: '2026-11-19T22:00:00Z', type, ...extra })
    expect(eventHeadline(ev('schild.block.set.v1', { outcome: 'blocked', ip: '203.0.113.9' }))).toBe('IP gesperrt')
    expect(eventHeadline(ev('schild.block.set.v1', { outcome: 'would_block' }))).toBe('IP wäre gesperrt worden')
    expect(eventHeadline(ev('schild.block.lifted.v1'))).toBe('Sperre aufgehoben')
    expect(eventHeadline(ev('schild.behaviour.triggered.v1', { summary: 'behaviour path_probing block' }))).toBe('Szenario: Suche nach Schwachstellen')
    expect(eventHeadline(ev('schild.behaviour.triggered.v1'))).toBe('Szenario ausgelöst')
    expect(eventHeadline(ev('schild.ratelimit.exceeded.v1'))).toBe('Limit überschritten')
    // No type of the contract falls back to the bare word "Ereignis".
    for (const t of ['schild.distributed.detected.v1', 'schild.distributed.ended.v1', 'schild.dashboard.access_reset.v1', 'schild.incident.exported.v1', 'schild.access.protection_set.v1',
      'schild.access.protection_removed.v1', 'schild.access.login.v1', 'schild.access.prefix_locked.v1', 'schild.crawler.policy_set.v1'])
      expect(eventTypeLabel(t), t).not.toBe('Ereignis')
  })

  it('shows an incident reason in German, the CRS text only as detail', () => {
    const r = incidentReason('913100, 930130 Found User-Agent associated with security scanner')!
    expect(r.title).not.toMatch(/Found|associated/)
    expect(r.detail).toContain('Found User-Agent')
    expect(incidentReason('949110, 942100 Inbound Anomaly Score Exceeded')!.title).toBe(incidentReason('942100')!.title)
    expect(incidentReason('behaviour waf_repeat: 5 blocked requests')!.detail).toBeNull()
  })
})

describe('styleguide (D)', () => {
  it('needs the login like every other page', async () => {
    mock.state.session.authenticated = false
    const { router } = await mountApp('/styleguide')
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.next).toBe('/styleguide')
  })
})

describe('only requests the API can answer (D)', () => {
  it('monitoring off: one probe per session, no other 409', async () => {
    mock.state.monitoring.enabled = false
    await mountApp('/w/verein.example')
    await waitFor(() => !!byTestId('monitoring-off'))
    await settle(10)
    expect(conflicts().map(a => a.path)).toEqual(['/api/v0/monitoring/now'])
    // A second page in the same session asks nothing again.
    cleanup()
    answers.length = 0
    await mountApp('/w/verein.example/charts')
    await settle(10)
    expect(conflicts()).toEqual([])
  })

  it('a filter at 6 h without the request ring costs no 409', async () => {
    await mountApp('/w/verein.example?time=6h&filter=country:DE')
    await settle(12)
    expect(answers.some(a => a.path === '/api/v0/monitoring/series' && a.status === 200)).toBe(true)
    expect(conflicts().filter(a => a.path !== '/api/v0/requests')).toEqual([])
    // The ring probe is the only 409 of the session, and it is asked once.
    expect(conflicts().filter(a => a.path === '/api/v0/requests').length).toBeLessThanOrEqual(1)
  })
})
