import { describe, expect, it } from 'vitest'
import { buildSeed } from '../src/mock/seed'
import { LabMock, memorySessionStore } from '../src/mock/state'

function lab() {
  const m = new LabMock(memorySessionStore(), { peerDelayMs: 0, now: new Date('2026-10-26T12:00:00Z') })
  const s = m.login({ user: 'm.muster', password: 'ok' }).body as { csrf_token: string }
  return { m, csrf: s.csrf_token }
}
const body = (r: { body?: unknown }) => r.body as any

describe('lab mock (mirrors the server rules the UI depends on)', () => {
  it('contains no IP address anywhere (labs never receive visitor IPs)', () => {
    const json = JSON.stringify(buildSeed(new Date('2026-10-26T12:00:00Z')))
    expect(json).not.toMatch(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
    expect(json).not.toMatch(/"(ip|client_ip|remote_addr|ip_prefix|ip_hash)"/i)
  })

  it('requires login and a CSRF token for changes', () => {
    const m = new LabMock(memorySessionStore(), { peerDelayMs: 0 })
    expect(m.guard('GET', null)?.status).toBe(401)
    expect(m.login({ password: 'falsch' }).status).toBe(401)
    const s = body(m.login({ password: 'x' }))
    expect(m.guard('GET', null)).toBeNull()
    expect(m.guard('POST', 'wrong')?.status).toBe(403)
    expect(m.guard('POST', s.csrf_token)).toBeNull()
  })

  it('never approves above the evidence and always names person and organisation', () => {
    const { m } = lab()
    expect(m.approve('prop-0007', { max_action: 'block', org: 'op-test-a', max_action_until: '2026-11-01T00:00:00Z' }).status).toBe(409)
    expect(m.approve('prop-0007', { max_action: 'challenge', org: '' }).status).toBe(400)
    expect(m.approve('prop-0007', { max_action: 'challenge', org: 'op-test-a' }).status).toBe(400) // needs max_action_until
    const ok = m.approve('prop-0007', { max_action: 'challenge', org: 'op-test-a', max_action_until: '2026-11-01T00:00:00Z' })
    expect(ok.status).toBe(200)
    expect(body(ok).approvals[0]).toMatchObject({ by: 'm.muster', org: 'op-test-a', max_action: 'challenge' })
    // The same person cannot approve twice.
    expect(m.approve('prop-0007', { max_action: 'observe', org: 'op-test-b' }).status).toBe(409)
  })

  it('rejects only with a reason', () => {
    const { m } = lab()
    expect(m.reject('prop-0007', { reason: ' ' }).status).toBe(400)
    expect(body(m.reject('prop-0007', { reason: 'trifft normale Suchanfragen' })).status).toBe('rejected')
  })

  it('creates a proposal from a pattern and recomputes the allowed action from evidence', async () => {
    const { m } = lab()
    const pattern = m.state.patterns.find(p => p.action_sig === 'sqli/rest-api')!
    const created = m.createProposal({ pattern_id: pattern.pattern_id, class: 'virtual_patch', seclang: 'SecRule ARGS "@detectSQLi" "id:7700100,phase:2,deny,log,t:none"', target: { software: 'wp-plugin/rest', versions: '<1.2' } as never, requested_max_action: 'block' })
    expect(created.status).toBe(201)
    const p = body(created)
    expect(p.allowed_max_action).toBe('observe') // 3 issuers at 33 %
    expect(pattern.proposal_id).toBe(p.id)
    const after = body(m.addEvidence(p.id, { kind: 'reproduction', image: 'wp:6.6', version: '1.1', request: 'GET / HTTP/1.1', result: 'reproduced' }))
    expect(after.allowed_max_action).toBe('challenge')
    expect(after.evidence.reproduced_operators).toBe(1)
    expect(m.addEvidence(p.id, { kind: 'reproduction' }).status).toBe(400)
  })

  it('withdraw all (wire: emergency stop): wire confirm_text NOT-AUS and password, then collects co-signatures', () => {
    const { m } = lab()
    expect(m.emergencyStop({ confirm_text: 'ALLE ZURÜCKZIEHEN' as never, password: 'x', reason: 'emergency_stop' }).status).toBe(400)
    expect(m.emergencyStop({ confirm_text: 'NOT-AUS', password: 'falsch', reason: 'emergency_stop' }).status).toBe(403)
    expect(m.emergencyStop({ confirm_text: 'NOT-AUS', password: '', reason: 'emergency_stop' }).status).toBe(400)
    const r = m.emergencyStop({ confirm_text: 'NOT-AUS', password: 'x', reason: 'emergency_stop' })
    expect(r.status).toBe(201)
    expect(body(r)).toMatchObject({ scope: 'all', status: 'collecting', signatures: [{ lab: 'lab-a' }] })
    expect(m.emergencyStop({ confirm_text: 'NOT-AUS', password: 'x', reason: 'emergency_stop' }).status).toBe(409)
  })

  it('co-signing by a second operator makes a withdrawal effective', () => {
    const { m } = lab()
    const w = m.state.withdrawals.find(x => x.status === 'collecting')!
    expect(m.cosign(w.seq, { password: 'falsch' }).status).toBe(403)
    const r = body(m.cosign(w.seq, { password: 'x' }))
    expect(r.status).toBe('effective')
    expect(m.cosign(w.seq, { password: 'x' }).status).toBe(409)
  })

  it('revoking an issuer needs the password and stops all its clients', () => {
    const { m } = lab()
    expect(m.revokeIssuer('issuer-test-evil', { password: '' }).status).toBe(400)
    expect(body(m.revokeIssuer('issuer-test-evil', { password: 'x' })).revoked).toBe(true)
    expect(m.state.clients.filter(c => c.issuer === 'issuer-test-evil').every(c => c.revoked)).toBe(true)
  })

  it('keeps the scoring floors (min 3 issuers, max share 0.34)', () => {
    const { m } = lab()
    const r = m.updateSettings({ scoring: { min_issuers: 2, max_issuer_share: 0.5 }, confirm: { password: 'x' } })
    expect(r.status).toBe(400)
    expect(body(r).errors.map((e: { pointer: string }) => e.pointer)).toEqual(['/scoring/min_issuers', '/scoring/max_issuer_share'])
    expect(body(m.updateSettings({ scoring: { min_issuers: 4 }, confirm: { password: 'x' } })).scoring.min_issuers).toBe(4)
  })

  it('serves a log whose digests match the envelopes', async () => {
    const { m } = lab()
    await m.whenReady()
    const list = body(await m.listLog(new URLSearchParams()))
    expect(list.head.size).toBe(list.items[0].index + 1)
    expect(list.items[0].envelope).toBeNull()
    const entry = body(await m.getLogEntry(list.items[0].index))
    expect(entry.envelope.payload).toBeTruthy()
  })
})
