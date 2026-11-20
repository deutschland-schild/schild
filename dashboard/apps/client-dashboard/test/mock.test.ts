import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { SseParser } from '../src/lib/sse'
import { ipMatches } from '../src/mock/handlers'
import { mockServer } from './helpers'

const BASE = 'http://dashboard.schild.test/api/v0'
const mock = mockServer()
beforeAll(() => mock.server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => mock.server.close())
const csrf = () => mock.state.session.csrf_token!

describe('mock backend follows the API conventions', () => {
  it('rejects state changes without X-CSRF-Token (403 csrf) and answers problem+json', async () => {
    const res = await fetch(`${BASE}/allowlist/mine`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label: 'x' }) })
    expect(res.status).toBe(403)
    expect(res.headers.get('content-type')).toContain('application/problem+json')
    expect((await res.json()).code).toBe('csrf')
  })

  it('answers 401 unauthenticated without a session', async () => {
    mock.reset({ scenario: 'login' })
    const res = await fetch(`${BASE}/overview`)
    expect(res.status).toBe(401)
    expect((await res.json()).code).toBe('unauthenticated')
    mock.reset({})
  })

  it('returns field errors for invalid settings and has no mode to set (D89)', async () => {
    const h = { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }
    let res = await fetch(`${BASE}/settings`, { method: 'PATCH', headers: h, body: JSON.stringify({ retention: { raw_ip_days: 0 } }) })
    expect(res.status).toBe(400)
    expect((await res.json()).errors[0].pointer).toBe('/retention/raw_ip_days')
    res = await fetch(`${BASE}/settings`, { method: 'PATCH', headers: h, body: JSON.stringify({ mode: 'observe' }) })
    expect(res.status).toBe(400)
    expect((await res.json()).errors[0].pointer).toBe('/mode')
  })

  it('pages with cursors until next_cursor is null', async () => {
    let cursor: string | null = ''
    let n = 0
    while (cursor !== null) {
      const res: Response = await fetch(`${BASE}/events?limit=100${cursor ? `&cursor=${cursor}` : ''}`)
      const page = await res.json() as { items: unknown[], next_cursor: string | null }
      n += page.items.length
      cursor = page.next_cursor
    }
    expect(n).toBe(mock.state.events.length)
  })

  it('replays missed events on the SSE stream after Last-Event-ID', async () => {
    const last = mock.state.events[3]!.summary.id
    const missed = mock.state.events.slice(0, 3).map(e => e.summary.id).reverse()
    const ctrl = new AbortController()
    const res = await fetch(`${BASE}/events/stream`, { headers: { 'Last-Event-ID': last }, signal: ctrl.signal })
    expect(res.headers.get('content-type')).toContain('text/event-stream')
    const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader()
    const parser = new SseParser()
    const ids: string[] = []
    while (ids.length < 4) {
      const { value } = await reader.read()
      for (const m of parser.feed(value!)) if (m.id) ids.push(m.id)
    }
    ctrl.abort()
    // The three newer stored events come first, oldest first, then a new live event.
    expect(ids.slice(0, 3)).toEqual(missed)
    expect(missed).not.toContain(ids[3])
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('matches IPs exactly and by CIDR', () => {
    expect(ipMatches('203.0.113.42', '203.0.113.0/24')).toBe(true)
    expect(ipMatches('198.51.100.1', '203.0.113.0/24')).toBe(false)
    expect(ipMatches('2001:db8::17', '2001:db8::/32')).toBe(true)
    expect(ipMatches('2001:db9::17', '2001:db8::/32')).toBe(false)
    expect(ipMatches('192.0.2.1', '192.0.2.1')).toBe(true)
  })
})
