import type { Relay } from '../src/api/types'
import { describe, expect, it } from 'vitest'
import { FROZEN_AFTER_S, observeRelays } from '../src/lib/frozen'

const relay = (id: string, last: string, status: Relay['status'] = 'connected', kind: Relay['kind'] = 'relay'): Relay => ({ id, kind, status, last_event_id: last })

describe('frozen relay detection', () => {
  it('flags a connected relay whose last event stands still', () => {
    const mem = new Map()
    const t0 = 1_000_000
    observeRelays([relay('r1', 'a-1'), relay('r2', 'a-1')], mem, t0)
    const later = observeRelays([relay('r1', 'a-9'), relay('r2', 'a-1')], mem, t0 + FROZEN_AFTER_S * 1000)
    expect(later['relay/r1']!.frozen).toBe(false)
    expect(later['relay/r2']!.frozen).toBe(true)
  })

  it('does not flag disconnected relays (they already show as disconnected)', () => {
    const mem = new Map()
    observeRelays([relay('r', 'x', 'disconnected')], mem, 0)
    expect(observeRelays([relay('r', 'x', 'disconnected')], mem, 10 * 60_000)['relay/r']!.frozen).toBe(false)
  })

  it('keeps a relay and a peer lab with the same id apart', () => {
    const mem = new Map()
    observeRelays([relay('lab-b', 'a-1'), relay('lab-b', 'a-1', 'connected', 'peer_lab')], mem, 0)
    const later = observeRelays([relay('lab-b', 'a-1'), relay('lab-b', 'a-7', 'connected', 'peer_lab')], mem, FROZEN_AFTER_S * 1000)
    expect(later['relay/lab-b']!.frozen).toBe(true)
    expect(later['peer_lab/lab-b']!.frozen).toBe(false)
  })
})
