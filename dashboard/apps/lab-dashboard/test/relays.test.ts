import type { Relay } from '../src/api/types'
import { describe, expect, it } from 'vitest'
import relayFixture from '../../../../contracts/api/fixtures/lab/listRelays.json'
import { computeAlerts } from '../src/lib/alerts'
import { splitSubscribers, subscriberKey, subscriberKind } from '../src/lib/relays'

const sub = (id: string, kind: Relay['kind'], status: Relay['status'] = 'connected'): Relay => ({ id, kind, status, connected_since: null, bundle_version: 0 })

describe('feed subscribers: relays vs peer labs (Relay.kind, contracts v0.2)', () => {
  // Regression: lab-b and lab-c follow lab-a's feed for co-signing and were counted as relays ("4 von 4 Relays" with two relays).
  const items = [sub('relay-dev-1', 'relay'), sub('lab-c', 'peer_lab'), sub('lab-b', 'peer_lab'), sub('relay-dev-2', 'relay')]

  it('splits by the server-side kind', () => {
    expect(subscriberKind(sub('lab-b', 'peer_lab'))).toBe('peer_lab')
    const s = splitSubscribers(items)
    expect(s.relays.map(r => r.id)).toEqual(['relay-dev-1', 'relay-dev-2'])
    expect(s.peerLabs.map(r => r.id)).toEqual(['lab-c', 'lab-b'])
  })

  it('does not trust the name: a relay that calls itself like a peer lab stays a relay', () => {
    const s = splitSubscribers([sub('lab-b', 'relay'), sub('lab-b', 'peer_lab')])
    expect(s.relays).toHaveLength(1)
    expect(s.peerLabs).toHaveLength(1)
    expect(subscriberKey(s.relays[0]!)).not.toBe(subscriberKey(s.peerLabs[0]!))
  })

  it('reads the kind from the contract fixture', () => {
    const s = splitSubscribers(relayFixture.items as Relay[])
    expect(s.relays.map(r => r.id)).toEqual(['relay-1', 'relay-2'])
    expect(s.peerLabs.map(r => r.id)).toEqual(['lab-a2'])
  })

  it('does not report a disconnected peer lab as a disconnected relay', () => {
    const alerts = computeAlerts({ relays: [sub('relay-dev-1', 'relay'), sub('lab-b', 'peer_lab', 'disconnected')] })
    expect(alerts.map(a => a.id)).toEqual(['peer-feeds'])
    expect(alerts[0]!.title).toBe('1 Peer-Lab folgt dem Feed gerade nicht')
  })
})
