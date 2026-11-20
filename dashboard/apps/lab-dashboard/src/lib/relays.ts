import type { Relay } from '@/api/types'

/**
 * The lab's feed has two kinds of subscribers: relays (they fan the feed out to clients) and peer labs (they
 * follow it for co-signing). GET /relays lists both. Since contracts v0.2 (D24) the lab says which is which in
 * `Relay.kind`: `peer_lab` only when the subscription is signed by a rules key of a configured peer, so a relay
 * that names itself like a peer lab stays a relay. The dashboard no longer guesses from the subscriber name.
 */
export type SubscriberKind = Relay['kind']

export function subscriberKind(r: Pick<Relay, 'kind'>): SubscriberKind {
  return r.kind
}

/** Stable key of a subscriber: a relay and a peer lab may report the same id. */
export function subscriberKey(r: Pick<Relay, 'id' | 'kind'>): string {
  return `${r.kind}/${r.id}`
}

export interface SplitSubscribers<T extends Pick<Relay, 'kind'>> {
  relays: T[]
  peerLabs: T[]
}

/** Splits the feed subscribers into real relays and peer labs by the server-side `kind`. */
export function splitSubscribers<T extends Pick<Relay, 'kind'>>(items: T[]): SplitSubscribers<T> {
  const out: SplitSubscribers<T> = { relays: [], peerLabs: [] }
  for (const r of items) (r.kind === 'peer_lab' ? out.peerLabs : out.relays).push(r)
  return out
}
