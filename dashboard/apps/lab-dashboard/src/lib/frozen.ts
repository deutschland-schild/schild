import type { Relay } from '@/api/types'
import { subscriberKey } from './relays'

/**
 * Frozen-relay detection in the dashboard: the lab re-signs a checkpoint every 60 s, so a healthy relay's
 * last_event_id moves at least once a minute. If it stands still for FROZEN_AFTER_S while the relay
 * claims to be connected, the relay is probably frozen (serving stale data). Clients detect this on their
 * side via checkpoint expiry (contracts/stream.md); this view helps the operator notice it first.
 */
export const FROZEN_AFTER_S = 180

export interface RelaySeen { id: string, since: number }
export type RelayMemory = Map<string, RelaySeen>

export interface RelayHealth { frozen: boolean, stillForS: number }

export function observeRelays(relays: Relay[], memory: RelayMemory, now = Date.now()): Record<string, RelayHealth> {
  const out: Record<string, RelayHealth> = {}
  for (const r of relays) {
    const key = r.last_event_id ?? ''
    const sk = subscriberKey(r) // a relay and a peer lab may report the same id
    const seen = memory.get(sk)
    if (!seen || seen.id !== key) memory.set(sk, { id: key, since: now })
    const since = memory.get(sk)!.since
    const stillForS = Math.round((now - since) / 1000)
    out[sk] = { frozen: r.status !== 'disconnected' && !!key && stillForS >= FROZEN_AFTER_S, stillForS }
  }
  return out
}
