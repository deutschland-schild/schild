import type { LabHealth } from '../src/api/types'
import { describe, expect, it } from 'vitest'
import health from '../../../../contracts/api/fixtures/lab/getHealth.json'
import full from '../../../../contracts/api/fixtures/lab/getHealth.queue-full.json'
import relays from '../../../../contracts/api/fixtures/lab/listRelays.json'
import { computeAlerts } from '../src/lib/alerts'

const now = new Date('2026-10-26T12:00:30Z')

describe('overview alerts', () => {
  it('is quiet for a healthy lab', () => {
    expect(computeAlerts({ health: health as LabHealth, now, checkpointTtlS: 180 })).toEqual([])
  })

  it('flags a full queue and a lagging worker, most urgent first', () => {
    const a = computeAlerts({ health: full as LabHealth, now, checkpointTtlS: 180 })
    expect(a.map(x => x.id)).toEqual(['queue-full', 'worker-scoring'])
    expect(a[0]!.tone).toBe('danger')
  })

  it('flags ack p99 at or above 50 ms, a stale checkpoint and disconnected relays', () => {
    const h = { ...(health as LabHealth), ack_ms: { p50: 4, p99: 50, window_s: 300 } }
    const ids = computeAlerts({ health: h, relays: relays.items as never, now: new Date('2026-10-26T12:10:00Z'), checkpointTtlS: 180 }).map(x => x.id)
    expect(ids).toEqual(['ack', 'checkpoint', 'relays'])
  })
})
