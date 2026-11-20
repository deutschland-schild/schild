import type { LiveState } from '@schild/ui'
import type { MaybeRefOrGetter } from 'vue'
import type { LiveTick, ServerNow } from '@/api/monitoring'
import type { StreamHandle, StreamState } from '@/lib/sse'
import { defaultBaseUrl } from '@schild/app-kit'
import { computed, onScopeDispose, ref, shallowRef, toValue, watch } from 'vue'
import { apiPrefix } from '@/api/generated/operations'
import { openStream } from '@/lib/sse'

/** Seconds kept for the rolling live numbers (the "last 60 s" of the tiles). */
const WINDOW = 60

/**
 * Live ticks of GET /monitoring/stream (one per second, every 10th with a server sample).
 * Keeps the last 60 ticks and derives the rolling numbers of the "Gerade jetzt" tiles.
 * Reconnects with Last-Event-ID, so a short drop replays the missed seconds.
 */
export function useMonitoringStream(site: MaybeRefOrGetter<string | undefined>, enabled: MaybeRefOrGetter<boolean> = true) {
  const ticks = shallowRef<LiveTick[]>([])
  const server = shallowRef<ServerNow | null>(null)
  const state = ref<LiveState>('connecting')
  let handle: StreamHandle | null = null

  function url() {
    const s = toValue(site)
    return `${defaultBaseUrl(apiPrefix)}/monitoring/stream${s ? `?site=${encodeURIComponent(s)}` : ''}`
  }
  function onState(s: StreamState) {
    state.value = s === 'live' ? 'live' : s === 'connecting' ? 'connecting' : s === 'offline' ? 'offline' : 'paused'
  }
  function connect() {
    handle?.close()
    ticks.value = []
    handle = openStream({
      url: url(),
      onState,
      onMessage: (m) => {
        if (m.event !== 'tick') return
        try {
          const t = JSON.parse(m.data) as LiveTick
          const last = ticks.value[ticks.value.length - 1]
          if (last && Date.parse(last.t) >= Date.parse(t.t)) return
          ticks.value = [...ticks.value, t].slice(-WINDOW)
          if (t.server) server.value = t.server
        }
        catch { /* ignore malformed ticks */ }
      },
    })
  }
  function close() {
    handle?.close()
    handle = null
  }

  watch(() => [toValue(enabled), toValue(site)] as const, ([on]) => {
    if (on) connect()
    else close()
  }, { immediate: true })
  onScopeDispose(close)

  /** Rolling numbers over the ticks received (up to 60 s). */
  const rolling = computed(() => {
    const t = ticks.value
    if (!t.length) return null
    let requests = 0
    let stopped = 0
    let would = 0
    let failClosed = 0
    for (const x of t) {
      requests += x.traffic.requests
      stopped += x.traffic.stopped
      would += x.traffic.would_block
      failClosed += x.traffic.fail_closed
    }
    const last = t[t.length - 1]!
    return {
      seconds: t.length,
      requestsPerS: requests / t.length,
      stoppedShare: requests ? stopped / requests : null,
      wouldBlockShare: requests ? would / requests : null,
      failClosed,
      latencyTotalP95: last.latency_total_p95_ms ?? null,
      latencyOverheadP95: last.latency_overhead_p95_ms ?? null,
    }
  })

  return { ticks, server, state, rolling, reconnect: connect, close }
}
