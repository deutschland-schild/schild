import type { QueryClient } from '@tanstack/vue-query'
import type { ComputedRef } from 'vue'
import { computed, reactive } from 'vue'

/**
 * Live updates for the dashboard.
 *
 * Preferred: one SSE stream (`GET <api>/events/stream`, contracts v0.1, operationId streamEvents) whose event
 * names are topics: `health` carries a full LabHealth body, `signals` a ReceivedSignal, `log` a LogEntry, and
 * every other topic a LiveNotice; all of them except health invalidate the queries of their topic.
 * Fallback: when the stream is missing or broken, queries poll at calm intervals (pollInterval).
 * The dashboard never touches the ingest path; one stream or a few small GETs per interval (M6).
 */
export type LiveMode = 'connecting' | 'stream' | 'poll'

export const live = reactive({
  mode: 'connecting' as LiveMode,
  /** Paused by the user: no polling, stream events are ignored until resume. */
  paused: false,
  lastEventAt: null as Date | null,
})

/** Query keys refreshed per stream topic. */
export const TOPICS: Record<string, readonly (readonly unknown[])[]> = {
  health: [['health']],
  patterns: [['patterns'], ['signals']],
  signals: [['signals']],
  proposals: [['proposals']],
  bundles: [['bundles']],
  withdrawals: [['withdrawals']],
  network: [['network']],
  log: [['log']],
  issuers: [['issuers'], ['clients']],
  clients: [['clients']],
  settings: [['settings']],
}

/** refetchInterval for vue-query: polls only when no stream is live and the user did not pause. */
export function pollInterval(ms: number): ComputedRef<number | false> {
  return computed(() => (live.paused || live.mode === 'stream' ? false : ms))
}

export interface LiveOptions {
  url: string
  /** Injected for tests. */
  EventSource?: typeof EventSource
  /** Retry the stream after falling back to polling (ms). */
  retryMs?: number
}

/** Connect the stream; returns a stop function. */
export function startLive(qc: QueryClient, opts: LiveOptions): () => void {
  const ES = opts.EventSource ?? (typeof EventSource === 'undefined' ? undefined : EventSource)
  const retryMs = opts.retryMs ?? 60_000
  let es: EventSource | undefined
  let retry: ReturnType<typeof setTimeout> | undefined
  let stopped = false

  if (!ES) {
    live.mode = 'poll'
    return () => {}
  }

  const handle = (topic: string, raw: string) => {
    live.lastEventAt = new Date()
    if (live.paused) return
    if (topic === 'health' && raw) {
      try {
        qc.setQueryData(['health'], JSON.parse(raw))
        return
      }
      catch {
        // fall through to invalidation
      }
    }
    for (const key of TOPICS[topic] ?? []) void qc.invalidateQueries({ queryKey: key })
  }

  const connect = () => {
    if (stopped) return
    live.mode = 'connecting'
    es = new ES(opts.url, { withCredentials: true })
    es.onopen = () => {
      live.mode = 'stream'
    }
    es.onerror = () => {
      if (!es || es.readyState === 2 /* CLOSED */) {
        // Endpoint missing or refused: poll, and try the stream again later.
        es?.close()
        live.mode = 'poll'
        retry = setTimeout(connect, retryMs)
      }
      else {
        live.mode = 'connecting' // the browser reconnects with Last-Event-ID; poll meanwhile
      }
    }
    for (const topic of Object.keys(TOPICS)) es.addEventListener(topic, e => handle(topic, (e as MessageEvent).data))
    es.onmessage = (e) => {
      // Unnamed events may carry {"topic": "..."}.
      try {
        const msg = JSON.parse(e.data) as { topic?: string }
        if (msg.topic) handle(msg.topic, '')
      }
      catch {
        // ignore keep-alives and malformed data
      }
    }
  }
  connect()

  return () => {
    stopped = true
    if (retry) clearTimeout(retry)
    es?.close()
  }
}

/** Resume after a pause: refresh everything once. */
export function setPaused(qc: QueryClient, paused: boolean): void {
  live.paused = paused
  if (!paused) void qc.invalidateQueries()
}
