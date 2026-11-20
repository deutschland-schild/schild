import type { LiveState } from '@schild/ui'
import type { MaybeRefOrGetter } from 'vue'
import type { EventQuery } from '@/api/queries'
import type { EventSummary } from '@/api/types'
import type { StreamHandle, StreamState } from '@/lib/sse'
import { defaultBaseUrl } from '@schild/app-kit'
import { onScopeDispose, ref, shallowRef, toValue, watch } from 'vue'
import { apiPrefix } from '@/api/generated/operations'
import { openStream } from '@/lib/sse'

const MAX = 500

/**
 * Live events over SSE (GET /events/stream) with pause/resume.
 * Pause closes the connection but keeps the last event id; resume sends it as Last-Event-ID
 * so the server replays what happened in between.
 */
export function useLiveEvents(filters: MaybeRefOrGetter<Omit<EventQuery, 'cursor' | 'limit' | 'from' | 'to'>>) {
  const events = shallowRef<EventSummary[]>([])
  const state = ref<LiveState>('paused')
  const active = ref(false)
  const missedWhilePaused = ref(0)
  let handle: StreamHandle | null = null
  let lastId: string | undefined

  function url() {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(toValue(filters))) if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
    const qs = q.toString()
    return `${defaultBaseUrl(apiPrefix)}/events/stream${qs ? `?${qs}` : ''}`
  }

  function onState(s: StreamState) {
    if (!active.value) return
    state.value = s === 'live' ? 'live' : s === 'connecting' ? 'connecting' : s === 'offline' ? 'offline' : 'paused'
  }

  function connect(resumeFrom?: string) {
    handle?.close()
    handle = openStream({
      url: url(),
      lastEventId: resumeFrom,
      onState,
      onMessage: (m) => {
        if (m.event !== 'event' && m.event !== 'message') return
        try {
          const e = JSON.parse(m.data) as EventSummary
          if (events.value.some(x => x.id === e.id)) return
          events.value = [e, ...events.value].slice(0, MAX)
          if (m.id) lastId = m.id
        }
        catch { /* ignore malformed lines */ }
      },
    })
  }

  function start() {
    active.value = true
    missedWhilePaused.value = 0
    connect(lastId)
  }

  function pause() {
    if (handle) lastId = handle.lastEventId() ?? lastId
    handle?.close()
    handle = null
    state.value = 'paused'
  }

  function resume() {
    if (!active.value) return start()
    connect(lastId)
  }

  function stop() {
    pause()
    active.value = false
    events.value = []
    lastId = undefined
  }

  // New filters: start a fresh stream (the old buffer no longer matches).
  watch(() => JSON.stringify(toValue(filters)), () => {
    if (!active.value) return
    events.value = []
    lastId = undefined
    if (state.value !== 'paused') connect()
  })

  onScopeDispose(() => handle?.close())

  return { events, state, active, start, pause, resume, stop, missedWhilePaused }
}
