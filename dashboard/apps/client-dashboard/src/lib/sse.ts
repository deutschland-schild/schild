/**
 * Minimal SSE client on fetch (instead of EventSource) so the dashboard can send Last-Event-ID itself
 * when resuming after a pause, and can pause without losing its place. Reconnects with backoff.
 */

export interface SseMessage {
  id?: string
  event: string
  data: string
}

/** Incremental parser for text/event-stream (WHATWG HTML §9.2.6). */
export class SseParser {
  private buf = ''
  private data: string[] = []
  private event = ''
  private id: string | undefined
  /** Server-requested reconnection delay, if any. */
  retry: number | undefined

  feed(chunk: string): SseMessage[] {
    this.buf += chunk
    const out: SseMessage[] = []
    let nl: number
    while ((nl = this.buf.search(/\r\n|\r|\n/)) >= 0) {
      // A lone CR at the end may be the first half of CRLF split across chunks: wait for more.
      if (this.buf[nl] === '\r' && nl === this.buf.length - 1) break
      const line = this.buf.slice(0, nl)
      const sepLen = this.buf.startsWith('\r\n', nl) ? 2 : 1
      this.buf = this.buf.slice(nl + sepLen)
      if (line === '') {
        if (this.data.length) out.push({ id: this.id, event: this.event || 'message', data: this.data.join('\n') })
        this.data = []
        this.event = ''
        continue
      }
      if (line.startsWith(':')) continue
      const colon = line.indexOf(':')
      const field = colon < 0 ? line : line.slice(0, colon)
      let value = colon < 0 ? '' : line.slice(colon + 1)
      if (value.startsWith(' ')) value = value.slice(1)
      if (field === 'data') this.data.push(value)
      else if (field === 'event') this.event = value
      else if (field === 'id' && !value.includes('\0')) this.id = value
      else if (field === 'retry' && /^\d+$/.test(value)) this.retry = Number(value)
    }
    return out
  }
}

export type StreamState = 'connecting' | 'live' | 'offline' | 'closed'

export interface StreamOptions {
  url: string
  lastEventId?: string
  onMessage: (m: SseMessage) => void
  onState: (s: StreamState) => void
  fetchImpl?: typeof fetch
  /** Backoff steps in ms after a failed or ended connection. */
  backoff?: number[]
}

export interface StreamHandle {
  close: () => void
  lastEventId: () => string | undefined
}

/** Open a reconnecting SSE stream. `close()` stops it for good (used for pause). */
export function openStream(opts: StreamOptions): StreamHandle {
  const backoff = opts.backoff ?? [1000, 2000, 5000, 10_000]
  const doFetch = opts.fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a))
  let lastId = opts.lastEventId
  let closed = false
  let attempt = 0
  let ctrl: AbortController | null = null
  let timer: ReturnType<typeof setTimeout> | null = null

  async function connect() {
    if (closed) return
    opts.onState('connecting')
    ctrl = new AbortController()
    const parser = new SseParser()
    try {
      const headers: Record<string, string> = { Accept: 'text/event-stream' }
      if (lastId) headers['Last-Event-ID'] = lastId
      const res = await doFetch(opts.url, { headers, signal: ctrl.signal, credentials: 'same-origin', cache: 'no-store' })
      if (res.status === 401 || res.status === 403) {
        closed = true
        opts.onState('closed')
        return
      }
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`)
      attempt = 0
      opts.onState('live')
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        for (const m of parser.feed(value)) {
          if (m.id) lastId = m.id
          opts.onMessage(m)
        }
      }
    }
    catch {
      // fall through to reconnect
    }
    if (closed) return
    opts.onState('offline')
    const wait = parser.retry ?? backoff[Math.min(attempt, backoff.length - 1)]!
    attempt++
    timer = setTimeout(connect, wait)
  }

  void connect()
  return {
    close() {
      closed = true
      if (timer) clearTimeout(timer)
      ctrl?.abort()
      opts.onState('closed')
    },
    lastEventId: () => lastId,
  }
}
