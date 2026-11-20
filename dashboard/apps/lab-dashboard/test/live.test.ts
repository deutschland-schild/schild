import { QueryClient } from '@tanstack/vue-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { live, pollInterval, setPaused, startLive } from '../src/lib/live'

class FakeES {
  static last: FakeES
  readyState = 0
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((e: MessageEvent) => void) | null = null
  listeners: Record<string, ((e: MessageEvent) => void)[]> = {}
  closed = false
  constructor(public url: string) {
    FakeES.last = this
  }

  addEventListener(t: string, fn: (e: MessageEvent) => void) {
    (this.listeners[t] ??= []).push(fn)
  }

  emit(t: string, data: string) {
    for (const fn of this.listeners[t] ?? []) fn({ data } as MessageEvent)
  }

  close() {
    this.closed = true
    this.readyState = 2
  }
}

afterEach(() => {
  live.paused = false
  live.mode = 'connecting'
  vi.useRealTimers()
})

describe('live updates', () => {
  it('uses the stream when it opens and stops polling', () => {
    const qc = new QueryClient()
    const poll = pollInterval(5000)
    const stop = startLive(qc, { url: '/api/v0/events/stream', EventSource: FakeES as never })
    expect(live.mode).toBe('connecting')
    expect(poll.value).toBe(5000)
    FakeES.last.readyState = 1
    FakeES.last.onopen!()
    expect(live.mode).toBe('stream')
    expect(poll.value).toBe(false)
    stop()
    expect(FakeES.last.closed).toBe(true)
  })

  it('writes pushed health into the cache and invalidates other topics', () => {
    const qc = new QueryClient()
    const spy = vi.spyOn(qc, 'invalidateQueries')
    startLive(qc, { url: '/s', EventSource: FakeES as never })
    FakeES.last.onopen!()
    FakeES.last.emit('health', JSON.stringify({ lab: 'lab-a' }))
    expect(qc.getQueryData(['health'])).toEqual({ lab: 'lab-a' })
    FakeES.last.emit('proposals', '{}')
    expect(spy).toHaveBeenCalledWith({ queryKey: ['proposals'] })
  })

  it('falls back to polling when the stream is missing, and retries later', () => {
    vi.useFakeTimers()
    const qc = new QueryClient()
    startLive(qc, { url: '/s', EventSource: FakeES as never, retryMs: 1000 })
    const first = FakeES.last
    first.readyState = 2
    first.onerror!()
    expect(live.mode).toBe('poll')
    expect(pollInterval(5000).value).toBe(5000)
    vi.advanceTimersByTime(1000)
    expect(FakeES.last).not.toBe(first)
  })

  it('pausing stops polling and ignores events; resuming refreshes', () => {
    const qc = new QueryClient()
    const spy = vi.spyOn(qc, 'invalidateQueries')
    startLive(qc, { url: '/s', EventSource: FakeES as never })
    setPaused(qc, true)
    expect(pollInterval(5000).value).toBe(false)
    FakeES.last.emit('health', '{"lab":"x"}')
    expect(qc.getQueryData(['health'])).toBeUndefined()
    setPaused(qc, false)
    expect(spy).toHaveBeenCalled()
  })
})
