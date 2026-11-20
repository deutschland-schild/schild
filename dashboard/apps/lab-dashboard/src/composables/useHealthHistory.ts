import type { LabHealth } from '@/api/types'
import { reactive, watch } from 'vue'
import { useHealth } from '@/api/queries'

const MAX = 60
/** Ring buffer of recent health samples (kept for the session, survives navigation). */
const history = reactive({ rate: [] as number[], p99: [] as number[], p50: [] as number[], queue: [] as number[], last: '' })

export function pushSample(h: LabHealth): void {
  if (h.generated_at === history.last) return
  history.last = h.generated_at
  const push = (arr: number[], v: number) => {
    arr.push(v)
    if (arr.length > MAX) arr.shift()
  }
  push(history.rate, Math.round(h.ingest.rate_per_s * 60))
  push(history.p99, h.ack_ms.p99)
  push(history.p50, h.ack_ms.p50)
  push(history.queue, h.queue.depth.new_pattern + h.queue.depth.repeat + h.queue.depth.baseline)
}

export function useHealthHistory() {
  const q = useHealth()
  watch(() => q.data.value, h => h && pushSample(h), { immediate: true })
  return { health: q, history }
}
