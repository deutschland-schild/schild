import type { MaybeRefOrGetter } from 'vue'
import { computed, toValue } from 'vue'
import { useBehaviourHits } from '@/api/behaviour'
import { hitBlockRunning } from '@/lib/behaviour'

/**
 * Behaviour blocks a website set that still run, with how long and why (D36 measurement D.4: among many
 * WAF incidents the duration of a block was out of reach of the incident list). Blocks that ended
 * (ended_at, also with a restart) are left out. Shared by Ereignisse and the status line on Zugriffe (D68).
 */
export function useRunningBlocks(site: MaybeRefOrGetter<string>) {
  const q = useBehaviourHits(() => ({ active: true, kind: 'scenario' as const, ...(toValue(site) ? { site: toValue(site) } : {}) }))
  const running = computed(() => (q.data.value?.pages[0]?.items ?? []).filter(h => hitBlockRunning(h) && h.duration_s && h.level))
  /** The first 20 for a list. */
  const blocks = computed(() => running.value.slice(0, 20))
  const count = computed(() => q.data.value ? running.value.length : null)
  return { q, blocks, count }
}
