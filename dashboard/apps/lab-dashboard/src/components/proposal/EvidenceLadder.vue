<script setup lang="ts">
import type { Evidence, MaxAction, ProposalClass } from '@/api/types'
import { Check, Circle } from '@lucide/vue'
import { computed } from 'vue'
import { actionRank, ladder } from '@/lib/evidence'
import { ACTION_HINT, ACTION_LABEL } from '@/lib/labels'

/** The evidence ladder observe -> challenge -> block (G2): which steps are reached and what each needs. */
const props = defineProps<{ cls: ProposalClass, evidence: Evidence, requested?: MaxAction, allowed?: MaxAction | null }>()
const steps = computed(() => ladder(props.cls, props.evidence))
/** A step whose evidence is there but which the lab still caps (negative corpus, simulated operators). */
function capped(action: MaxAction, reached: boolean) {
  return reached && props.allowed !== undefined && actionRank(props.allowed) < actionRank(action)
}
</script>

<template>
  <ol class="grid gap-3 md:grid-cols-3" aria-label="Belegstufen">
    <li
      v-for="(s, i) in steps"
      :key="s.action"
      class="rounded-xl border p-3"
      :class="s.reached && !capped(s.action, s.reached) ? 'border-status-signal/50 bg-status-signal-subtle' : 'bg-card'"
      :data-step="s.action"
      :data-reached="s.reached"
    >
      <div class="flex items-center justify-between gap-2">
        <p class="text-sm font-bold">
          <span class="font-normal text-muted-foreground">{{ i + 1 }}.</span> {{ ACTION_LABEL[s.action] }}
        </p>
        <span class="text-right text-xs font-medium" :class="s.reached && !capped(s.action, s.reached) ? 'text-status-signal-text' : 'text-muted-foreground'">
          {{ capped(s.action, s.reached) ? 'vom Lab begrenzt' : s.reached ? 'erreicht' : 'offen' }}<template v-if="requested === s.action"> · gewünscht</template>
        </span>
      </div>
      <p class="mt-0.5 text-xs text-muted-foreground">
        {{ ACTION_HINT[s.action] }}
      </p>
      <p class="mt-2 text-xs font-medium">
        {{ s.mode === 'all' ? 'Braucht alles:' : 'Braucht eins davon:' }}
      </p>
      <ul class="mt-1 space-y-1">
        <li v-for="r in s.requirements" :key="r.text" class="flex items-start gap-1.5 text-xs">
          <Check v-if="r.met" class="mt-0.5 size-3.5 shrink-0 text-status-signal-text" aria-hidden="true" />
          <Circle v-else class="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          <span>
            <span class="sr-only">{{ r.met ? 'Erfüllt:' : 'Offen:' }}</span>
            {{ r.text }}<span v-if="r.progress" class="text-muted-foreground"> ({{ r.progress }})</span>
          </span>
        </li>
      </ul>
    </li>
  </ol>
</template>
