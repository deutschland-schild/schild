<script setup lang="ts">
import type { RequestOutcome } from '@/api/requests'
import { computed } from 'vue'
import { REQUEST_OUTCOMES } from '@/lib/requests'

/**
 * What schild did with one request, on the tonal scale (no red for traffic): Durchgelassen plain,
 * Erkannt outlined, Gesperrt solid, 503 neutral. The title says why.
 */
const props = defineProps<{ outcome: RequestOutcome, title?: string }>()
const meta = computed(() => REQUEST_OUTCOMES[props.outcome])
const cls = computed(() => {
  switch (meta.value.tone) {
    case 'strong': return 'border-transparent bg-foreground/85 text-background'
    case 'outline': return 'border-foreground/40 bg-card text-foreground'
    case 'neutral': return 'border-dashed bg-muted text-muted-foreground'
    default: return 'border-transparent text-muted-foreground'
  }
})
</script>

<template>
  <span :class="['inline-flex items-center rounded-full border px-1.5 py-px text-xs font-medium whitespace-nowrap', cls]" :title="title ?? meta.detail" :data-outcome="outcome">
    {{ meta.label }}
  </span>
</template>
