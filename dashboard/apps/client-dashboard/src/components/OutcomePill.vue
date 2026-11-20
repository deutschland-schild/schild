<script setup lang="ts">
import type { Outcome, WouldBlockReason } from '@/api/types'
import { StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { letThroughText, OUTCOMES } from '@/lib/labels'

/** Outcome of a request; for would_block the title says why it was let through (would_block_reason, v0.5). */
const props = withDefaults(defineProps<{ outcome?: Outcome | null, size?: 'sm' | 'md', reason?: WouldBlockReason | null }>(), { outcome: null, size: 'sm', reason: null })
const meta = computed(() => props.outcome ? OUTCOMES[props.outcome] : null)
const title = computed(() => props.outcome === 'would_block' ? letThroughText(props.reason) : meta.value?.explain)
</script>

<template>
  <StatusPill v-if="meta" :tone="meta.tone" :size="size" :title="title" :data-reason="outcome === 'would_block' && reason ? reason : undefined" data-testid="outcome">
    {{ meta.label }}
  </StatusPill>
  <span v-else class="text-muted-foreground">–</span>
</template>
