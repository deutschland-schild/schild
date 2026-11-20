<script setup lang="ts">
import type { BotVerification } from '@/api/requests'
import { formatNumber } from '@schild/ui'
import { computed } from 'vue'
import { VERIFICATION, verificationLabel } from '@/lib/requests'

/** Verification state of a bot in words ("bestätigt", "gibt sich als Googlebot aus"); never colour alone. */
const props = defineProps<{ state: BotVerification, name?: string, count?: number }>()
const meta = computed(() => VERIFICATION[props.state])
const cls = computed(() => {
  switch (meta.value.tone) {
    case 'strong': return 'border-transparent bg-foreground/85 text-background'
    case 'outline': return 'border-dashed border-foreground/40 text-foreground'
    case 'muted': return 'border-border text-muted-foreground'
    default: return 'border-border bg-card text-foreground'
  }
})
</script>

<template>
  <span :class="['inline-flex items-center gap-1 rounded-full border px-1.5 py-px text-xs font-medium whitespace-nowrap', cls]" :title="meta.explain" :data-verification="state">
    {{ verificationLabel(state, name) }}<span v-if="count !== undefined" class="tabular-nums opacity-80">{{ formatNumber(count) }}</span>
  </span>
</template>
