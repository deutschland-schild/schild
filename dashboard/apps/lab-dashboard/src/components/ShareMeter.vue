<script setup lang="ts">
import { formatPercent } from '@schild/ui'
import { computed } from 'vue'
import { MAX_ISSUER_SHARE } from '@/lib/evidence'

/** Largest issuer share with the 34 % limit marked. Text carries the meaning, the bar only magnitude. */
const props = defineProps<{ share: number, compact?: boolean }>()
const over = computed(() => props.share > MAX_ISSUER_SHARE)
</script>

<template>
  <div class="flex items-center gap-2" :title="`Größter Anteil eines Bürgen: ${formatPercent(share)} (Grenze ${formatPercent(MAX_ISSUER_SHARE)})`">
    <div class="relative h-1.5 w-16 shrink-0 overflow-hidden rounded-full bg-muted" aria-hidden="true">
      <div class="h-full rounded-full" :class="over ? 'bg-status-warning' : 'bg-chart-2'" :style="{ width: `${Math.min(100, share * 100)}%` }" />
      <div class="absolute inset-y-0 w-px bg-foreground/60" :style="{ left: `${MAX_ISSUER_SHARE * 100}%` }" />
    </div>
    <span class="tabular-nums text-xs" :class="over ? 'font-medium text-status-warning' : 'text-muted-foreground'">
      {{ formatPercent(share) }}<span v-if="over && !compact"> · über Grenze</span>
    </span>
  </div>
</template>
