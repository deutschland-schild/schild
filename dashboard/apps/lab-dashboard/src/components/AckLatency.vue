<script setup lang="ts">
import type { LabHealth } from '@/api/types'
import { computed } from 'vue'
import { ACK_P99_TARGET_MS } from '@/lib/labels'

/** p50 / p99 / max on one scale with the 50 ms target marked (M6). Numbers are always shown as text. */
const props = defineProps<{ ack: LabHealth['ack_ms'] }>()
const scaleMax = computed(() => Math.max(ACK_P99_TARGET_MS * 1.2, (props.ack.max ?? props.ack.p99) * 1.1))
const pct = (v: number) => `${Math.min(100, (v / scaleMax.value) * 100)}%`
const fmt = (v: number) => `${v.toLocaleString('de-DE', { maximumFractionDigits: 1 })} ms`
const rows = computed(() => [
  { key: 'p50', label: 'p50', value: props.ack.p50 },
  { key: 'p99', label: 'p99', value: props.ack.p99 },
  ...(props.ack.max !== undefined ? [{ key: 'max', label: 'Max', value: props.ack.max }] : []),
])
const over = computed(() => props.ack.p99 >= ACK_P99_TARGET_MS)
</script>

<template>
  <div class="space-y-3">
    <p class="text-sm" :class="over ? 'font-medium text-status-danger' : 'text-muted-foreground'" data-testid="ack-summary">
      <template v-if="over">
        p99 {{ fmt(ack.p99) }} liegt über dem Ziel von {{ ACK_P99_TARGET_MS }} ms.
      </template>
      <template v-else>
        p99 {{ fmt(ack.p99) }} liegt unter dem Ziel von {{ ACK_P99_TARGET_MS }} ms.
      </template>
      <span class="text-muted-foreground"> Gemessen über {{ Math.round(ack.window_s / 60) || ack.window_s }} {{ ack.window_s >= 60 ? 'min' : 's' }}.</span>
    </p>
    <div class="relative space-y-2">
      <div v-for="r in rows" :key="r.key" class="grid grid-cols-[3rem_1fr_5rem] items-center gap-2 text-sm">
        <span class="text-muted-foreground">{{ r.label }}</span>
        <div class="relative h-2 rounded-full bg-muted" aria-hidden="true">
          <div class="h-full rounded-full" :class="r.value >= ACK_P99_TARGET_MS ? 'bg-status-danger' : 'bg-chart-1'" :style="{ width: pct(r.value) }" />
        </div>
        <span class="text-right tabular-nums">{{ fmt(r.value) }}</span>
      </div>
      <div class="pointer-events-none absolute inset-y-0 left-[3.5rem] right-[5.5rem]" aria-hidden="true">
        <div class="absolute -top-1 -bottom-1 w-0 border-l-2 border-dashed border-status-warning" :style="{ left: pct(ACK_P99_TARGET_MS) }" />
      </div>
    </div>
    <p class="text-xs text-muted-foreground">
      Gestrichelte Linie: Ziel {{ ACK_P99_TARGET_MS }} ms.
    </p>
  </div>
</template>
