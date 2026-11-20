<script setup lang="ts">
import { formatNumber } from '@schild/ui'
import { computed } from 'vue'

const props = defineProps<{ used: number, quota: number }>()
const ratio = computed(() => (props.quota > 0 ? props.used / props.quota : props.used > 0 ? 1 : 0))
</script>

<template>
  <div class="min-w-32 space-y-1">
    <div class="h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden="true">
      <div class="h-full rounded-full" :class="ratio >= 0.9 ? 'bg-status-warning' : 'bg-chart-2'" :style="{ width: `${Math.min(100, ratio * 100)}%` }" />
    </div>
    <p class="text-xs tabular-nums text-muted-foreground">
      {{ formatNumber(used) }} von {{ formatNumber(quota) }}
    </p>
  </div>
</template>
