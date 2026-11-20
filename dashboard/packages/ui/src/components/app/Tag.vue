<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import type { StatusTone } from './types'
import { cn } from '@schild/ui/lib/utils'

/** Small bold inline badge next to a title (website: "Probelauf" in warning tones). */
const props = withDefaults(defineProps<{ tone?: StatusTone, class?: HTMLAttributes['class'] }>(), { tone: 'neutral', class: undefined })
const toneClass: Record<StatusTone, string> = {
  signal: 'bg-status-signal-subtle text-status-signal-text',
  success: 'bg-status-success-subtle text-status-success',
  warning: 'bg-status-warning-subtle text-status-warning',
  danger: 'bg-status-danger-subtle text-status-danger',
  info: 'bg-status-info-subtle text-status-info',
  neutral: 'bg-secondary text-muted-foreground',
}
</script>

<template>
  <span data-slot="tag" :data-tone="tone" :class="cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 align-middle text-[11px] leading-4 font-bold whitespace-nowrap', toneClass[tone], props.class)">
    <slot />
  </span>
</template>
