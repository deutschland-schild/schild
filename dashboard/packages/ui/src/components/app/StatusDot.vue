<script setup lang="ts">
import type { StatusTone } from './types'
import { cn } from '@schild/ui/lib/utils'

/**
 * A small status dot. Colour is never the only cue: pass `label` (read by screen readers and shown as
 * tooltip) or put the state in words next to it.
 */
const props = withDefaults(defineProps<{ tone?: StatusTone, label?: string, class?: string }>(), { tone: 'neutral', label: undefined, class: undefined })
const dotClass: Record<StatusTone, string> = {
  signal: 'bg-status-signal',
  success: 'bg-status-success',
  warning: 'bg-status-warning',
  danger: 'bg-status-danger',
  info: 'bg-status-info',
  neutral: 'bg-transparent ring-[1.5px] ring-status-neutral ring-inset',
}
</script>

<template>
  <span :class="cn('inline-flex size-2 shrink-0 rounded-full', dotClass[props.tone], props.class)" :title="label" :data-tone="tone" data-slot="status-dot">
    <span v-if="label" class="sr-only">{{ label }}</span>
  </span>
</template>
