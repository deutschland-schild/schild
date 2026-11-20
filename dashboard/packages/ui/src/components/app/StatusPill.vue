<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import type { StatusTone } from './types'
import { cn } from '@schild/ui/lib/utils'
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  tone?: StatusTone
  /** Show a coloured dot before the label (colour is never the only cue: the label carries meaning). */
  dot?: boolean
  /** Gentle pulse on the dot, disabled with prefers-reduced-motion. */
  pulse?: boolean
  size?: 'sm' | 'md'
  class?: HTMLAttributes['class']
}>(), { tone: 'neutral', dot: true, pulse: false, size: 'md', class: undefined })

const toneClass: Record<StatusTone, string> = {
  signal: 'bg-status-signal-subtle text-status-signal-text border-status-signal/40',
  success: 'bg-status-success-subtle text-status-success border-status-success/30',
  warning: 'bg-status-warning-subtle text-status-warning border-status-warning/30',
  danger: 'bg-status-danger-subtle text-status-danger border-status-danger/30',
  info: 'bg-status-info-subtle text-status-info border-status-info/30',
  neutral: 'bg-status-neutral-subtle text-status-neutral border-border',
}
const dotClass: Record<StatusTone, string> = {
  signal: 'bg-status-signal',
  success: 'bg-status-success',
  warning: 'bg-status-warning',
  danger: 'bg-status-danger',
  info: 'bg-status-info',
  neutral: 'bg-status-neutral',
}
const classes = computed(() => cn(
  'inline-flex items-center gap-1.5 rounded-full border font-medium whitespace-nowrap',
  props.size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs',
  toneClass[props.tone],
  props.class,
))
</script>

<template>
  <span :class="classes" :data-tone="tone">
    <span v-if="dot" class="relative flex size-2" aria-hidden="true">
      <span v-if="pulse" :class="cn('absolute inline-flex size-full rounded-full opacity-60 motion-safe:animate-ping', dotClass[tone])" />
      <span :class="cn('relative inline-flex size-2 rounded-full', dotClass[tone])" />
    </span>
    <slot />
  </span>
</template>
