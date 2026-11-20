<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { cn } from '@schild/ui/lib/utils'

/**
 * Green-tinted band at the bottom of a panel that sums up the effect of a choice
 * (website: "Probelauf mit den letzten 24 Stunden: …") with the actions on the right
 * (ink primary, outline secondary). Optional small footnote row below.
 */
const props = withDefaults(defineProps<{
  /** Announce text changes politely (for summaries that follow a selection). */
  live?: boolean
  class?: HTMLAttributes['class']
}>(), { live: false, class: undefined })
</script>

<template>
  <div data-slot="effect-footer" :class="cn('border-t', props.class)">
    <div class="flex flex-wrap items-center justify-between gap-x-6 gap-y-3 bg-status-signal-subtle px-4 py-3.5 sm:px-5">
      <div class="min-w-0 flex-1 basis-72 text-sm leading-snug text-pretty" :aria-live="live ? 'polite' : undefined">
        <slot />
      </div>
      <div v-if="$slots.actions" class="flex flex-wrap items-center gap-2">
        <slot name="actions" />
      </div>
    </div>
    <p v-if="$slots.note" class="border-t bg-card px-4 py-2.5 text-xs text-muted-foreground sm:px-5">
      <slot name="note" />
    </p>
  </div>
</template>
