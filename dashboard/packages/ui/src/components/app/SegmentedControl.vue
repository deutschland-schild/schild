<script setup lang="ts" generic="T extends string">
import type { HTMLAttributes } from 'vue'
import type { SegmentOption } from './types'
import { cn } from '@schild/ui/lib/utils'
import { RadioGroupItem, RadioGroupRoot } from 'reka-ui'
import { computed, useId } from 'vue'

/**
 * Website-style segmented control (rounded pill, active segment raised, no coloured fill):
 * a radio group, so arrow keys move the choice and only the active segment is a tab stop.
 * Disabled options stay visible with a short reason. An option can carry a small mark ("empfohlen").
 */
const props = withDefaults(defineProps<{
  options: SegmentOption<T>[]
  /** Accessible name of the group. */
  label: string
  size?: 'sm' | 'md'
  disabled?: boolean
  /** Show the reasons of disabled options as a small line below. */
  showReasons?: boolean
  class?: HTMLAttributes['class']
}>(), { size: 'sm', disabled: false, showReasons: true, class: undefined })
const model = defineModel<T>({ required: true })
const id = useId()
const reasons = computed(() => props.options.filter(o => o.disabled && o.reason))

// Every tone shows the active segment the same calm way: raised white on the muted track, no dark or coloured fill.
// The tone stays in the API so callers keep their meaning; the look is deliberately uniform (initiator, 2026-10-29).
const calm = 'data-[state=checked]:bg-background data-[state=checked]:text-foreground data-[state=checked]:shadow-sm data-[state=checked]:ring-1 data-[state=checked]:ring-border'
const activeTone: Record<NonNullable<SegmentOption['tone']>, string> = { ink: calm, signal: calm, neutral: calm }
</script>

<template>
  <div :class="cn('inline-grid max-w-full justify-items-start gap-1', props.class)">
    <RadioGroupRoot
      v-model="model"
      :aria-label="label"
      orientation="horizontal"
      :disabled="disabled"
      class="flex max-w-full flex-wrap rounded-full bg-muted p-0.5 ring-1 ring-border"
      data-slot="segmented-control"
    >
      <RadioGroupItem
        v-for="o in options"
        :key="o.value"
        :value="o.value"
        :disabled="o.disabled"
        :aria-describedby="o.disabled && o.reason ? `${id}-${o.value}` : undefined"
        :title="o.disabled ? o.reason : undefined"
        :data-testid="o.testid"
        :data-value="o.value"
        :class="cn(
          'rounded-full font-medium whitespace-nowrap transition-colors outline-none data-[state=checked]:font-semibold',
          'text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring',
          'disabled:cursor-not-allowed disabled:opacity-55 disabled:hover:text-muted-foreground',
          size === 'sm' ? 'min-h-7 px-2.5 text-xs' : 'min-h-8 px-3.5 text-[13px]',
          activeTone[o.tone ?? 'signal'],
        )"
      >
        {{ o.label }} <span v-if="o.mark" class="font-normal opacity-70" data-slot="segment-mark">{{ o.mark }}</span>
      </RadioGroupItem>
    </RadioGroupRoot>
    <p v-if="showReasons && reasons.length" class="text-xs text-muted-foreground">
      <span v-for="(o, i) in reasons" :id="`${id}-${o.value}`" :key="o.value">{{ i ? ' · ' : '' }}{{ o.label }}: {{ o.reason }}</span>
    </p>
    <template v-else>
      <span v-for="o in reasons" :id="`${id}-${o.value}`" :key="o.value" class="sr-only">{{ o.reason }}</span>
    </template>
  </div>
</template>
