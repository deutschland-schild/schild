<script setup lang="ts">
import type { MaybeNumber } from '@schild/ui/lib/chart'
import { bandPath, describeTrend, gapLinePath } from '@schild/ui/lib/chart'
import { formatNumber } from '@schild/ui/lib/format'
import { computed, useId } from 'vue'

/**
 * Small trend line for stat tiles: a thin line on a soft wash, zero-based, straight segments.
 * Gaps (null) stay gaps, so a missing stretch is not drawn as a jump and the time axis keeps its scale.
 */
const props = withDefaults(defineProps<{
  values: MaybeNumber[]
  /** Accessible name, e.g. "Abgewehrte Anfragen, letzte 24 Stunden". */
  label: string
  /** CSS colour; defaults to the main monitoring tone. */
  color?: string
  width?: number
  height?: number
  area?: boolean
}>(), { color: 'var(--tone-main)', width: 120, height: 32, area: true })

const gradientId = `spark-${useId()}`
const pad = 2
const nums = computed(() => props.values.filter((v): v is number => typeof v === 'number' && Number.isFinite(v)))
const top = computed(() => Math.max(0, ...nums.value) || 1)
const xOf = (i: number) => pad + (props.values.length > 1 ? (i * (props.width - pad * 2)) / (props.values.length - 1) : (props.width - pad * 2) / 2)
const yOf = (v: number) => pad + (props.height - 2 * pad) * (1 - v / top.value)
const line = computed(() => gapLinePath(props.values, xOf, yOf))
const fill = computed(() => bandPath([], props.values, xOf, yOf))
const last = computed(() => {
  for (let i = props.values.length - 1; i >= 0; i--) {
    const v = props.values[i]
    if (typeof v === 'number' && Number.isFinite(v)) return { x: xOf(i), y: yOf(v) }
  }
  return null
})
const summary = computed(() => `${props.label}: ${nums.value.length ? describeTrend(nums.value, formatNumber) : 'keine Daten'}`)
</script>

<template>
  <svg
    :viewBox="`0 0 ${width} ${height}`"
    :width="width"
    :height="height"
    role="img"
    :aria-label="summary"
    class="block max-w-full overflow-visible"
    preserveAspectRatio="none"
  >
    <title>{{ summary }}</title>
    <defs>
      <linearGradient :id="gradientId" x1="0" x2="0" y1="0" y2="1">
        <stop offset="0%" :stop-color="color" stop-opacity="0.16" />
        <stop offset="100%" :stop-color="color" stop-opacity="0" />
      </linearGradient>
    </defs>
    <path v-if="area && nums.length > 1" :d="fill" :fill="`url(#${gradientId})`" />
    <path v-if="nums.length > 1" :d="line" fill="none" :stroke="color" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke" />
    <circle v-if="last" :cx="last.x" :cy="last.y" r="2.5" :fill="color" class="stroke-card" stroke-width="1.5" />
  </svg>
</template>
