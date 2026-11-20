<script setup lang="ts">
import type { ChartSeries } from './types'
import { areaPath, linePath, toPoints, yScale } from '@schild/ui/lib/chart'
import { formatCompact, formatNumber } from '@schild/ui/lib/format'
import { useElementSize } from '@vueuse/core'
import { computed, ref, useId, useTemplateRef } from 'vue'

/**
 * Line/area chart over time. One y-axis, thin 2px lines, recessive grid,
 * crosshair + tooltip on hover and keyboard (arrow keys), legend for >= 2 series,
 * and a screen-reader table with all values.
 */
const props = withDefaults(defineProps<{
  series: ChartSeries[]
  /** One label per x position (e.g. "14:00"). */
  labels: string[]
  /** Accessible name / caption. */
  label: string
  height?: number
  /** Fill under the lines (only for a single series to avoid overdraw). */
  area?: boolean
  format?: (n: number) => string
}>(), { height: 220, area: true, format: formatNumber })

const root = useTemplateRef<HTMLElement>('root')
const { width: measured } = useElementSize(root)
const width = computed(() => Math.max(280, Math.round(measured.value || 600)))
const margin = { top: 8, right: 8, bottom: 24, left: 40 }
const innerW = computed(() => width.value - margin.left - margin.right)
const innerH = computed(() => props.height - margin.top - margin.bottom)
const scale = computed(() => yScale(props.series.flatMap(s => s.values)))
const uid = useId()

const colorOf = (s: ChartSeries, i: number) => `var(--chart-${s.slot ?? ((i % 5) + 1)})`
const lines = computed(() => props.series.map((s, i) => {
  const pts = toPoints(s.values, innerW.value, innerH.value, scale.value.max)
  return { s, color: colorOf(s, i), pts, line: linePath(pts), fill: areaPath(pts, innerH.value) }
}))
const yOf = (v: number) => innerH.value * (1 - v / scale.value.max)
const count = computed(() => Math.max(0, ...props.series.map(s => s.values.length)))
const xOf = (i: number) => count.value > 1 ? (i * innerW.value) / (count.value - 1) : innerW.value / 2
const labelEvery = computed(() => Math.max(1, Math.ceil(count.value / Math.max(2, Math.floor(innerW.value / 72)))))

const active = ref<number | null>(null)
function onPointer(e: PointerEvent) {
  const svg = e.currentTarget as SVGSVGElement
  const rect = svg.getBoundingClientRect()
  const x = ((e.clientX - rect.left) / rect.width) * width.value - margin.left
  if (count.value < 1) return
  const i = Math.round((x / innerW.value) * (count.value - 1))
  active.value = Math.min(count.value - 1, Math.max(0, i))
}
function onKey(e: KeyboardEvent) {
  if (count.value < 1) return
  const cur = active.value ?? -1
  if (e.key === 'ArrowRight') active.value = Math.min(count.value - 1, cur + 1)
  else if (e.key === 'ArrowLeft') active.value = Math.max(0, cur < 0 ? count.value - 1 : cur - 1)
  else if (e.key === 'Home') active.value = 0
  else if (e.key === 'End') active.value = count.value - 1
  else if (e.key === 'Escape') active.value = null
  else return
  e.preventDefault()
}
const tooltipLeft = computed(() => active.value === null ? 0 : ((margin.left + xOf(active.value)) / width.value) * 100)
</script>

<template>
  <figure class="w-full">
    <div v-if="series.length > 1" class="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-hidden="true">
      <span v-for="l in lines" :key="l.s.id" class="inline-flex items-center gap-1.5">
        <span class="h-0.5 w-3 rounded-full" :style="{ background: l.color }" />{{ l.s.label }}
      </span>
    </div>
    <div ref="root" class="relative w-full">
      <svg
        :viewBox="`0 0 ${width} ${height}`"
        :height="height"
        class="block w-full rounded-md focus-visible:outline-2 focus-visible:outline-ring"
        role="img"
        :aria-label="label"
        :aria-describedby="`${uid}-table`"
        tabindex="0"
        @pointermove="onPointer"
        @pointerleave="active = null"
        @keydown="onKey"
        @blur="active = null"
      >
        <g :transform="`translate(${margin.left},${margin.top})`">
          <g class="text-muted-foreground">
            <g v-for="t in scale.ticks" :key="t">
              <line :x1="0" :x2="innerW" :y1="yOf(t)" :y2="yOf(t)" stroke="currentColor" stroke-opacity="0.15" />
              <text :x="-8" :y="yOf(t)" dy="0.32em" text-anchor="end" class="fill-current text-[10px] tabular-nums">{{ formatCompact(t) }}</text>
            </g>
            <template v-for="(l, i) in labels" :key="i">
              <text v-if="i % labelEvery === 0" :x="xOf(i)" :y="innerH + 16" :text-anchor="i === 0 ? 'start' : i === labels.length - 1 ? 'end' : 'middle'" class="fill-current text-[10px]">{{ l }}</text>
            </template>
          </g>
          <template v-for="l in lines" :key="l.s.id">
            <path v-if="area && series.length === 1" :d="l.fill" :fill="l.color" fill-opacity="0.12" />
            <path :d="l.line" fill="none" :stroke="l.color" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
          </template>
          <g v-if="active !== null">
            <line :x1="xOf(active)" :x2="xOf(active)" :y1="0" :y2="innerH" class="stroke-foreground" stroke-opacity="0.35" stroke-dasharray="3 3" />
            <template v-for="l in lines" :key="l.s.id">
              <circle v-if="l.pts[active]" :cx="l.pts[active]!.x" :cy="l.pts[active]!.y" r="4" :fill="l.color" class="stroke-card" stroke-width="2" />
            </template>
          </g>
        </g>
      </svg>
      <div
        v-if="active !== null"
        class="pointer-events-none absolute top-0 z-10 min-w-32 -translate-x-1/2 rounded-md border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md"
        :style="{ left: `clamp(4rem, ${tooltipLeft}%, calc(100% - 4rem))` }"
        aria-live="polite"
      >
        <p class="mb-1 font-medium">
          {{ labels[active] }}
        </p>
        <p v-for="l in lines" :key="l.s.id" class="flex items-center justify-between gap-3">
          <span class="inline-flex items-center gap-1.5 text-muted-foreground"><span class="size-2 rounded-full" :style="{ background: l.color }" />{{ l.s.label }}</span>
          <span class="font-medium tabular-nums">{{ format(l.s.values[active] ?? 0) }}</span>
        </p>
      </div>
    </div>
    <figcaption v-if="$slots.caption" class="mt-2 text-xs text-muted-foreground">
      <slot name="caption" />
    </figcaption>
    <table :id="`${uid}-table`" class="sr-only">
      <caption>{{ label }}</caption>
      <thead>
        <tr>
          <th scope="col">
            Zeitpunkt
          </th>
          <th v-for="s in series" :key="s.id" scope="col">
            {{ s.label }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(l, i) in labels" :key="i">
          <th scope="row">
            {{ l }}
          </th>
          <td v-for="s in series" :key="s.id">
            {{ format(s.values[i] ?? 0) }}
          </td>
        </tr>
      </tbody>
    </table>
  </figure>
</template>
