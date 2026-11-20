<script setup lang="ts">
import type { TimeSeries } from './types'
import { Button } from '@schild/ui/components/ui/button'
import { bandPath, gapLinePath, seriesStats, stackLayers, stackTotal, timeTicks, yScale } from '@schild/ui/lib/chart'
import { formatCompact, formatNumber } from '@schild/ui/lib/format'
import { useElementSize } from '@vueuse/core'
import { computed, ref, useId, useTemplateRef } from 'vue'

/**
 * Time series chart for monitoring (MVP-21): stacked areas and lines on one y-axis, straight segments
 * between buckets (no smoothing, so nothing overshoots), gaps (null) drawn as gaps, thin restart markers,
 * crosshair and tooltip by mouse and arrow keys, a summary as accessible name and an "Als Tabelle zeigen"
 * toggle with the same data. A stack of two or more series gets a 2px total line on top and a "Gesamt"
 * row in tooltip and table. No animation, no chart library.
 */
const props = withDefaults(defineProps<{
  series: TimeSeries[]
  /** Short x labels, one per step ("14:00"). */
  labels: string[]
  /** Longer labels for tooltip and table ("Mi., 14:00"); defaults to labels. */
  longLabels?: string[]
  /** Start of each step (ms); puts x ticks on round local times. Without it ticks are spaced evenly. */
  times?: number[]
  /** Accessible name and table caption ("Anfragen pro Sekunde"). */
  label: string
  /** Sentence for screen readers; default: mean and maximum of the first series. */
  summary?: string
  height?: number
  format?: (n: number) => string
  axisFormat?: (n: number) => string
  /** Fixed top of the y-axis (e.g. 1 for ratios). */
  max?: number
  /** Thin vertical markers, e.g. restarts ("Neustart von Schild"). */
  markers?: { index: number, label: string }[]
  /** Name and colour of the stack total. */
  totalLabel?: string
  totalColor?: string
}>(), {
  height: 200,
  format: formatNumber,
  axisFormat: formatCompact,
  longLabels: undefined,
  times: undefined,
  summary: undefined,
  max: undefined,
  markers: () => [],
  totalLabel: 'Gesamt',
  totalColor: 'var(--tone-main)',
})

const root = useTemplateRef<HTMLElement>('root')
const { width: measured } = useElementSize(root)
const width = computed(() => Math.max(280, Math.round(measured.value || 600)))
const innerH = computed(() => props.height - 10 - 24)
const uid = useId()
const showTable = ref(false)

const colorOf = (s: TimeSeries, i: number) => s.color ?? `var(--chart-${s.slot ?? ((i % 5) + 1)})`
const stacked = computed(() => props.series.filter(s => s.stack))
const bands = computed(() => stackLayers(stacked.value.map(s => s.values)))
const count = computed(() => Math.max(0, ...props.series.map(s => s.values.length), props.labels.length))
/** Total of the stack: drawn as a line and listed first in tooltip and table (two or more layers). */
const hasTotal = computed(() => stacked.value.length >= 2)
const totalValues = computed(() => Array.from({ length: count.value }, (_, i) => stackTotal(stacked.value.map(s => s.values), i)))

const scale = computed(() => {
  const vals: number[] = []
  for (const b of bands.value) for (const v of b.hi) if (v !== null) vals.push(v)
  for (const s of props.series) if (!s.stack) for (const v of s.values) if (typeof v === 'number') vals.push(v)
  if (props.max !== undefined) vals.push(props.max)
  return yScale(vals, 3)
})
// The left margin fits the widest tick label (about 6 px per character at 10 px).
const margin = computed(() => ({ top: 10, right: 8, bottom: 24, left: Math.max(36, 12 + 6 * Math.max(...scale.value.ticks.map(t => props.axisFormat(t).length))) }))
const innerW = computed(() => width.value - margin.value.left - margin.value.right)
const yOf = (v: number) => innerH.value * (1 - Math.min(v, scale.value.max) / scale.value.max)
const xOf = (i: number) => count.value > 1 ? (i * innerW.value) / (count.value - 1) : innerW.value / 2
const xTicks = computed(() => timeTicks(props.times ?? [], innerW.value / 96, count.value).filter(i => i < props.labels.length))
const anchorOf = (i: number) => xOf(i) < 24 ? 'start' : xOf(i) > innerW.value - 24 ? 'end' : 'middle'

const areas = computed(() => stacked.value.map((s, k) => {
  const b = bands.value[k]!
  return { s, color: colorOf(s, props.series.indexOf(s)), d: bandPath(b.lo, b.hi, xOf, yOf) }
}))
/** 1px surface-coloured seams between the bands (the gap that separates neighbours, no outline). */
const seams = computed(() => bands.value.slice(1).map(b => gapLinePath(b.lo, xOf, yOf)))
const topLine = computed(() => {
  const last = bands.value[bands.value.length - 1]
  if (!last) return null
  const only = stacked.value.length === 1 ? stacked.value[0]! : null
  return { d: gapLinePath(last.hi, xOf, yOf), color: only ? colorOf(only, props.series.indexOf(only)) : props.totalColor }
})
// Lines with a wash (the one the chart is about) are drawn last, so a neighbour never hides them.
const lines = computed(() => props.series.filter(s => !s.stack).sort((a, b) => Number(!!a.fill) - Number(!!b.fill)).map(s => ({
  s,
  color: colorOf(s, props.series.indexOf(s)),
  d: gapLinePath(s.values, xOf, yOf),
  fill: s.fill ? bandPath([], s.values, xOf, yOf) : '',
})))
const legend = computed(() => props.series.map((s, i) => ({ s, color: colorOf(s, i) })))

const tip = (i: number) => (props.longLabels ?? props.labels)[i] ?? ''
const valueText = (v: number | null | undefined) => typeof v === 'number' && Number.isFinite(v) ? props.format(v) : 'keine Daten'

const ariaSummary = computed(() => {
  if (props.summary) return props.summary
  const first = props.series[0]
  const values = hasTotal.value ? totalValues.value : first?.values
  const st = values ? seriesStats(values) : null
  if (!values || !st) return `${props.label}: noch keine Daten`
  // A stack is summarised by its total (what the chart title counts), a line chart by its first line.
  return `${props.label}: im Mittel ${props.format(st.mean)}, höchstens ${props.format(st.max)} um ${tip(st.maxIndex)}`
})

const active = ref<number | null>(null)
function onPointer(e: PointerEvent) {
  const svg = e.currentTarget as SVGSVGElement
  const rect = svg.getBoundingClientRect()
  const x = ((e.clientX - rect.left) / rect.width) * width.value - margin.value.left
  if (count.value < 1) return
  const i = Math.round((x / innerW.value) * (count.value - 1))
  active.value = Math.min(count.value - 1, Math.max(0, i))
}
function onKey(e: KeyboardEvent) {
  if (count.value < 1) return
  const cur = active.value ?? -1
  const page = Math.max(1, Math.round(count.value / 12))
  if (e.key === 'ArrowRight') active.value = Math.min(count.value - 1, cur + 1)
  else if (e.key === 'ArrowLeft') active.value = Math.max(0, cur < 0 ? count.value - 1 : cur - 1)
  else if (e.key === 'PageUp') active.value = Math.min(count.value - 1, Math.max(0, cur) + page)
  else if (e.key === 'PageDown') active.value = Math.max(0, (cur < 0 ? count.value - 1 : cur) - page)
  else if (e.key === 'Home') active.value = 0
  else if (e.key === 'End') active.value = count.value - 1
  else if (e.key === 'Escape') active.value = null
  else return
  e.preventDefault()
}
const tooltipLeft = computed(() => active.value === null ? 0 : ((margin.value.left + xOf(active.value)) / width.value) * 100)
/** The tooltip sits beside the crosshair (right of it, left of it in the right half), never over the marker. */
const tooltipStyle = computed(() => tooltipLeft.value > 55
  ? { right: `calc(${100 - tooltipLeft.value}% + 12px)` }
  : { left: `calc(${tooltipLeft.value}% + 12px)` })
const pointOf = (values: (number | null | undefined)[], i: number) => {
  const v = values[i]
  return typeof v === 'number' && Number.isFinite(v) ? { x: xOf(i), y: yOf(v) } : null
}
/** Hover markers: one neutral dot on the stack top (never a layer colour), one per line in its colour. */
const hoverDots = computed(() => {
  const i = active.value
  if (i === null) return []
  const out: { key: string, x: number, y: number, color: string | null }[] = []
  const last = bands.value[bands.value.length - 1]
  const top = last ? pointOf(last.hi, i) : null
  if (top) out.push({ key: 'stack', ...top, color: null })
  for (const l of lines.value) {
    const p = pointOf(l.s.values, i)
    if (p) out.push({ key: l.s.id, ...p, color: l.color })
  }
  return out
})
</script>

<template>
  <figure class="w-full min-w-0" data-slot="time-chart">
    <div class="mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
      <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-hidden="true">
        <span v-if="hasTotal" class="inline-flex items-center gap-1.5">
          <span class="h-0.5 w-3 rounded-full" :style="{ background: totalColor }" />
          {{ totalLabel }}
        </span>
        <span v-for="l in legend" :key="l.s.id" class="inline-flex items-center gap-1.5">
          <span v-if="l.s.stack" class="size-2.5 rounded-[3px] ring-1 ring-foreground/10 ring-inset" :style="{ background: l.color }" />
          <span v-else-if="l.s.dashed" class="h-0 w-3 border-t-2 border-dashed" :style="{ borderColor: l.color }" />
          <span v-else class="h-0.5 w-3 rounded-full" :style="{ background: l.color }" />
          {{ l.s.label }}
        </span>
      </div>
      <Button variant="link" size="sm" class="h-auto p-0 text-xs" :aria-expanded="showTable" :aria-controls="`${uid}-table`" @click="showTable = !showTable">
        {{ showTable ? 'Als Diagramm zeigen' : 'Als Tabelle zeigen' }}
      </Button>
    </div>
    <div v-show="!showTable" ref="root" class="relative w-full">
      <svg
        :viewBox="`0 0 ${width} ${height}`"
        :height="height"
        class="block w-full rounded-md focus-visible:outline-2 focus-visible:outline-ring"
        role="img"
        :aria-label="ariaSummary"
        tabindex="0"
        @pointermove="onPointer"
        @pointerleave="active = null"
        @keydown="onKey"
        @blur="active = null"
      >
        <g :transform="`translate(${margin.left},${margin.top})`">
          <g class="text-muted-foreground">
            <g v-for="t in scale.ticks" :key="t">
              <line :x1="0" :x2="innerW" :y1="yOf(t)" :y2="yOf(t)" class="stroke-border" stroke-width="1" shape-rendering="crispEdges" />
              <text :x="-8" :y="yOf(t)" dy="0.32em" text-anchor="end" class="fill-current text-[10px] tabular-nums">{{ axisFormat(t) }}</text>
            </g>
            <text v-for="i in xTicks" :key="`x${i}`" :x="xOf(i)" :y="innerH + 16" :text-anchor="anchorOf(i)" class="fill-current text-[10px] tabular-nums" data-slot="x-tick">{{ labels[i] }}</text>
          </g>
          <path v-for="a in areas" :key="a.s.id" :d="a.d" :fill="a.color" :data-series="a.s.id" />
          <path v-for="(d, k) in seams" :key="`seam${k}`" :d="d" fill="none" class="stroke-card" stroke-width="1" />
          <path v-if="topLine" :d="topLine.d" fill="none" :stroke="topLine.color" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" data-slot="total-line" />
          <template v-for="l in lines" :key="l.s.id">
            <path v-if="l.fill" :d="l.fill" :fill="l.color" fill-opacity="0.1" />
            <path
              :d="l.d"
              fill="none"
              :stroke="l.color"
              stroke-width="2"
              stroke-linejoin="round"
              stroke-linecap="round"
              :stroke-dasharray="l.s.dashed ? '5 4' : undefined"
              :data-series="l.s.id"
            />
          </template>
          <g v-for="m in markers" :key="`m${m.index}`" class="text-muted-foreground" data-slot="marker">
            <line :x1="xOf(m.index)" :x2="xOf(m.index)" :y1="0" :y2="innerH" stroke="currentColor" stroke-width="1" stroke-dasharray="2 3" />
            <title>{{ m.label }} · {{ tip(m.index) }}</title>
          </g>
          <g v-if="active !== null" data-slot="crosshair">
            <line :x1="xOf(active)" :x2="xOf(active)" :y1="0" :y2="innerH" class="stroke-foreground" stroke-opacity="0.3" stroke-width="1" />
            <circle
              v-for="p in hoverDots"
              :key="p.key"
              :cx="p.x"
              :cy="p.y"
              r="4"
              :fill="p.color ?? 'var(--card)'"
              :class="p.color ? 'stroke-card' : 'stroke-foreground'"
              stroke-width="2"
              :data-dot="p.key"
            />
          </g>
        </g>
      </svg>
      <div
        v-if="active !== null"
        class="pointer-events-none absolute top-0 z-10 min-w-44 rounded-md border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md"
        :style="tooltipStyle"
        aria-live="polite"
        data-slot="tooltip"
      >
        <p class="mb-1.5 text-muted-foreground">
          {{ tip(active) }}
        </p>
        <p v-if="hasTotal" class="mb-1 flex items-center justify-between gap-4 border-b pb-1" data-slot="tooltip-total">
          <span class="inline-flex items-center gap-1.5 text-muted-foreground"><span class="h-0.5 w-3 rounded-full" :style="{ background: totalColor }" />{{ totalLabel }}</span>
          <span class="font-semibold tabular-nums">{{ valueText(totalValues[active]) }}</span>
        </p>
        <p v-for="l in legend" :key="l.s.id" class="flex items-center justify-between gap-4">
          <span class="inline-flex items-center gap-1.5 text-muted-foreground">
            <span v-if="l.s.stack" class="size-2 rounded-[2px] ring-1 ring-foreground/10 ring-inset" :style="{ background: l.color }" />
            <span v-else-if="l.s.dashed" class="h-0 w-3 border-t-2 border-dashed" :style="{ borderColor: l.color }" />
            <span v-else class="h-0.5 w-3 rounded-full" :style="{ background: l.color }" />
            {{ l.s.label }}
          </span>
          <span class="font-medium tabular-nums">{{ valueText(l.s.values[active]) }}</span>
        </p>
        <p v-for="m in markers.filter(x => x.index === active)" :key="m.index" class="mt-1 text-muted-foreground">
          {{ m.label }}
        </p>
      </div>
    </div>
    <div v-show="showTable" class="max-h-80 overflow-auto rounded-md border">
      <table :id="`${uid}-table`" class="w-full text-left text-xs tabular-nums">
        <caption class="sr-only">
          {{ label }}
        </caption>
        <thead class="sticky top-0 bg-card">
          <tr>
            <th scope="col" class="px-2 py-1.5 font-medium">
              Zeitpunkt
            </th>
            <th v-if="hasTotal" scope="col" class="px-2 py-1.5 text-right font-medium">
              {{ totalLabel }}
            </th>
            <th v-for="s in series" :key="s.id" scope="col" class="px-2 py-1.5 text-right font-medium">
              {{ s.label }}
            </th>
          </tr>
        </thead>
        <tbody v-if="showTable">
          <tr v-for="(_, i) in labels" :key="i" class="border-t">
            <th scope="row" class="px-2 py-1 font-normal text-muted-foreground">
              {{ tip(i) }}<template v-for="m in markers.filter(x => x.index === i)" :key="m.index">
                · {{ m.label }}
              </template>
            </th>
            <td v-if="hasTotal" class="px-2 py-1 text-right font-medium">
              {{ valueText(totalValues[i]) }}
            </td>
            <td v-for="s in series" :key="s.id" class="px-2 py-1 text-right">
              {{ valueText(s.values[i]) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <figcaption v-if="$slots.caption" class="mt-2 text-xs text-muted-foreground">
      <slot name="caption" />
    </figcaption>
  </figure>
</template>
