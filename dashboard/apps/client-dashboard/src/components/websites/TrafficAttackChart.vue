<script setup lang="ts">
import { bandPath, Button, formatCompact, formatNumber, gapLinePath, timeTicks, yScale } from '@schild/ui'
import { computed, onBeforeUnmount, onMounted, ref, useId, useTemplateRef } from 'vue'
import { TONES } from '@/lib/monitoring'
import { ANNOTATION_RANK, groupMarkers } from '@/lib/websites'

/**
 * Main chart of the website overview (D36): traffic on top (calm line with a soft wash) and a narrow
 * "Alarme" band below on the same time axis with its own scale (gestoppt dark, erkannt lighter),
 * so a wave or a spike shows at a glance without a dual y-axis. One crosshair and tooltip for both.
 * The last point while still counting (partial) is drawn dashed. Markers (waves, blocks, config, restarts,
 * gaps) sit on the axis and link to their details. "Als Tabelle zeigen" lists the same numbers.
 */
export interface ChartMarker {
  index: number
  label: string
  glyph: string
  to: string | null
  /** Shaded until this index (a monitoring gap). */
  untilIndex?: number
  kind: string
}

const props = withDefaults(defineProps<{
  /** Start of each point (ms). */
  times: number[]
  labels: string[]
  longLabels: string[]
  values: (number | null)[]
  partial?: boolean[]
  stopped: (number | null)[]
  would: (number | null)[]
  /** Accessible name and legend ("Anfragen pro Minute"). */
  label: string
  attacksLabel?: string
  format?: (n: number) => string
  axisFormat?: (n: number) => string
  attackFormat?: (n: number) => string
  /** Fixed top of the y-axis (ratios). */
  max?: number
  markers?: ChartMarker[]
  height?: number
  /** Why "erkannt" came through (would_block_reason; one text for a bin, e.g. "Erkannt, aber durchgelassen: Testprofil"). */
  wouldNote?: string
}>(), {
  partial: () => [],
  attacksLabel: 'Alarme',
  format: formatNumber,
  axisFormat: formatCompact,
  attackFormat: formatNumber,
  max: undefined,
  markers: () => [],
  height: 300,
  wouldNote: undefined,
})

const root = useTemplateRef<HTMLElement>('root')
const measured = ref(0)
let observer: ResizeObserver | undefined
onMounted(() => {
  if (!root.value) return
  measured.value = root.value.clientWidth
  if (typeof ResizeObserver === 'undefined') return
  observer = new ResizeObserver(entries => (measured.value = entries[0]?.contentRect.width ?? measured.value))
  observer.observe(root.value)
})
onBeforeUnmount(() => observer?.disconnect())
const width = computed(() => Math.max(300, Math.round(measured.value || 640)))
const uid = useId()
const showTable = ref(false)

const BAND_H = 56
const GAP = 14
const MARKER_ROW = 24
const PAD = 8
const topH = computed(() => props.height - MARKER_ROW - GAP - BAND_H - 22 - PAD)
const count = computed(() => Math.max(props.values.length, props.labels.length))

const scale = computed(() => {
  const vals = props.values.filter((v): v is number => typeof v === 'number')
  if (props.max !== undefined) vals.push(props.max)
  return yScale(vals, 3)
})
const attackTotal = computed(() => Array.from({ length: count.value }, (_, i) => {
  const s = props.stopped[i]
  const w = props.would[i]
  return typeof s === 'number' || typeof w === 'number' ? (s ?? 0) + (w ?? 0) : null
}))
const attackMax = computed(() => yScale(attackTotal.value.filter((v): v is number => v !== null), 1).max)

const margin = computed(() => ({ left: Math.max(40, 12 + 6 * Math.max(...scale.value.ticks.map(t => props.axisFormat(t).length), props.attackFormat(attackMax.value).length)), right: 10 }))
const innerW = computed(() => width.value - margin.value.left - margin.value.right)
const xOf = (i: number) => count.value > 1 ? (i * innerW.value) / (count.value - 1) : innerW.value / 2
const yOf = (v: number) => topH.value * (1 - Math.min(v, scale.value.max) / scale.value.max)
const bandTop = computed(() => topH.value + GAP)
const bandY = (v: number) => BAND_H * (Math.min(v, attackMax.value) / attackMax.value)
const xTicks = computed(() => timeTicks(props.times, innerW.value / 96, count.value).filter(i => i < props.labels.length))
const anchorOf = (i: number) => xOf(i) < 24 ? 'start' : xOf(i) > innerW.value - 24 ? 'end' : 'middle'

const isPartial = (i: number) => !!props.partial[i]
/** Complete points as a solid line; the stretch into a partial point dashed. */
const solid = computed(() => props.values.map((v, i) => isPartial(i) ? null : v))
const dashed = computed(() => props.values.map((v, i) => isPartial(i) || isPartial(i + 1) ? v : null))
const linePath = computed(() => gapLinePath(solid.value, xOf, yOf))
const dashPath = computed(() => props.partial.some(Boolean) ? gapLinePath(dashed.value, xOf, yOf) : '')
const fillPath = computed(() => bandPath([], props.values, xOf, yOf))

const barW = computed(() => Math.max(1, innerW.value / Math.max(1, count.value) - (count.value > 120 ? 0 : 1)))
const bars = computed(() => attackTotal.value.map((_, i) => {
  const s = props.stopped[i] ?? 0
  const w = props.would[i] ?? 0
  if (s + w <= 0) return null
  const x = xOf(i) - barW.value / 2
  const hs = bandY(s)
  const hw = bandY(s + w) - hs
  return { i, x, hs, hw, partial: isPartial(i) }
}).filter(b => b !== null))

/**
 * Marker chips: markers closer than 26 px share one chip (the most important kind names it, the count
 * says how many), and every chip stays inside the plot, so a dense attack never runs out of the page.
 */
interface MarkerChip { left: string, lead: ChartMarker, items: ChartMarker[], title: string }
const rank = (m: ChartMarker) => {
  const r = ANNOTATION_RANK.indexOf(m.kind as typeof ANNOTATION_RANK[number])
  return r < 0 ? ANNOTATION_RANK.length : r
}
const chips = computed<MarkerChip[]>(() => groupMarkers(
  props.markers.map(m => ({ x: margin.value.left + xOf(m.index), item: m })),
  26,
  12,
  width.value - 12,
).map((g) => {
  const lead = [...g.items].sort((a, b) => rank(a) - rank(b))[0]!
  const names = g.items.slice(0, 6).map(m => `${m.label} · ${props.longLabels[m.index] ?? ''}`)
  if (g.items.length > 6) names.push(`und ${g.items.length - 6} weitere`)
  return { left: `${(g.x / width.value) * 100}%`, lead, items: g.items, title: names.join('\n') }
}))
const gaps = computed(() => props.markers.filter(m => m.untilIndex !== undefined && m.untilIndex > m.index))

// ---------------------------------------------------------------- hover
const active = ref<number | null>(null)
function onPointer(e: PointerEvent) {
  const svg = e.currentTarget as SVGSVGElement
  const rect = svg.getBoundingClientRect()
  const x = ((e.clientX - rect.left) / rect.width) * width.value - margin.value.left
  if (count.value < 1) return
  active.value = Math.min(count.value - 1, Math.max(0, Math.round((x / innerW.value) * (count.value - 1))))
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
const tipLeft = computed(() => active.value === null ? 0 : ((margin.value.left + xOf(active.value)) / width.value) * 100)
const tipStyle = computed(() => tipLeft.value > 55 ? { right: `calc(${100 - tipLeft.value}% + 12px)` } : { left: `calc(${tipLeft.value}% + 12px)` })
const valueText = (v: number | null | undefined, f = props.format) => typeof v === 'number' && Number.isFinite(v) ? f(v) : 'keine Daten'
const markersAt = (i: number) => props.markers.filter(m => m.index === i || (m.untilIndex !== undefined && i > m.index && i <= m.untilIndex))
const hoverDot = computed(() => {
  const i = active.value
  if (i === null) return null
  const v = props.values[i]
  return typeof v === 'number' ? { x: xOf(i), y: yOf(v) } : null
})

const summary = computed(() => {
  const vals = props.values.filter((v): v is number => typeof v === 'number')
  const att = attackTotal.value.filter((v): v is number => v !== null)
  if (!vals.length) return `${props.label}: noch keine Daten`
  const max = Math.max(...vals)
  const maxAtt = att.length ? Math.max(...att) : 0
  const ai = attackTotal.value.indexOf(maxAtt)
  return `${props.label}: höchstens ${props.format(max)}. ${props.attacksLabel}: höchstens ${props.attackFormat(maxAtt)}${ai >= 0 && maxAtt > 0 ? ` um ${props.longLabels[ai]}` : ''}. ${props.markers.length} Markierungen.`
})
</script>

<template>
  <figure class="w-full min-w-0" data-slot="traffic-attack-chart" data-testid="main-chart">
    <div class="mb-2 flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
      <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground" aria-hidden="true">
        <span class="inline-flex items-center gap-1.5"><span class="h-0.5 w-3 rounded-full" :style="{ background: TONES.main }" />{{ label }}</span>
        <span v-if="partial.some(Boolean)" class="inline-flex items-center gap-1.5"><span class="h-0 w-3 border-t-2 border-dashed" :style="{ borderColor: TONES.main }" />wird noch gezählt</span>
        <span class="inline-flex items-center gap-1.5"><span class="size-2.5 rounded-[3px]" :style="{ background: TONES.deep }" />gesperrt</span>
        <span class="inline-flex items-center gap-1.5"><span class="size-2.5 rounded-[3px]" :style="{ background: TONES.light }" />erkannt</span>
      </div>
      <Button variant="link" size="sm" class="h-auto p-0 text-xs" :aria-expanded="showTable" :aria-controls="`${uid}-table`" @click="showTable = !showTable">
        {{ showTable ? 'Als Diagramm zeigen' : 'Als Tabelle zeigen' }}
      </Button>
    </div>
    <div v-show="!showTable" ref="root" class="relative w-full">
      <!-- Markers on top of the plot: links to the wave, the incident, the settings. -->
      <div class="relative h-6 overflow-hidden" data-slot="markers">
        <template v-for="(c, k) in chips" :key="`mk${k}`">
          <RouterLink
            v-if="c.lead.to"
            :to="c.lead.to"
            class="absolute top-0 flex h-6 min-w-6 -translate-x-1/2 items-center justify-center rounded-full border bg-card px-1 text-[10px] font-semibold text-foreground shadow-xs hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring"
            :style="{ left: c.left }"
            :title="c.title"
            :data-marker="c.lead.kind"
            :data-kinds="c.items.map(m => m.kind).join(' ')"
            :data-count="c.items.length"
          >
            <!-- The name is the hidden text, not an aria-label: the visible glyph and count are not words (axe label-content-name-mismatch). -->
            <span aria-hidden="true">{{ c.lead.glyph }}<template v-if="c.items.length > 1"><span class="ml-0.5 font-normal text-muted-foreground">{{ c.items.length > 99 ? '99+' : c.items.length }}</span></template></span>
            <span class="sr-only">{{ c.items.length > 1 ? `${c.items.length} Markierungen: ${c.title}` : `${c.lead.label}, ${longLabels[c.lead.index] ?? ''}` }}</span>
          </RouterLink>
          <span
            v-else
            class="absolute top-0 flex h-6 min-w-6 -translate-x-1/2 items-center justify-center rounded-full border border-dashed bg-card px-1 text-[10px] text-muted-foreground"
            :style="{ left: c.left }"
            :title="c.title"
            :data-marker="c.lead.kind"
            :data-kinds="c.items.map(m => m.kind).join(' ')"
            :data-count="c.items.length"
          >{{ c.lead.glyph }}<template v-if="c.items.length > 1"><span class="ml-0.5">{{ c.items.length > 99 ? '99+' : c.items.length }}</span></template><span class="sr-only">{{ c.title }}</span></span>
        </template>
      </div>
      <svg
        :viewBox="`0 0 ${width} ${height - MARKER_ROW}`"
        :height="height - MARKER_ROW"
        class="block w-full rounded-md focus-visible:outline-2 focus-visible:outline-ring"
        role="img"
        :aria-label="summary"
        tabindex="0"
        @pointermove="onPointer"
        @pointerleave="active = null"
        @keydown="onKey"
        @blur="active = null"
      >
        <g :transform="`translate(${margin.left},${PAD})`">
          <!-- top: traffic -->
          <g class="text-muted-foreground">
            <g v-for="t in scale.ticks" :key="t">
              <line :x1="0" :x2="innerW" :y1="yOf(t)" :y2="yOf(t)" class="stroke-border" stroke-width="1" shape-rendering="crispEdges" />
              <text :x="-8" :y="yOf(t)" dy="0.32em" text-anchor="end" class="fill-current text-[10px] tabular-nums">{{ axisFormat(t) }}</text>
            </g>
          </g>
          <rect v-for="(g, k) in gaps" :key="`gap${k}`" :x="xOf(g.index)" :y="0" :width="Math.max(2, xOf(g.untilIndex!) - xOf(g.index))" :height="bandTop + BAND_H" class="fill-muted-foreground" fill-opacity="0.08" />
          <path :d="fillPath" :fill="TONES.main" fill-opacity="0.1" />
          <path :d="linePath" fill="none" :stroke="TONES.main" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" data-series="main" />
          <path v-if="dashPath" :d="dashPath" fill="none" :stroke="TONES.main" stroke-width="2" stroke-dasharray="4 4" stroke-linecap="round" data-series="partial" />

          <!-- below: attacks on their own scale -->
          <g :transform="`translate(0,${bandTop})`" data-slot="attack-band">
            <line :x1="0" :x2="innerW" :y1="BAND_H" :y2="BAND_H" class="stroke-border" stroke-width="1" shape-rendering="crispEdges" />
            <text :x="-8" :y="6" text-anchor="end" class="fill-muted-foreground text-[10px] tabular-nums">{{ attackFormat(attackMax) }}</text>
            <text :x="-8" :y="BAND_H" text-anchor="end" class="fill-muted-foreground text-[10px]">0</text>
            <text :x="0" :y="-3" class="fill-muted-foreground text-[10px] font-medium">{{ attacksLabel }}</text>
            <g v-for="b in bars" :key="b.i" :opacity="b.partial ? 0.55 : 1">
              <rect :x="b.x" :y="BAND_H - b.hs" :width="barW" :height="b.hs" :fill="TONES.deep" />
              <rect v-if="b.hw > 0" :x="b.x" :y="BAND_H - b.hs - b.hw" :width="barW" :height="b.hw" :fill="TONES.light" />
            </g>
          </g>

          <!-- markers through both panels -->
          <line v-for="(m, k) in markers" :key="`ml${k}`" :x1="xOf(m.index)" :x2="xOf(m.index)" :y1="0" :y2="bandTop + BAND_H" class="stroke-muted-foreground" stroke-opacity="0.5" stroke-width="1" stroke-dasharray="2 3" />

          <text v-for="i in xTicks" :key="`x${i}`" :x="xOf(i)" :y="bandTop + BAND_H + 15" :text-anchor="anchorOf(i)" class="fill-muted-foreground text-[10px] tabular-nums">{{ labels[i] }}</text>

          <g v-if="active !== null" data-slot="crosshair">
            <line :x1="xOf(active)" :x2="xOf(active)" :y1="0" :y2="bandTop + BAND_H" class="stroke-foreground" stroke-opacity="0.3" stroke-width="1" />
            <circle v-if="hoverDot" :cx="hoverDot.x" :cy="hoverDot.y" r="4" :fill="TONES.main" class="stroke-card" stroke-width="2" />
          </g>
        </g>
      </svg>
      <div
        v-if="active !== null"
        class="pointer-events-none absolute top-4 z-10 min-w-48 rounded-md border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md"
        :style="tipStyle"
        aria-live="polite"
        data-slot="tooltip"
      >
        <p class="mb-1.5 text-muted-foreground">
          {{ longLabels[active] }}<template v-if="isPartial(active)">
            · wird noch gezählt
          </template>
        </p>
        <p class="flex items-center justify-between gap-4">
          <span class="inline-flex items-center gap-1.5 text-muted-foreground"><span class="h-0.5 w-3 rounded-full" :style="{ background: TONES.main }" />{{ label }}</span>
          <span class="font-semibold tabular-nums">{{ valueText(values[active]) }}</span>
        </p>
        <p class="mt-1 flex items-center justify-between gap-4 border-t pt-1">
          <span class="inline-flex items-center gap-1.5 text-muted-foreground"><span class="size-2 rounded-[2px]" :style="{ background: TONES.deep }" />gesperrt</span>
          <span class="font-medium tabular-nums">{{ valueText(stopped[active], attackFormat) }}</span>
        </p>
        <p class="flex items-center justify-between gap-4">
          <span class="inline-flex items-center gap-1.5 text-muted-foreground"><span class="size-2 rounded-[2px]" :style="{ background: TONES.light }" />erkannt</span>
          <span class="font-medium tabular-nums">{{ valueText(would[active], attackFormat) }}</span>
        </p>
        <p v-if="wouldNote && (would[active] ?? 0) > 0" class="mt-0.5 max-w-64 text-muted-foreground" data-testid="tooltip-would-note">
          {{ wouldNote }}
        </p>
        <p v-for="(m, k) in markersAt(active)" :key="k" class="mt-1 border-t pt-1 font-medium">
          {{ m.label }}
        </p>
      </div>
    </div>
    <div v-show="showTable" class="max-h-80 overflow-auto rounded-md border">
      <table :id="`${uid}-table`" class="w-full text-left text-xs tabular-nums">
        <caption class="sr-only">
          {{ label }} und {{ attacksLabel }}
        </caption>
        <thead class="sticky top-0 bg-card">
          <tr>
            <th scope="col" class="px-2 py-1.5 font-medium">
              Zeitpunkt
            </th>
            <th scope="col" class="px-2 py-1.5 text-right font-medium">
              {{ label }}
            </th>
            <th scope="col" class="px-2 py-1.5 text-right font-medium">
              Gesperrt
            </th>
            <th scope="col" class="px-2 py-1.5 text-right font-medium">
              Erkannt
            </th>
          </tr>
        </thead>
        <tbody v-if="showTable">
          <tr v-for="(_, i) in labels" :key="i" class="border-t">
            <th scope="row" class="px-2 py-1 font-normal text-muted-foreground">
              {{ longLabels[i] }}<template v-if="isPartial(i)">
                (wird noch gezählt)
              </template><template v-for="m in markers.filter(x => x.index === i)" :key="m.label">
                · {{ m.label }}
              </template>
            </th>
            <td class="px-2 py-1 text-right font-medium">
              {{ valueText(values[i]) }}
            </td>
            <td class="px-2 py-1 text-right">
              {{ valueText(stopped[i], attackFormat) }}
            </td>
            <td class="px-2 py-1 text-right">
              {{ valueText(would[i], attackFormat) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </figure>
</template>
