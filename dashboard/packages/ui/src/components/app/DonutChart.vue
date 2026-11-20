<script setup lang="ts">
import type { DonutSlice } from './types'
import { Button } from '@schild/ui/components/ui/button'
import { arcPath, donutAngles } from '@schild/ui/lib/chart'
import { formatNumber, formatPercent } from '@schild/ui/lib/format'
import { computed, ref, useId } from 'vue'

/**
 * Donut for parts of a whole (at most six slices: five named plus "Andere"). The caller passes the
 * slices in their order (largest first, "Andere" last) with a colour that follows the entity, never its
 * rank. Thin ring with a 2px surface gap between slices, no labels on the ring: the centre names the
 * largest (or the hovered / focused) slice with its share, the legend beside it lists every slice with
 * its share, so identity never depends on colour alone. Slices marked clickable are buttons in the
 * legend and on the ring (select emits the id). "Als Tabelle zeigen" lists counts and shares.
 */
const props = withDefaults(defineProps<{
  slices: DonutSlice[]
  /** Accessible name and table caption ("Anfragen nach Gerät"). */
  label: string
  /** Column title of the counts in the table ("Anfragen"). */
  unit?: string
  format?: (n: number) => string
  /** The slice that is set as a filter (outlined). */
  active?: string | null
  /** Diameter in px. */
  size?: number
}>(), { unit: 'Anzahl', format: formatNumber, active: null, size: 116 })
const emit = defineEmits<{ select: [id: string] }>()

const uid = useId()
const showTable = ref(false)
const hover = ref<string | null>(null)

const R_OUT = 56
const R_IN = 41
const total = computed(() => props.slices.reduce((a, s) => a + Math.max(0, s.value), 0))
const arcs = computed(() => {
  const ang = donutAngles(props.slices.map(s => s.value))
  return props.slices.map((s, i) => ({ s, share: ang[i]!.share, d: arcPath(60, 60, R_IN, R_OUT, ang[i]!.a0, ang[i]!.a1) }))
})
const rows = computed(() => arcs.value.map(a => ({ ...a.s, share: a.share })))
/** The centre: the hovered or focused slice, else the filtered one, else the largest named slice. */
const focus = computed(() => {
  const id = hover.value ?? props.active
  return rows.value.find(r => r.id === id) ?? rows.value.find(r => !r.other && r.value > 0) ?? null
})
const summary = computed(() => total.value > 0
  ? `${props.label}: ${rows.value.filter(r => r.value > 0).map(r => `${r.label} ${formatPercent(r.share)}`).join(', ')}`
  : `${props.label}: noch keine Daten`)
function pick(s: DonutSlice) {
  if (s.clickable) emit('select', s.id)
}
</script>

<template>
  <figure class="w-full min-w-0" data-slot="donut-chart">
    <div v-show="!showTable" class="flex flex-wrap items-center gap-x-5 gap-y-3">
      <div class="relative shrink-0" :style="{ width: `${size}px`, height: `${size}px` }">
        <svg viewBox="0 0 120 120" :width="size" :height="size" role="img" :aria-label="summary" class="block">
          <circle v-if="total <= 0" cx="60" cy="60" :r="(R_IN + R_OUT) / 2" fill="none" class="stroke-muted" :stroke-width="R_OUT - R_IN" />
          <path
            v-for="a in arcs"
            :key="a.s.id"
            :d="a.d"
            :fill="a.s.color"
            class="stroke-card transition-opacity"
            stroke-width="2"
            stroke-linejoin="round"
            :opacity="(hover ?? active) && (hover ?? active) !== a.s.id ? 0.45 : 1"
            :class="a.s.clickable ? 'cursor-pointer' : ''"
            :data-slice="a.s.id"
            @pointerenter="hover = a.s.id"
            @pointerleave="hover = null"
            @click="pick(a.s)"
          >
            <title>{{ a.s.label }}: {{ formatPercent(a.share) }} ({{ format(a.s.value) }})</title>
          </path>
        </svg>
        <div v-if="focus && total > 0" class="pointer-events-none absolute inset-0 flex flex-col items-center justify-center px-4 text-center" aria-hidden="true">
          <span class="text-lg leading-tight font-semibold">{{ formatPercent(focus.share) }}</span>
          <span class="line-clamp-2 max-w-full text-[10px] leading-tight break-words hyphens-auto text-muted-foreground">{{ focus.label }}</span>
        </div>
      </div>
      <ul class="min-w-40 flex-1 space-y-0.5 text-sm" :aria-label="label">
        <li v-for="r in rows" :key="r.id" :data-row="r.id">
          <component
            :is="r.clickable ? 'button' : 'div'"
            :type="r.clickable ? 'button' : undefined"
            class="flex w-full items-start gap-2 rounded-md px-1.5 py-1 text-left"
            :class="[r.clickable ? 'hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring' : '', active === r.id ? 'bg-muted font-medium' : '']"
            :aria-pressed="r.clickable ? active === r.id : undefined"
            :title="r.hint"
            @pointerenter="hover = r.id"
            @pointerleave="hover = null"
            @focus="hover = r.id"
            @blur="hover = null"
            @click="pick(r)"
          >
            <span class="mt-[3px] size-2.5 shrink-0 rounded-[3px]" :style="{ background: r.color }" aria-hidden="true" />
            <span class="min-w-0 flex-1 leading-tight hyphens-auto">{{ r.label }}</span>
            <span class="tabular-nums text-muted-foreground">{{ formatPercent(r.share) }}</span>
          </component>
        </li>
      </ul>
    </div>
    <div v-show="showTable" class="overflow-auto rounded-md border">
      <table :id="`${uid}-table`" class="w-full text-left text-xs tabular-nums">
        <caption class="sr-only">
          {{ label }}
        </caption>
        <thead>
          <tr>
            <th scope="col" class="px-2 py-1.5 font-medium">
              Teil
            </th>
            <th scope="col" class="px-2 py-1.5 text-right font-medium">
              {{ unit }}
            </th>
            <th scope="col" class="px-2 py-1.5 text-right font-medium">
              Anteil
            </th>
          </tr>
        </thead>
        <tbody v-if="showTable">
          <tr v-for="r in rows" :key="r.id" class="border-t">
            <th scope="row" class="px-2 py-1 font-normal">
              {{ r.label }}
            </th>
            <td class="px-2 py-1 text-right">
              {{ format(r.value) }}
            </td>
            <td class="px-2 py-1 text-right">
              {{ formatPercent(r.share) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <figcaption class="mt-2 flex flex-wrap items-center justify-between gap-2">
      <span class="text-xs text-muted-foreground">
        <slot name="caption" />
      </span>
      <Button variant="link" size="sm" class="h-auto p-0 text-xs" :aria-expanded="showTable" :aria-controls="`${uid}-table`" @click="showTable = !showTable">
        {{ showTable ? 'Als Diagramm zeigen' : 'Als Tabelle zeigen' }}
      </Button>
    </figcaption>
  </figure>
</template>
