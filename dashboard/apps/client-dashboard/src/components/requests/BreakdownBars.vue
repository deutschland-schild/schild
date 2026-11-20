<script setup lang="ts">
import { formatNumber, formatPercent } from '@schild/ui'
import { computed } from 'vue'
import { TONES } from '@/lib/monitoring'

/**
 * Bar list of a breakdown (top pages, sources, countries): label, count and share on the card surface
 * in ink, the magnitude as a thin bar in the one brand tone below (one series, one colour). A row is a
 * button that filters the page; the set filter is marked. A tag (e.g. "KI-Assistent") and a leading
 * glyph (a flag) are optional. Rendered as a real list, so it is its own table view.
 */
export interface BarRow {
  id: string
  label: string
  value: number
  /** Share of the whole (0..1); without it no percentage is shown. */
  share?: number | null
  /** Small text tag after the label. */
  tag?: string
  /** Leading glyph, e.g. a flag emoji (decorative, the label names the country). */
  glyph?: string
  mono?: boolean
  title?: string
}
const props = withDefaults(defineProps<{
  rows: BarRow[]
  /** Accessible name of the list. */
  label: string
  active?: string | null
  format?: (n: number) => string
  clickable?: boolean
}>(), { active: null, format: formatNumber, clickable: true })
const emit = defineEmits<{ select: [id: string] }>()

const max = computed(() => Math.max(1, ...props.rows.map(r => r.value)))
</script>

<template>
  <ul class="-mx-1.5 space-y-0.5" :aria-label="label" data-slot="breakdown-bars">
    <li v-for="r in rows" :key="r.id" :data-row="r.id">
      <component
        :is="clickable ? 'button' : 'div'"
        :type="clickable ? 'button' : undefined"
        class="block w-full rounded-md px-1.5 py-1 text-left"
        :class="[clickable ? 'hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring' : '', active === r.id ? 'bg-muted' : '']"
        :aria-pressed="clickable ? active === r.id : undefined"
        :title="r.title"
        @click="clickable && emit('select', r.id)"
      >
        <span class="flex items-baseline gap-2 text-sm">
          <span v-if="r.glyph" class="w-5 shrink-0 text-center" aria-hidden="true">{{ r.glyph }}</span>
          <span class="min-w-0 flex-1 truncate" :class="[r.mono ? 'font-mono text-[13px]' : '', active === r.id ? 'font-semibold' : '']">{{ r.label }}</span>
          <span v-if="r.tag" class="shrink-0 rounded-full border px-1.5 text-[11px] leading-4 text-muted-foreground" data-slot="bar-tag">{{ r.tag }}</span>
          <span class="shrink-0 font-medium tabular-nums">{{ format(r.value) }}</span>
          <span v-if="r.share !== undefined" class="w-12 shrink-0 text-right text-xs tabular-nums text-muted-foreground">{{ r.share === null ? '–' : formatPercent(r.share) }}</span>
        </span>
        <span class="mt-1 block h-1 rounded-full bg-muted" :class="r.glyph ? 'ml-7' : ''" aria-hidden="true">
          <span class="block h-full rounded-full" :style="{ width: `${Math.max(1, (r.value / max) * 100)}%`, background: TONES.main }" />
        </span>
      </component>
    </li>
  </ul>
</template>
