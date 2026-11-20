<script setup lang="ts">
import { formatNumber, Skeleton } from '@schild/ui'
import { computed, onMounted, shallowRef, useId } from 'vue'
import { keyLabel } from '@/lib/monitoring'
import { mapSteps, MAP_STEP_COLORS } from '@/lib/requests'

/**
 * Built-in world map of the Länder tab (MVP-22): simplified Natural Earth shapes shipped with the app
 * (no tile server, no external request), coloured by requests on a calm one-hue sequential scale (log
 * steps, light to dark). Countries without requests stay in the muted surface colour. Hover shows the
 * numbers, a click filters the page by the country; the list next to the map carries the same numbers
 * for keyboard and screen readers.
 */
const props = defineProps<{
  items: { key: string, requests: number, stopped: number, would_block: number }[]
  /** The country filter that is set (outlined). */
  active?: string | null
}>()
const emit = defineEmits<{ select: [country: string] }>()

const shapes = shallowRef<{ viewBox: string, outline: string, shapes: Record<string, string> } | null>(null)
/** Countries without requests: a quiet grey that still shows the coastlines on the card. */
const NO_DATA = 'color-mix(in oklab, var(--muted-foreground) 16%, var(--card))'
const clipId = `world-${useId()}`
onMounted(async () => {
  // Loaded on demand: about 85 KB of path data only when the Länder tab opens.
  const m = await import('@/assets/world-110m')
  shapes.value = { viewBox: m.WORLD_VIEWBOX, outline: m.WORLD_OUTLINE, shapes: m.WORLD_SHAPES }
})

const byKey = computed(() => new Map(props.items.map(i => [i.key, i])))
const steps = computed(() => mapSteps(props.items.map(i => i.requests)))
const paths = computed(() => {
  const s = shapes.value
  if (!s) return []
  return Object.entries(s.shapes).map(([id, d]) => {
    const it = byKey.value.get(id)
    const step = it ? steps.value.stepOf(it.requests) : -1
    return {
      id,
      d,
      it,
      fill: step < 0 ? NO_DATA : MAP_STEP_COLORS[step]!,
      title: it ? `${keyLabel('country', id)}: ${formatNumber(it.requests)} Anfragen, ${formatNumber(it.would_block)} erkannt, ${formatNumber(it.stopped)} gesperrt` : `${keyLabel('country', id)}: keine Anfragen`,
    }
  })
})
</script>

<template>
  <figure class="min-w-0" data-testid="world-map">
    <Skeleton v-if="!shapes" class="aspect-[1000/431] w-full" />
    <svg v-else :viewBox="shapes.viewBox" class="h-auto w-full" role="img" aria-label="Weltkarte: Anfragen nach Land. Die Zahlen stehen in der Liste daneben.">
      <defs>
        <clipPath :id="clipId">
          <path :d="shapes.outline" />
        </clipPath>
      </defs>
      <g :clip-path="`url(#${clipId})`">
        <path
          v-for="p in paths"
          :key="p.id"
          :d="p.d"
          :style="{ fill: p.fill }"
          :stroke="p.id === active ? 'var(--foreground)' : 'var(--card)'"
          :stroke-width="p.id === active ? 1.5 : 0.5"
          :class="p.it ? 'cursor-pointer hover:opacity-80' : ''"
          :data-country="p.id"
          @click="p.it && emit('select', p.id)"
        >
          <title>{{ p.title }}</title>
        </path>
      </g>
    </svg>
    <figcaption class="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
      <span>Anfragen:</span>
      <span v-for="(c, i) in MAP_STEP_COLORS" :key="c" class="inline-flex items-center gap-1">
        <span class="size-3 rounded-sm border" :style="{ background: c }" aria-hidden="true" />
        <span class="tabular-nums">{{ steps.labels[i] }}</span>
      </span>
      <span class="inline-flex items-center gap-1"><span class="size-3 rounded-sm border" :style="{ background: NO_DATA }" aria-hidden="true" />keine</span>
    </figcaption>
  </figure>
</template>
