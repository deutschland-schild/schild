<script setup lang="ts">
import type { BarRow } from './BreakdownBars.vue'
import type { WebsiteRangeKey } from '@/api/websites'
import { flagEmoji, formatNumber } from '@schild/ui'
import { computed } from 'vue'
import { isFilterUnavailable, useWebsiteBreakdown } from '@/api/websites'
import { keyLabel } from '@/lib/monitoring'
import { WEBSITE_COPY } from '@/lib/websites'
import BreakdownBars from './BreakdownBars.vue'
import OverviewCard from './OverviewCard.vue'
import WorldMap from './WorldMap.vue'

/**
 * Länder of the Zugriffe overview: the built-in world map (one hue, light to dark, no tile server) and
 * the top countries with flag, requests and share as bars. A click on a country, on the map or in the
 * list, filters the page. Same query as the Länder tab, so switching tabs costs no second request.
 */
const props = defineProps<{ site: string, range: WebsiteRangeKey, filters: string[], activeCountry?: string | null, offerRange?: boolean }>()
const emit = defineEmits<{ filter: [expr: string], range: [key: WebsiteRangeKey], more: [] }>()

const q = useWebsiteBreakdown(() => ({ site: props.site, range: props.range, filters: props.filters, by: 'country', top: 100 }))
const b = computed(() => q.data.value)
const items = computed(() => (b.value?.items ?? []).filter(i => i.key !== 'ZZ'))
const total = computed(() => b.value?.total.requests ?? 0)
const rows = computed<BarRow[]>(() => items.value.slice(0, 8).map(i => ({
  id: i.key,
  label: keyLabel('country', i.key),
  value: i.requests,
  share: total.value ? i.requests / total.value : null,
  glyph: flagEmoji(i.key),
  title: `${formatNumber(i.would_block)} erkannt, ${formatNumber(i.stopped)} gesperrt`,
})))
const state = computed(() => {
  if (isFilterUnavailable(q.error.value)) return 'unavailable'
  if (!b.value) return q.isError.value ? 'error' : 'loading'
  return items.value.length ? 'ok' : 'empty'
})
const estimate = computed(() => b.value && !b.value.exact ? `${WEBSITE_COPY.estimate}: seltene Länder können etwas zu hoch erscheinen.` : null)
</script>

<template>
  <OverviewCard
    title="Länder"
    description="Woher die Anfragen kommen, nur das Land. Klick auf ein Land filtert die ganze Seite."
    testid="overview-countries"
    :state="state"
    :estimate="estimate"
    :partial="!!b?.partial"
    :offer-range="offerRange"
    more="Alle Länder"
    @range="emit('range', '48h')"
    @more="emit('more')"
  >
    <div class="grid items-start gap-4 md:grid-cols-[3fr_2fr]">
      <WorldMap :items="items" :active="activeCountry" @select="c => emit('filter', `country:${c}`)" />
      <BreakdownBars :rows="rows" label="Anfragen nach Land" :active="activeCountry" @select="c => emit('filter', `country:${c}`)" />
    </div>
  </OverviewCard>
</template>
