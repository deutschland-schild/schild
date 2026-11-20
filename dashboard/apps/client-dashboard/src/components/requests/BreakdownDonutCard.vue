<script setup lang="ts">
import type { WebsiteRangeKey } from '@/api/websites'
import type { DonutKey } from '@/lib/requests-overview'
import { DonutChart, formatNumber } from '@schild/ui'
import { computed } from 'vue'
import { isFilterUnavailable, useWebsiteBreakdown } from '@/api/websites'
import { COPY } from '@/lib/monitoring'
import { WEBSITE_COPY } from '@/lib/websites'
import { DONUTS, donutSlices, OVERVIEW_COPY } from '@/lib/requests-overview'
import OverviewCard from './OverviewCard.vue'

/**
 * One donut of the Zugriffe overview from a breakdown (Mensch / Bot, Geräte, Browser, Betriebssystem,
 * Statuscodes): shares of requests, at most five named slices plus "Andere". A click on a slice sets its
 * filter on the page, or opens the tab that lists a group (KI-Crawler, Andere Bots).
 */
const props = defineProps<{
  kind: DonutKey
  title: string
  description?: string
  testid: string
  site: string
  range: WebsiteRangeKey
  filters: string[]
  /** The value of this dimension among the page's filters. */
  activeValue?: string | null
  offerRange?: boolean
}>()
const emit = defineEmits<{ filter: [expr: string], tab: [key: string], range: [key: WebsiteRangeKey] }>()

const def = computed(() => DONUTS[props.kind])
const q = useWebsiteBreakdown(() => ({ site: props.site, range: props.range, filters: props.filters, by: def.value.by, top: 16 }))
const b = computed(() => q.data.value)
const view = computed(() => b.value ? donutSlices(def.value, b.value.items, b.value.other.requests) : null)
const state = computed(() => {
  if (isFilterUnavailable(q.error.value)) return 'unavailable'
  if (!b.value) return q.isError.value ? 'error' : 'loading'
  return view.value && view.value.total > 0 ? 'ok' : 'empty'
})
const active = computed(() => {
  const v = props.activeValue
  if (!v) return null
  return def.value.slices.find(s => s.keys(v))?.id ?? null
})
const estimate = computed(() => b.value && !b.value.exact ? `${WEBSITE_COPY.estimate}: Mit Filter oder bei mehreren Websites kommen die Zahlen aus Ranglisten oder einem Teil der gespeicherten Anfragen.` : null)
const unverified = computed(() => props.kind === 'bots' && b.value?.bot_verification === false)
const caption = computed(() => [
  OVERVIEW_COPY.sharesOfRequests,
  view.value?.excluded ? `Ohne Angabe (meist Bots und Werkzeuge): ${formatNumber(view.value.excluded)}.` : '',
  unverified.value ? COPY.botsUnverified : '',
].filter(Boolean).join(' '))

function select(id: string) {
  const s = view.value?.slices.find(x => x.id === id)
  if (s?.filter) emit('filter', s.filter)
  else if (s?.tab) emit('tab', s.tab)
}
</script>

<template>
  <OverviewCard :title="title" :description="description" :testid="testid" :state="state" :estimate="estimate" :partial="!!b?.partial" :offer-range="offerRange" :skeleton-rows="4" @range="emit('range', '48h')">
    <DonutChart v-if="view" :slices="view.slices" :label="`${title}: Anteile an den Anfragen`" unit="Anfragen" :active="active" @select="select">
      <template #caption>
        {{ caption }}
      </template>
    </DonutChart>
    <slot name="footer" />
  </OverviewCard>
</template>
