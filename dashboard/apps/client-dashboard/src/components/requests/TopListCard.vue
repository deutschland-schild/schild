<script setup lang="ts">
import type { BarRow } from './BreakdownBars.vue'
import type { WebsiteRangeKey } from '@/api/websites'
import { computed } from 'vue'
import { isFilterUnavailable, useWebsiteBreakdown } from '@/api/websites'
import { keyLabel } from '@/lib/monitoring'
import { WEBSITE_COPY } from '@/lib/websites'
import { isAiReferrer } from '@/lib/requests-overview'
import BreakdownBars from './BreakdownBars.vue'
import OverviewCard from './OverviewCard.vue'

/**
 * Top-Seiten, Herkunft, IP-Adressen or User-Agents of the Zugriffe overview as bars: the eight largest
 * entries with requests and share; a click filters the page. Sources mark AI assistants ("KI-Assistent").
 * Path, referrer lists are bounded top lists of the gateway, so they carry the Näherungswert note;
 * addresses and User-Agents come from the single requests (D65).
 */
const props = defineProps<{
  by: 'path' | 'referrer' | 'ip' | 'user_agent'
  title: string
  description: string
  testid: string
  more: string
  site: string
  range: WebsiteRangeKey
  filters: string[]
  activeValue?: string | null
  offerRange?: boolean
}>()
const emit = defineEmits<{ filter: [expr: string], range: [key: WebsiteRangeKey], more: [] }>()

const q = useWebsiteBreakdown(() => ({ site: props.site, range: props.range, filters: props.filters, by: props.by, top: 16 }))
const b = computed(() => q.data.value)
const total = computed(() => b.value?.total.requests ?? 0)
const rows = computed<BarRow[]>(() => (b.value?.items ?? []).slice(0, 8).map((i) => {
  const ai = props.by === 'referrer' && isAiReferrer(i.key)
  return {
    id: i.key,
    label: ai ? (i.label ?? i.key.slice(3)) : keyLabel(props.by, i.key, i.label),
    value: i.requests,
    share: total.value ? i.requests / total.value : null,
    tag: ai ? 'KI-Assistent' : undefined,
    mono: props.by !== 'referrer',
    title: props.by === 'user_agent' ? i.key : undefined,
  }
}))
const state = computed(() => {
  if (isFilterUnavailable(q.error.value)) return 'unavailable'
  if (!b.value) return q.isError.value ? 'error' : 'loading'
  return rows.value.length ? 'ok' : 'empty'
})
const estimate = computed(() => b.value && !b.value.exact ? `${WEBSITE_COPY.estimate}: Schild führt eine begrenzte Rangliste. Seltene Einträge können etwas zu hoch erscheinen.` : null)
</script>

<template>
  <OverviewCard
    :title="title"
    :description="description"
    :testid="testid"
    :state="state"
    :estimate="estimate"
    :partial="!!b?.partial"
    :offer-range="offerRange"
    :more="more"
    @range="emit('range', '48h')"
    @more="emit('more')"
  >
    <BreakdownBars :rows="rows" :label="title" :active="activeValue" @select="k => emit('filter', `${by}:${k}`)" />
  </OverviewCard>
</template>
