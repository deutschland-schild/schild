<script setup lang="ts">
import type { WebsiteRangeKey } from '@/api/websites'
import { DonutChart, formatNumber } from '@schild/ui'
import { computed } from 'vue'
import { isFilterUnavailable, seriesResolutionFor, useBotClients, useWebsiteKpis, useWebsiteSeries } from '@/api/websites'
import { COPY } from '@/lib/monitoring'
import { WEBSITE_COPY } from '@/lib/websites'
import { newReturningSlices, seriesSum } from '@/lib/requests-overview'
import BreakdownDonutCard from './BreakdownDonutCard.vue'
import CountriesCard from './CountriesCard.vue'
import OverviewCard from './OverviewCard.vue'
import SecurityCard from './SecurityCard.vue'
import TopListCard from './TopListCard.vue'

/**
 * Lower part of the Zugriffe Überblick (MVP-22, D36, D68), like a cookie-free web analytics view: who
 * visits, from where, with what. The KPIs and the main chart sit above it (TrafficHeadline). Here: the
 * countries on the built-in map, donuts for parts of a whole (Mensch / Bot, Geräte, Browser, System,
 * Statuscodes, Neu / wiederkehrend), bars for long lists (Seiten, Herkunft) and a small Sicherheit card
 * that links to Ereignisse. Every click filters the whole page (or opens the tab with the full list).
 * Data: getWebsiteKpis, queryMetricSeries and getTrafficBreakdown.
 */
const props = defineProps<{
  site: string
  range: WebsiteRangeKey
  /** All filters of the page (KPIs and series). */
  filters: string[]
  /** Filters the breakdowns can apply (none when only the request ring could answer them). */
  panelFilters: string[]
  ring: boolean
  ringAnswers: boolean
  valueOf: (dimension: string) => string | null
}>()
const emit = defineEmits<{ filter: [expr: string], range: [key: WebsiteRangeKey], tab: [key: string] }>()

const kpisQ = useWebsiteKpis(() => ({ site: props.site, range: props.range, filters: props.filters }))
const kpis = computed(() => kpisQ.data.value)

const resolution = computed(() => seriesResolutionFor(props.range, props.filters.length > 0, props.ringAnswers))
/** New visitors under a filter come from the single requests only: without them no request (no 409 per click, D36 D.3). */
const newAnswerable = computed(() => !props.filters.length || props.ringAnswers)
const curQ = useWebsiteSeries(() => ({
  site: props.site,
  range: props.range,
  filters: props.filters,
  metrics: ['traffic.clients_new'],
  resolution: resolution.value,
}), newAnswerable)
const seriesUnavailable = computed(() => !newAnswerable.value || isFilterUnavailable(curQ.error.value))
const newSum = computed(() => seriesSum(curQ.data.value?.series.find(s => s.metric === 'traffic.clients_new')?.values))

const newReturning = computed(() => newReturningSlices(kpis.value?.current.visitors.value, seriesUnavailable.value ? null : newSum.value))
const newReturningState = computed(() => {
  if (seriesUnavailable.value || kpis.value?.current.visitors.unavailable === 'filter_needs_requests') return 'unavailable'
  if (!curQ.data.value || !kpis.value) return curQ.isError.value || kpisQ.isError.value ? 'error' : 'loading'
  return newReturning.value.some(s => s.value > 0) ? 'ok' : 'empty'
})
// Bots are no visitors (D36 amendment 2026-10-29): how many different addresses came as a bot, next to Mensch oder Bot.
const botClientsQ = useBotClients(() => props.site)
const botClients = computed(() => botClientsQ.data.value?.bots ?? null)
const offer = computed(() => props.ring)
const card = computed(() => ({ site: props.site, range: props.range, filters: props.panelFilters, offerRange: offer.value }))
</script>

<template>
  <div class="space-y-4" data-testid="traffic-overview">
    <div class="grid gap-4 lg:grid-cols-3">
      <CountriesCard
        class="lg:col-span-2"
        v-bind="card"
        :active-country="valueOf('country')"
        @filter="e => emit('filter', e)"
        @range="k => emit('range', k)"
        @more="emit('tab', 'countries')"
      />
      <BreakdownDonutCard
        v-bind="card"
        kind="bots"
        title="Mensch oder Bot"
        description="Wer die Anfragen geschickt hat, nach der Kennung des Browsers oder Bots."
        testid="donut-bots"
        :active-value="valueOf('bot_category')"
        @filter="e => emit('filter', e)"
        @tab="k => emit('tab', k)"
        @range="k => emit('range', k)"
      >
        <template v-if="botClients !== null" #footer>
          <p class="mt-2 text-xs text-muted-foreground" :title="WEBSITE_COPY.botClientsTitle" data-testid="bot-clients">
            {{ WEBSITE_COPY.botClients }}: ≈ {{ formatNumber(botClients) }} in den letzten 10 Minuten
          </p>
        </template>
      </BreakdownDonutCard>
    </div>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <TopListCard
        v-bind="card"
        by="path"
        title="Top-Seiten"
        description="Die meistgefragten Seiten. Ähnliche Pfade sind zusammengefasst, zum Beispiel /blog/{slug}. Ein Klick zeigt die einzelnen Anfragen mit dem echten Pfad."
        testid="overview-pages"
        more="Alle Seiten"
        :active-value="valueOf('path')"
        @filter="e => emit('filter', e)"
        @range="k => emit('range', k)"
        @more="emit('tab', 'pages')"
      />
      <TopListCard
        v-bind="card"
        by="referrer"
        title="Herkunft"
        description="Von welcher Website die Besucher kamen, nur die Domain."
        testid="overview-sources"
        more="Alle Quellen"
        :active-value="valueOf('referrer')"
        @filter="e => emit('filter', e)"
        @range="k => emit('range', k)"
        @more="emit('tab', 'sources')"
      />
      <OverviewCard
        title="Neu oder wiederkehrend"
        description="Besucher, die Schild in den 7 Tagen davor nicht gesehen hat, und die übrigen."
        testid="donut-new-returning"
        :state="newReturningState"
        :estimate="COPY.clientsEstimate"
        :offer-range="offer"
        :skeleton-rows="4"
        @range="emit('range', '48h')"
      >
        <DonutChart :slices="newReturning" label="Besucher: neu oder wiederkehrend" unit="Besucher">
          <template #caption>
            Nach einem Neustart von Schild zählt jeder Besucher erst einmal als neu.
          </template>
        </DonutChart>
      </OverviewCard>
    </div>

    <div v-if="ring" class="grid gap-4 md:grid-cols-2" data-testid="overview-clients">
      <TopListCard
        v-bind="card"
        by="ip"
        title="IP-Adressen"
        description="Welche Adressen am meisten angefragt haben, aus den einzelnen Anfragen."
        testid="overview-ips"
        more="Alle Adressen"
        :active-value="valueOf('ip')"
        @filter="e => emit('filter', e)"
        @range="k => emit('range', k)"
        @more="emit('tab', 'sources')"
      />
      <TopListCard
        v-bind="card"
        by="user_agent"
        title="User-Agents"
        description="Die vollständige Kennung, die Browser oder Bot mitschicken, aus den einzelnen Anfragen."
        testid="overview-user-agents"
        more="Alle User-Agents"
        :active-value="valueOf('user_agent')"
        @filter="e => emit('filter', e)"
        @range="k => emit('range', k)"
        @more="emit('tab', 'tech')"
      />
    </div>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <BreakdownDonutCard v-bind="card" kind="device" title="Geräte" testid="donut-device" :active-value="valueOf('device')" @filter="e => emit('filter', e)" @range="k => emit('range', k)" />
      <BreakdownDonutCard v-bind="card" kind="browser" title="Browser" testid="donut-browser" :active-value="valueOf('browser')" @filter="e => emit('filter', e)" @range="k => emit('range', k)" />
      <BreakdownDonutCard v-bind="card" kind="os" title="Betriebssystem" testid="donut-os" :active-value="valueOf('os')" @filter="e => emit('filter', e)" @range="k => emit('range', k)" />
    </div>

    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <BreakdownDonutCard
        v-bind="card"
        kind="status"
        title="Statuscodes"
        description="Wie deine Website geantwortet hat."
        testid="donut-status"
        :active-value="valueOf('status_class')"
        @filter="e => emit('filter', e)"
        @range="k => emit('range', k)"
      />
      <SecurityCard class="xl:col-span-2" :site="site" :kpis="kpis" :ring="ring" />
    </div>
  </div>
</template>
