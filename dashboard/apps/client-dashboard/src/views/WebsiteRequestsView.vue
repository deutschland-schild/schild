<script setup lang="ts">
import type { PanelTab } from '@/components/websites/PanelCard.vue'
import type { WebsiteRangeKey } from '@/api/websites'
import type { RequestTabKey } from '@/lib/requests'
import type { KpiKey } from '@/lib/websites'
import { Button, Card, CardContent, EmptyState } from '@schild/ui'
import { X } from '@lucide/vue'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { statusOf } from '@/api/client'
import { isMonitoringOff, monitoringState } from '@/api/monitoring'
import { useOverview } from '@/api/queries'
import { isFilterUnavailable, ringCovers, ringKeptFrom, ringRange, useRealtime, useRequestRing, useWebsite, useWebsiteKpis, WEBSITE_RANGES } from '@/api/websites'
import BotsTab from '@/components/requests/BotsTab.vue'
import BreakdownDonutCard from '@/components/requests/BreakdownDonutCard.vue'
import CountriesTab from '@/components/requests/CountriesTab.vue'
import OutcomeTimeline from '@/components/requests/OutcomeTimeline.vue'
import PagesTab from '@/components/requests/PagesTab.vue'
import RequestList from '@/components/requests/RequestList.vue'
import RequestSearch from '@/components/requests/RequestSearch.vue'
import TrafficOverview from '@/components/requests/TrafficOverview.vue'
import AccessProtectionCard from '@/components/websites/AccessProtectionCard.vue'
import PanelCard from '@/components/websites/PanelCard.vue'
import RangePicker from '@/components/websites/RangePicker.vue'
import TrafficHeadline from '@/components/websites/TrafficHeadline.vue'
import WebsiteHeader from '@/components/websites/WebsiteHeader.vue'
import WebsiteStatusLine from '@/components/websites/WebsiteStatusLine.vue'
import { useWebsiteFilters } from '@/composables/useWebsiteFilters'
import { websitePath } from '@/lib/nav'
import { REQUEST_TABS, requestTabOf, REQUESTS_COPY } from '@/lib/requests'
import { kpiOf, WEBSITE_COPY, websiteName } from '@/lib/websites'

/**
 * Zugriffe, the start page of one website (MVP-22, D35, D36; D68 merged the old Überblick into it): a
 * status line with the Grundschutz and running blocks, then tabs like a small, cookie-free analytics view.
 * Überblick (KPI row, traffic and alarms on one axis with markers, "Letzte Alarme", Länder, donuts and top
 * lists), Seiten, Herkunft, Länder (with a built-in map), Bots & KI-Crawler, Technik, Fehler & Langsam and
 * the single requests (with what schild did per request over time). Numbers come from the monitoring
 * counters; the request ring answers filters, the list and Kontext. One filter state for the whole page.
 * State in the URL: view, time, metric, filter (repeated) and the list's own keys.
 */
const route = useRoute()
const router = useRouter()
const site = computed(() => typeof route.params.site === 'string' ? route.params.site : '')
const websiteQ = useWebsite(site)
const website = computed(() => websiteQ.data.value?.website)
const notFound = computed(() => statusOf(websiteQ.error.value) === 404)
const unprotected = computed(() => website.value?.protection === 'unprotected')

/**
 * The request ring (MVP-22) answers combined filters and breakdowns under a filter. Without it the rings
 * answer one filter (D36 fix round 1, measurement D.3: every filtered call answered 409), so the page
 * offers one filter at a time and keeps the tables unfiltered (useWebsiteFilters).
 */
const ringQ = useRequestRing()
const ring = computed(() => ringQ.data.value === true)
const ringKnown = computed(() => ringQ.isSuccess.value)
const { setQuery, range, filters, addFilter, removeFilter, chips, panelFilters, panelsUnfiltered, valueOf } = useWebsiteFilters(ring, ringKnown)

const tab = computed({
  get: () => requestTabOf(route.query.view),
  set: (v: RequestTabKey) => setQuery({ view: v === 'overview' ? undefined : v }),
})
/** Chart metric of the Überblick (a KPI click). */
const metric = computed({
  get: () => kpiOf(route.query.metric ?? 'visitors').key,
  set: (k: KpiKey) => setQuery({ metric: k === 'visitors' ? undefined : k }),
})
/** Tabs that need single requests (the ring); the others work from the monitoring counters. */
const RING_TABS: RequestTabKey[] = ['bots', 'requests']
const needsRing = computed(() => RING_TABS.includes(tab.value) && ringKnown.value && !ring.value)

const overview = useOverview()
const observe = computed(() => overview.data.value?.profile === 'test')
const kpisQ = useWebsiteKpis(() => ({ site: site.value, range: range.value, filters: filters.value }), () => !unprotected.value && !notFound.value)
const monitoringOff = computed(() => monitoringState.value === 'off' || isMonitoringOff(kpisQ.error.value))
const comboUnavailable = computed(() => isFilterUnavailable(kpisQ.error.value))
const on = computed(() => !monitoringOff.value && !unprotected.value && !notFound.value)
const ringAnswers = computed(() => ring.value && panelFilters.value.length === filters.value.length)

const realtimeQ = useRealtime(site, on)
const liveNow = computed(() => realtimeQ.data.value?.visitors_5m ?? null)

/** "Zeitraum verkürzen" of the panels asks for 48h: the longest range the request ring answers (D66). */
function setRange(k: WebsiteRangeKey) {
  range.value = k === '48h' && !ringCovers(range.value) ? ringRange() : k
}
/** Filters reach back only to the oldest single request kept (D66). */
const keptFromNote = computed(() => {
  const kept = ringKeptFrom.value
  if (!ring.value || !filters.value.length || kept === null || !ringCovers(range.value)) return null
  if (Date.now() - WEBSITE_RANGES[range.value].seconds * 1000 >= kept - 600_000) return null
  return WEBSITE_COPY.keptFrom(new Date(kept).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }))
})
function setTab(k: string) {
  tab.value = requestTabOf(k)
}
/** From a bot row to the list of its requests. */
function showRequests(q: Record<string, string>) {
  void router.replace({ query: { ...route.query, view: 'requests', ...q } })
}

/** The Diagramme page has the MVP-21 ranges (1 h, 6 h, 48 h, 14 days). */
const CHART_RANGE: Record<WebsiteRangeKey, string> = { 'echtzeit': '1h', '6h': '6h', '24h': '48h', '48h': '48h', '7d': '14d', '14d': '14d' }

const isAi = (k: string) => k.startsWith('ai:')
const ORIGIN: PanelTab[] = [
  { key: 'all', label: 'Quellen', by: 'referrer', columns: 'origin', top: 16 },
  { key: 'ai', label: 'KI-Assistenten', by: 'referrer', columns: 'origin', only: isAi, top: 32 },
]
const NETWORKS: PanelTab[] = [
  { key: 'net', label: 'Netzarten', by: 'net_class', columns: 'origin' },
  { key: 'asn', label: 'Netzbetreiber', by: 'asn', columns: 'origin' },
]
const TECH: { title: string, testid: string, tabs: PanelTab[] }[] = [
  { title: 'Browser', testid: 'panel-browser', tabs: [{ key: 'browser', label: 'Browser', by: 'browser', columns: 'traffic' }] },
  { title: 'Betriebssystem', testid: 'panel-os', tabs: [{ key: 'os', label: 'System', by: 'os', columns: 'traffic' }] },
  { title: 'Gerät', testid: 'panel-device', tabs: [{ key: 'device', label: 'Gerät', by: 'device', columns: 'traffic' }] },
  { title: 'Art des Clients', testid: 'panel-ua', tabs: [{ key: 'ua', label: 'Client', by: 'ua_class', columns: 'origin' }, { key: 'method', label: 'Methode', by: 'method', columns: 'origin' }] },
]
// D65: from the single requests only (D66: as long as the ring keeps them).
const CLIENTS: PanelTab[] = [
  { key: 'ip', label: 'IP-Adresse', by: 'ip', columns: 'origin', top: 16 },
  { key: 'ua', label: 'User-Agent', by: 'user_agent', columns: 'origin', top: 16 },
]
const USER_AGENTS: PanelTab[] = [{ key: 'ua', label: 'User-Agent', by: 'user_agent', columns: 'traffic', top: 16 }]
const CLIENTS_DESCRIPTION = 'Aus den einzelnen Anfragen. Ein Klick filtert die ganze Seite danach.'
const PAGES: PanelTab[] = [
  { key: 'path', label: 'Seite', by: 'path', columns: 'traffic', top: 16 },
  { key: 'attacked', label: 'Meistangegriffen', by: 'path', columns: 'pages', top: 16, byAttacks: true },
]
const TECH_DONUTS = [
  { kind: 'device', by: 'device', title: 'Geräte' },
  { kind: 'browser', by: 'browser', title: 'Browser' },
  { kind: 'os', by: 'os', title: 'Betriebssystem' },
] as const
const STATUS: PanelTab[] = [{ key: 'status', label: 'Status', by: 'status_class', columns: 'traffic' }]
const panelProps = computed(() => ({ site: site.value, range: range.value, filters: panelFilters.value, activeFilters: filters.value, offerRange: ring.value, observe: observe.value }))
</script>

<template>
  <div>
    <EmptyState v-if="notFound" :title="WEBSITE_COPY.notFoundTitle" :description="WEBSITE_COPY.notFound" data-testid="website-not-found">
      <Button as-child variant="outline" size="sm">
        <RouterLink to="/">
          Zu allen Websites
        </RouterLink>
      </Button>
    </EmptyState>
    <template v-else>
      <WebsiteHeader :id="site" :website="website" :title="REQUESTS_COPY.title">
        <template #actions>
          <button
            v-if="liveNow !== null"
            type="button"
            class="inline-flex items-center gap-1.5 rounded-full border bg-card px-3 py-1 text-sm font-medium hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring"
            :title="WEBSITE_COPY.liveNowTitle"
            data-testid="live-now"
            @click="range = 'echtzeit'"
          >
            <span class="relative flex size-2" aria-hidden="true"><span class="absolute inline-flex size-full rounded-full bg-status-success opacity-60 motion-safe:animate-ping" /><span class="relative inline-flex size-2 rounded-full bg-status-success" /></span>
            {{ WEBSITE_COPY.liveNow(liveNow) }}
          </button>
          <RequestSearch v-if="ring && on" :filters="filters" @update="f => setQuery({ filter: f })" />
          <RangePicker v-if="!unprotected" v-model="range" />
        </template>
      </WebsiteHeader>

      <p v-if="unprotected" class="rounded-xl border bg-card p-4 text-sm text-muted-foreground" data-testid="website-unprotected">
        {{ WEBSITE_COPY.unprotected }}
      </p>
      <template v-else>
        <WebsiteStatusLine :site="site" :website="website" />
        <AccessProtectionCard :site="site" :site-name="website ? websiteName(website) : site" banner />
      </template>

      <template v-if="unprotected" />
      <template v-else-if="monitoringOff">
        <p class="mb-4 rounded-xl border bg-card p-4 text-sm text-muted-foreground" data-testid="monitoring-off">
          {{ REQUESTS_COPY.monitoringOff }}
        </p>
        <TrafficHeadline :site="site" :range="range" :filters="filters" :ring="ring" :panels-unfiltered="panelsUnfiltered" :observe="observe" :metric="metric" monitoring-off />
      </template>
      <template v-else>
        <nav class="-mx-1 mb-4 overflow-x-auto" aria-label="Bereiche der Zugriffe">
          <div role="tablist" class="flex min-w-max gap-1 border-b px-1">
            <button
              v-for="t in REQUEST_TABS"
              :key="t.key"
              type="button"
              role="tab"
              :aria-selected="tab === t.key"
              :class="['-mb-px border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors focus-visible:outline-2 focus-visible:outline-ring', tab === t.key ? 'border-foreground text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground']"
              :data-tab="t.key"
              @click="tab = t.key"
            >
              {{ t.label }}
            </button>
          </div>
        </nav>

        <div v-if="chips.length" class="mb-3 flex flex-wrap items-center gap-2" aria-label="Filter" role="group" data-testid="filter-chips">
          <span class="text-xs text-muted-foreground">Gefiltert nach</span>
          <span v-for="c in chips" :key="c.expr" class="inline-flex items-center gap-1 rounded-full border bg-card py-0.5 pr-1 pl-2.5 text-sm" :data-filter="c.expr">
            <span class="text-muted-foreground">{{ c.label }}:</span>
            <span class="max-w-56 truncate font-medium" :title="c.value">{{ c.value }}</span>
            <button type="button" class="rounded-full p-0.5 hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring" :aria-label="`Filter ${c.label} ${c.value} entfernen`" @click="removeFilter(c.expr)">
              <X class="size-3.5" aria-hidden="true" />
            </button>
          </span>
          <Button v-if="chips.length > 1" variant="link" size="sm" class="h-auto p-0 text-xs" @click="setQuery({ filter: [] })">
            {{ WEBSITE_COPY.removeFilters }}
          </Button>
        </div>
        <p v-if="keptFromNote" class="mb-3 text-sm text-muted-foreground" data-testid="kept-from">
          {{ keptFromNote }}
        </p>
        <p v-if="panelsUnfiltered && tab !== 'requests' && !(tab === 'overview' && comboUnavailable)" class="mb-3 text-sm text-muted-foreground" data-testid="panels-unfiltered">
          {{ ring ? WEBSITE_COPY.panelsUnfilteredRing : `${WEBSITE_COPY.panelsUnfiltered} ${WEBSITE_COPY.oneFilter}` }}
          <Button v-if="ring" variant="link" size="sm" class="h-auto p-0 text-sm" @click="setRange('48h')">
            {{ WEBSITE_COPY.to48h }}
          </Button>
        </p>
        <Card v-if="ringKnown && !ring" class="mb-4 border-dashed" data-testid="ring-off">
          <CardContent class="text-sm">
            <p class="font-medium">
              {{ REQUESTS_COPY.ringOffTitle }}
            </p>
            <p class="mt-1 text-muted-foreground">
              {{ REQUESTS_COPY.ringOff }}
            </p>
          </CardContent>
        </Card>

        <template v-if="needsRing" />
        <div v-else-if="tab === 'overview'" data-testid="tab-overview">
          <TrafficHeadline
            v-model:metric="metric"
            :site="site"
            :range="range"
            :filters="filters"
            :ring="ring"
            :panels-unfiltered="panelsUnfiltered"
            :observe="observe"
            @range="setRange"
            @filters="f => setQuery({ filter: f })"
          />
          <TrafficOverview
            :site="site"
            :range="range"
            :filters="filters"
            :panel-filters="panelFilters"
            :ring="ring"
            :ring-answers="ringAnswers"
            :value-of="valueOf"
            @filter="addFilter"
            @range="setRange"
            @tab="setTab"
          />
        </div>
        <PagesTab v-else-if="tab === 'pages' && ring" :site="site" :range="range" :observe="observe" :active-path="valueOf('path')" @filter="addFilter" />
        <!-- Without the ring: pages from the monitoring top lists (no status mix or p95 per page). -->
        <PanelCard v-else-if="tab === 'pages'" v-bind="panelProps" title="Seiten" :tabs="PAGES" testid="panel-pages" @filter="addFilter" @range="setRange" />
        <div v-else-if="tab === 'sources'" class="grid gap-4 lg:grid-cols-2" data-testid="tab-sources">
          <PanelCard v-bind="panelProps" title="Herkunft" :tabs="ORIGIN" testid="panel-referrer" description="Von welcher Website die Besucher kamen (nur die Domain). KI-Assistenten wie ChatGPT sind zusammengefasst." @filter="addFilter" @range="setRange" />
          <PanelCard v-bind="panelProps" title="Netze" :tabs="NETWORKS" testid="panel-networks" @filter="addFilter" @range="setRange" />
          <PanelCard v-if="ring" v-bind="panelProps" title="Adressen und Kennungen" :tabs="CLIENTS" testid="panel-clients" :description="CLIENTS_DESCRIPTION" class="lg:col-span-2" @filter="addFilter" @range="setRange" />
        </div>
        <CountriesTab v-else-if="tab === 'countries'" :site="site" :range="range" :filters="panelFilters" :active-country="valueOf('country')" :offer-range="ring" @filter="addFilter" @range="setRange" />
        <BotsTab v-else-if="tab === 'bots'" :site="site" :range="range" :active-category="valueOf('bot_category')" @filter="addFilter" @requests="showRequests" />
        <div v-else-if="tab === 'tech'" class="grid gap-4 lg:grid-cols-2" data-testid="tab-tech">
          <div class="grid gap-4 md:grid-cols-3 lg:col-span-2">
            <BreakdownDonutCard v-for="d in TECH_DONUTS" :key="d.kind" :kind="d.kind" :title="d.title" :testid="`technik-${d.kind}`" :site="site" :range="range" :filters="panelFilters" :offer-range="ring" :active-value="valueOf(d.by)" @filter="addFilter" @range="setRange" />
          </div>
          <PanelCard v-for="p in TECH" :key="p.testid" v-bind="panelProps" :title="p.title" :tabs="p.tabs" :testid="p.testid" @filter="addFilter" @range="setRange" />
          <PanelCard v-if="ring" v-bind="panelProps" title="User-Agents" :tabs="USER_AGENTS" testid="panel-user-agents" :description="CLIENTS_DESCRIPTION" class="lg:col-span-2" @filter="addFilter" @range="setRange" />
          <p class="text-xs text-muted-foreground lg:col-span-2">
            Browser, System und Gerät liest Schild aus der Kennung, die der Browser mitschickt, ohne Versionen. Weitere Angaben fragt Schild nicht ab.
          </p>
        </div>
        <div v-else-if="tab === 'errors'" class="grid gap-4 lg:grid-cols-2" data-testid="tab-errors">
          <PanelCard v-bind="panelProps" title="Statuscodes" :tabs="STATUS" testid="panel-status" @filter="addFilter" @range="setRange" />
          <template v-if="ring">
            <PagesTab :site="site" :range="range" :observe="observe" mode="slow" @filter="addFilter" />
            <PagesTab class="lg:col-span-2" :site="site" :range="range" :observe="observe" mode="errors" @filter="addFilter" />
          </template>
          <p v-else class="text-sm text-muted-foreground">
            Fehler und Antwortzeit pro Seite rechnet Schild aus den einzelnen Anfragen. Ohne Zugriffsprotokoll findest du die Antwortzeiten der ganzen Website unter Diagramme.
          </p>
        </div>
        <div v-else-if="tab === 'requests'" class="space-y-4">
          <OutcomeTimeline :site="site" :range="range" :filters="filters" :ring-answers="ringAnswers" :observe="observe" @range="setRange" />
          <RequestList :site="site" :filters="filters" />
        </div>

        <p class="mt-6 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span>{{ WEBSITE_COPY.filterHint }} Besucher sind ein {{ WEBSITE_COPY.estimate }} ohne erkannte Bots: verschiedene Adressen pro Tag.</span>
          <RouterLink :to="{ path: websitePath(site, 'charts'), query: { time: CHART_RANGE[range] } }" class="underline underline-offset-4 hover:no-underline">
            Weitere Diagramme: Statuscodes, Antwortzeit, Datenmenge
          </RouterLink>
        </p>
        <p class="mt-2 text-xs text-muted-foreground">
          {{ REQUESTS_COPY.privacy }}
        </p>
      </template>
    </template>
  </div>
</template>
