<script setup lang="ts">
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, countryName, EmptyState, ErrorState, formatDateTime, formatNumber, RelativeTime, Skeleton, StatusPill } from '@schild/ui'
import { Info } from '@lucide/vue'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage, statusOf } from '@/api/client'
import { useOverview } from '@/api/queries'
import { useIncidents, useRequestRing, useWebsite, useWebsites } from '@/api/websites'
import EventList from '@/components/EventList.vue'
import RuleAlertsCard from '@/components/requests/RuleAlertsCard.vue'
import WebsiteHeader from '@/components/websites/WebsiteHeader.vue'
import { useRunningBlocks } from '@/composables/useRunningBlocks'
import { blockSourceText, INCIDENT_STATE, incidentReason, incidentState } from '@/lib/behaviour'
import { aggregateText } from '@/lib/incident'
import { NET_CLASSES } from '@/lib/monitoring'
import { websitePath } from '@/lib/nav'
import { contextLink } from '@/lib/requests'
import { partialView, plural } from '@/lib/summary'
import { incidentBlockText, WEBSITE_COPY } from '@/lib/websites'

/**
 * Ereignisse of one website (D68, what was Alarme plus the event list): running blocks and the incidents
 * (blocks with a number) of the last 7 days with how long a block lasts and why, "Alarme nach Regel", and
 * below every event of the website with filters, live view and the detail sheet. Blocks are gateway-wide
 * (D36): the page says so plainly. The events of all websites stay under /events.
 */
const route = useRoute()
const router = useRouter()
// MVP-22: "Kontext" per incident while the request ring runs.
const ringQ = useRequestRing()
const ring = computed(() => ringQ.data.value === true)
const site = computed(() => typeof route.params.site === 'string' ? route.params.site : '')
const websiteQ = useWebsite(site)
const website = computed(() => websiteQ.data.value?.website)
const notFound = computed(() => statusOf(websiteQ.error.value) === 404)
const all = useWebsites()
const total = computed(() => all.data.value?.websites.filter(w => w.protection !== 'unprotected').length ?? 0)
const overview = useOverview()
const observe = computed(() => overview.data.value?.profile === 'test')

// Exact counters of the last 24 hours of this website; "seit 14:32" or a gap hint when they do not
// cover the full window (D36 open items, traffic_24h_partial/_since), never "Näherungswert".
const day = computed(() => {
  const d = websiteQ.data.value
  if (!d?.traffic_24h) return null
  return {
    requests: d.traffic_24h.requests,
    stopped: d.traffic_24h.stopped,
    incidents: d.incidents_24h,
    partial: partialView(d.traffic_24h_partial, d.traffic_24h_since),
  }
})

const incidentsQ = useIncidents(site, 7)
const incidents = computed(() => incidentsQ.data.value?.items ?? [])
// Newest first (API order); the first 12, the rest on request.
const showAll = ref(false)
const shown = computed(() => showAll.value ? incidents.value : incidents.value.slice(0, 12))
const { blocks: runningBlocks } = useRunningBlocks(site)
// "Alarme nach Regel" (MVP-22): a click on a rule shows its requests on Zugriffe, tab Anfragen, filtered
// by the rule, over the 48 hours of the request ring.
function showRule(expr: string) {
  void router.push({ path: websitePath(site.value), query: { view: 'requests', time: '48h', filter: expr } })
}
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
      <WebsiteHeader :id="site" :website="website" title="Ereignisse" />

      <p class="mb-4 flex items-start gap-2 rounded-xl border bg-card p-4 text-sm" data-testid="block-scope">
        <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span>
          {{ WEBSITE_COPY.blockScope }} Wer eine Website angreift, kommt auch an die anderen nicht mehr heran, bis die Sperre endet oder du sie mit der Vorfallnummer aufhebst.
        </span>
      </p>

      <p v-if="day" class="mb-4 text-sm text-muted-foreground" data-testid="website-24h">
        Letzte 24 Stunden<template v-if="day.partial">
          <span :title="day.partial.text" data-testid="website-24h-partial">({{ day.partial.short }})</span>
        </template>: {{ plural(day.requests, 'Anfrage', 'Anfragen') }}, davon {{ formatNumber(day.stopped) }} gestoppt, {{ plural(day.incidents, 'Vorfall', 'Vorfälle') }}.
        <span v-if="day.partial" class="sr-only">{{ day.partial.text }}</span>
      </p>

      <Card v-if="runningBlocks.length" id="running-blocks" class="mb-4 scroll-mt-4" data-testid="running-blocks">
        <CardHeader>
          <CardTitle>Laufende Sperren</CardTitle>
          <CardDescription>Adressen, die gerade gesperrt sind, und wie lange die Sperre noch läuft.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul class="-mx-2 divide-y">
            <li v-for="h in runningBlocks" :key="h.id" class="flex flex-wrap items-baseline justify-between gap-2 px-2 py-2 text-sm">
              <span class="min-w-0">
                <RouterLink v-if="h.incident" :to="`/incidents/${h.incident}`" class="font-mono font-semibold underline-offset-4 hover:underline">{{ h.incident }}</RouterLink>
                <span class="text-muted-foreground"> · {{ blockSourceText(`behaviour:${h.scenario}`) }}</span>
              </span>
              <span class="text-xs text-muted-foreground" data-testid="block-duration">
                Gesperrt für {{ incidentBlockText({ duration_s: h.duration_s, net_class: h.geo?.net_class, level: h.level! }) }}<template v-if="h.until">
                  · endet <RelativeTime :value="h.until" />
                </template>
              </span>
            </li>
          </ul>
        </CardContent>
      </Card>

      <Card class="min-w-0" data-testid="incident-list">
        <CardHeader>
          <CardTitle>Vorfälle der letzten 7 Tage</CardTitle>
          <CardDescription>Jede Sperre hat eine Vorfallnummer. Damit findest du sie wieder und kannst sie aufheben.</CardDescription>
        </CardHeader>
        <CardContent>
          <ErrorState
            v-if="incidentsQ.isError.value && !incidentsQ.data.value"
            title="Die Vorfälle lassen sich gerade nicht laden"
            :description="errorMessage(incidentsQ.error.value)"
            :retrying="incidentsQ.isFetching.value"
            @retry="incidentsQ.refetch()"
          />
          <div v-else-if="incidentsQ.isPending.value" class="space-y-2">
            <Skeleton v-for="i in 4" :key="i" class="h-14 w-full" />
          </div>
          <p v-else-if="!incidents.length" class="text-sm text-muted-foreground">
            Keine Vorfälle in den letzten 7 Tagen.
          </p>
          <ul v-else class="-mx-2 divide-y">
            <li v-for="inc in shown" :key="inc.incident" class="px-2 py-3" :data-incident="inc.incident">
              <div class="flex flex-wrap items-baseline justify-between gap-2">
                <RouterLink :to="`/incidents/${inc.incident}`" class="font-mono text-sm font-semibold underline-offset-4 hover:underline">
                  {{ inc.incident }}
                </RouterLink>
                <span class="flex items-center gap-2 text-xs text-muted-foreground">
                  <RelativeTime :value="inc.time" />
                  <StatusPill :tone="INCIDENT_STATE[incidentState(inc)].tone" size="sm" data-testid="incident-list-status">
                    {{ INCIDENT_STATE[incidentState(inc)].label }}
                  </StatusPill>
                </span>
              </div>
              <p v-if="inc.reason" class="mt-0.5 truncate text-sm" :title="incidentReason(inc.reason)?.tooltip ?? undefined" data-testid="incident-reason">
                {{ incidentReason(inc.reason)?.title }}
              </p>
              <p class="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                <span v-if="inc.request.path" class="font-mono">{{ inc.request.method }} {{ inc.request.path }}</span>
                <span v-if="aggregateText(inc)" data-testid="incident-aggregate">{{ aggregateText(inc) }}</span>
                <span v-if="inc.request.geo">{{ countryName(inc.request.geo.country) }}<template v-if="inc.request.geo.net_class"> · {{ NET_CLASSES[inc.request.geo.net_class] ?? inc.request.geo.net_class }}</template></span>
                <span v-if="inc.sites_affected && inc.sites_affected.count > 1" class="font-medium text-foreground" data-testid="sites-affected">
                  {{ WEBSITE_COPY.sitesAffected(inc.sites_affected.count, inc.sites_affected.total || total) }}
                </span>
                <RouterLink v-if="ring" :to="contextLink(route, inc.request.id)" class="underline underline-offset-4 hover:no-underline" data-testid="incident-context">Kontext</RouterLink>
              </p>
              <p v-if="inc.block && incidentState(inc) === 'blocked'" class="mt-1 text-xs text-muted-foreground" data-testid="block-duration">
                Gesperrt für {{ incidentBlockText(inc.block) }} · {{ WEBSITE_COPY.blockScopeShort }}
              </p>
              <p v-else-if="inc.block && incidentState(inc) === 'ended'" class="mt-1 text-xs text-muted-foreground" data-testid="block-duration">
                Beendet um <time :datetime="inc.block.ended_at">{{ formatDateTime(inc.block.ended_at!) }}</time>
              </p>
            </li>
          </ul>
          <Button v-if="incidents.length > shown.length" variant="outline" size="sm" class="mt-2" @click="showAll = true">
            Alle {{ incidents.length }} Vorfälle zeigen
          </Button>
          <Button as-child variant="link" size="sm" class="mt-2 ml-3 h-auto p-0">
            <RouterLink to="/settings/rules/behaviour?view=detectors">
              Verteilte Wellen ansehen
            </RouterLink>
          </Button>
        </CardContent>
      </Card>

      <RuleAlertsCard v-if="ring" class="mt-4" :site="site" range="48h" :observe="observe" @filter="showRule" />

      <section class="mt-8" data-testid="website-events">
        <EventList :site="site" />
      </section>
    </template>
  </div>
</template>
