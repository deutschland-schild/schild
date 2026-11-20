<script setup lang="ts">
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, PageHeader, RelativeTime, Skeleton, StatusPill } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import { useOverview } from '@/api/queries'
import { useIncidents, useWebsites } from '@/api/websites'
import WebsiteCard from '@/components/websites/WebsiteCard.vue'
import { incidentReason } from '@/lib/behaviour'
import { baselineView } from '@/lib/summary'
import { WEBSITE_COPY, websiteName } from '@/lib/websites'

/**
 * "Alle Websites", the start page (D36 amendment 2026-10-31): the protection line, every website as a
 * card with its status, and attacks that reached several websites, so a problem shows at once.
 */
const websitesQ = useWebsites()
const list = computed(() => websitesQ.data.value)
const overview = useOverview()
const o = computed(() => overview.data.value)
const gs = computed(() => o.value ? baselineView(o.value) : null)
const observe = computed(() => o.value?.profile === 'test')
const monitoringOff = computed(() => !!list.value?.websites.length && list.value.websites.every(w => w.reasons.some(r => r.code === 'monitoring_off')))
const names = computed(() => new Map((list.value?.websites ?? []).map(w => [w.id, websiteName(w)])))
const protectedTotal = computed(() => list.value?.websites.filter(w => w.protection !== 'unprotected').length ?? 0)

// Attacks on several websites: blocks are gateway-wide, so one client touching many websites is the
// clearest sign of a scan across this server.
const incidentsQ = useIncidents('', 7)
const crossSite = computed(() => (incidentsQ.data.value?.items ?? []).filter(i => (i.sites_affected?.count ?? 0) > 1))
const shownCrossSite = computed(() => crossSite.value.slice(0, 6))
const affectedNames = (sites: string[]) => sites.map(s => names.value.get(s) ?? s).join(', ')
</script>

<template>
  <div>
    <PageHeader title="Alle Websites" description="Was auf deinen Websites los ist, wer mehrere davon angreift und was du dir ansehen solltest." />

    <div v-if="gs && o" class="mb-5 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border bg-card px-4 py-3 text-sm" data-testid="protection-line">
      <StatusPill :tone="gs.tone" size="sm">
        {{ gs.pill }}
      </StatusPill>
      <span class="min-w-0 flex-1 basis-56 text-muted-foreground">
        {{ gs.subtitle }}
      </span>
      <Button as-child variant="link" size="sm" class="h-auto p-0">
        <RouterLink to="/settings">
          Details ansehen
          <ArrowRight aria-hidden="true" />
        </RouterLink>
      </Button>
    </div>

    <section aria-labelledby="websites-title" class="mb-6" data-testid="server-websites">
      <div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="websites-title" class="sr-only">
          Websites
        </h2>
        <p v-if="list" class="text-xs text-muted-foreground">
          {{ list.websites.length }} {{ list.websites.length === 1 ? 'Website läuft' : 'Websites laufen' }} auf diesem Server
        </p>
      </div>
      <p v-if="monitoringOff" class="mb-4 rounded-xl border bg-card p-4 text-sm text-muted-foreground" data-testid="websites-monitoring-off">
        {{ WEBSITE_COPY.monitoringOff }}
      </p>
      <ErrorState
        v-if="websitesQ.isError.value && !list"
        title="Die Websites lassen sich gerade nicht laden"
        :description="errorMessage(websitesQ.error.value)"
        :retrying="websitesQ.isFetching.value"
        @retry="websitesQ.refetch()"
      />
      <div v-else-if="!list" class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Skeleton v-for="i in 3" :key="i" class="h-52 rounded-xl" />
      </div>
      <template v-else>
        <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3" data-testid="website-cards">
          <WebsiteCard v-for="w in list.websites" :key="w.id" :website="w" :observe="observe" />
        </div>
        <p v-if="list.other" class="mt-3 text-sm text-muted-foreground">
          {{ WEBSITE_COPY.otherWebsites(list.other.websites) }}
        </p>
        <p class="mt-3 text-xs text-muted-foreground">
          Die Zahlen gelten für die letzten 24 Stunden, der Status für die letzten 5 Minuten. Antwortzeit: 95 von 100 Anfragen waren schneller. „Bitte ansehen“ heißt: Es gibt einen Hinweis zur Website oder zu diesem Server, die Website läuft aber.
        </p>
      </template>
    </section>

    <Card data-testid="cross-site">
      <CardHeader>
        <CardTitle>Alarme auf mehreren Websites</CardTitle>
        <CardDescription>Vorfälle der letzten 7 Tage, bei denen dieselbe Adresse mehr als eine Website angefragt hat. {{ WEBSITE_COPY.blockScope }}</CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="incidentsQ.isPending.value" class="space-y-2">
          <Skeleton v-for="i in 3" :key="i" class="h-12 w-full" />
        </div>
        <p v-else-if="incidentsQ.isError.value && !incidentsQ.data.value" class="text-sm text-muted-foreground">
          Die Vorfälle lassen sich gerade nicht laden.
        </p>
        <p v-else-if="!crossSite.length" class="text-sm text-muted-foreground" data-testid="cross-site-empty">
          In den letzten 7 Tagen hat keine Adresse mehrere Websites zugleich angefragt.
        </p>
        <ul v-else class="-mx-2 divide-y">
          <li v-for="inc in shownCrossSite" :key="inc.incident" class="px-2 py-3" :data-incident="inc.incident">
            <div class="flex flex-wrap items-baseline justify-between gap-2">
              <RouterLink :to="`/incidents/${inc.incident}`" class="font-mono text-sm font-semibold underline-offset-4 hover:underline">
                {{ inc.incident }}
              </RouterLink>
              <RelativeTime :value="inc.time" class="text-xs text-muted-foreground" />
            </div>
            <p v-if="inc.reason" class="mt-0.5 truncate text-sm">
              {{ incidentReason(inc.reason)?.title }}
            </p>
            <p class="mt-1 text-xs text-muted-foreground">
              <span class="font-medium text-foreground" data-testid="sites-affected">{{ WEBSITE_COPY.sitesAffected(inc.sites_affected!.count, inc.sites_affected!.total || protectedTotal) }}</span>:
              {{ affectedNames(inc.sites_affected!.sites) }}<template v-if="inc.sites_affected!.count > inc.sites_affected!.sites.length">
                und weitere
              </template>
            </p>
          </li>
        </ul>
        <Button as-child variant="link" size="sm" class="mt-2 h-auto p-0">
          <RouterLink to="/incidents">
            Alle Vorfälle
            <ArrowRight aria-hidden="true" />
          </RouterLink>
        </Button>
      </CardContent>
    </Card>
  </div>
</template>
