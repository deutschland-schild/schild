<script setup lang="ts">
import { Button, ErrorState, formatMs, formatNumber, Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, Skeleton } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage, statusOf } from '@/api/client'
import { isRequestsOff, isRingBusy, useRequestContext } from '@/api/requests'
import { useWebsites } from '@/api/websites'
import { websitePath } from '@/lib/nav'
import { CONTEXT_PARAM, CONTEXT_STATES, contextIdOf, isAlert, offsetText, pathText, PATTERNS, REQUEST_OUTCOMES, REQUESTS_COPY, visitorSummaryText } from '@/lib/requests'
import { BROWSERS, keyLabel } from '@/lib/monitoring'
import { WEBSITE_COPY, websiteName } from '@/lib/websites'
import RequestOutcomeBadge from './RequestOutcomeBadge.vue'
import SiteStrip from './SiteStrip.vue'

/**
 * "Kontext" of an event (getRequestContext, MVP-22): what the same visitor did 5 minutes before and after,
 * in order, with the event's request highlighted, the visitor pattern (scanner or a visitor in a normal
 * session), the website-wide strip of the same window and how many websites the client touched. Opens
 * from every page with ?context=<event id> (incidents, events, Letzte Alarme, the request list).
 */
const route = useRoute()
const router = useRouter()
const id = computed(() => contextIdOf(route.query[CONTEXT_PARAM]))
const open = computed({
  get: () => !!id.value,
  set: (v: boolean) => {
    if (v) return
    const { [CONTEXT_PARAM]: _drop, ...query } = route.query
    void router.replace({ query })
  },
})
const q = useRequestContext(id)
const ctx = computed(() => q.data.value)
const all = useWebsites()
const names = computed(() => new Map((all.data.value?.websites ?? []).map(w => [w.id, websiteName(w)])))
const state = computed(() => ctx.value ? CONTEXT_STATES[ctx.value.state] : null)
const pattern = computed(() => ctx.value?.visitor_summary ? PATTERNS[ctx.value.visitor_summary.pattern] : null)
const anchorT = computed(() => ctx.value?.anchor?.t ?? null)

const hms = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const hm = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
const windowText = computed(() => ctx.value ? `${hm.format(new Date(ctx.value.from))} bis ${hms.format(new Date(ctx.value.to))}` : '')
const rows = computed(() => (ctx.value?.visitor_requests ?? []).map((r, i) => ({
  r,
  key: `${r.t}-${i}`,
  time: hms.format(new Date(r.t)),
  offset: anchorT.value ? offsetText(r.t, anchorT.value) : '',
  anchor: !!ctx.value?.anchor && (r.event_id ? r.event_id === ctx.value.event_id : false),
  alert: isAlert(r),
})))
const visitor = computed(() => ctx.value?.anchor?.visitor ?? null)
const site = computed(() => ctx.value?.anchor?.site ?? '')
const who = computed(() => {
  const a = ctx.value?.anchor
  if (!a) return ''
  return [keyLabel('country', a.country), a.net_class ? keyLabel('net_class', a.net_class) : '', a.browser !== 'none' ? BROWSERS[a.browser] : '', a.bot ? `Bot ${a.bot}` : ''].filter(Boolean).join(' · ')
})
/** With an address all of its requests; a record from before D49 opens the 6 h that hold it. */
const listLink = computed(() => {
  const a = ctx.value?.anchor
  if (!a || !visitor.value || !site.value) return null
  const end = Math.floor((Date.now() - Date.parse(a.t)) / 21_600_000) * 6
  return { path: websitePath(site.value), query: { view: 'requests', ...(a.ip ? { filter: `ip:${a.ip}` } : { visitor: visitor.value, window: '6h', until: String(end) }) } }
})
const off = computed(() => isRequestsOff(q.error.value))
const notFound = computed(() => statusOf(q.error.value) === 404 && !off.value)
</script>

<template>
  <Sheet v-model:open="open">
    <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-2xl xl:max-w-3xl" data-testid="context-sheet">
      <SheetHeader class="border-b">
        <SheetTitle>Kontext</SheetTitle>
        <SheetDescription>
          Was derselbe Besucher 5 Minuten vor und nach diesem Ereignis getan hat<template v-if="windowText">, {{ windowText }}</template>.
        </SheetDescription>
      </SheetHeader>
      <div class="space-y-5 p-4 text-sm">
        <div v-if="q.isPending.value" class="space-y-3" aria-busy="true">
          <Skeleton class="h-6 w-56" />
          <Skeleton class="h-16 w-full" />
          <Skeleton class="h-40 w-full" />
        </div>
        <p v-else-if="off" class="rounded-lg border bg-card p-4 text-muted-foreground" data-testid="context-off">
          {{ REQUESTS_COPY.ringOff }}
        </p>
        <p v-else-if="notFound" class="rounded-lg border bg-card p-4 text-muted-foreground">
          Zu diesem Ereignis gibt es keinen Kontext. Vielleicht wurde es inzwischen gelöscht.
        </p>
        <ErrorState v-else-if="q.isError.value" title="Der Kontext lässt sich gerade nicht laden" :description="isRingBusy(q.error.value) ? REQUESTS_COPY.busy : errorMessage(q.error.value)" :retrying="q.isFetching.value" @retry="q.refetch()" />
        <template v-else-if="ctx">
          <p v-if="state" class="rounded-lg border border-dashed bg-card p-3" :data-state="ctx.state" data-testid="context-state">
            <span class="font-medium">{{ ctx.state === 'expired' ? `Kontext ${state.label}` : state.label }}.</span>
            <span class="text-muted-foreground"> {{ state.explain }}</span>
          </p>

          <section v-if="ctx.visitor_summary" class="space-y-1" aria-label="Besucher">
            <div class="flex flex-wrap items-center gap-2">
              <span class="rounded-full border px-2 py-0.5 text-xs font-medium" :class="ctx.visitor_summary.pattern === 'alert_only' ? 'border-transparent bg-foreground/85 text-background' : 'bg-card'" :title="pattern?.explain" data-testid="context-pattern">
                {{ pattern?.label }}
              </span>
              <span class="text-muted-foreground tabular-nums">{{ visitorSummaryText(ctx.visitor_summary) }}</span>
            </div>
            <p class="text-xs text-muted-foreground">
              {{ pattern?.explain }}<template v-if="who">
                Besucher: {{ who }}.
              </template>
              Der Besucherschlüssel ist pseudonym und gilt nur für diesen Tag.
            </p>
            <p v-if="ctx.anchor?.user_agent" class="font-mono text-xs break-all text-muted-foreground" data-testid="context-ua">
              {{ ctx.anchor.user_agent }}
            </p>
          </section>

          <p v-if="ctx.sites_affected" class="text-sm" data-testid="context-sites">
            <span class="font-medium">{{ WEBSITE_COPY.sitesAffected(ctx.sites_affected.count, ctx.sites_affected.total) }}</span>
            <span v-if="ctx.sites_affected.count > 1" class="text-muted-foreground">: {{ ctx.sites_affected.sites.map(s => names.get(s) ?? s).join(', ') }}<template v-if="ctx.sites_affected.count > ctx.sites_affected.sites.length"> und weitere</template></span>
            <span class="text-muted-foreground"> (in den 24 Stunden davor)</span>
          </p>

          <section v-if="ctx.site_strip.length" aria-label="Ganze Website">
            <h3 class="mb-1 text-sm font-medium">
              Die ganze Website in diesen 10 Minuten
            </h3>
            <SiteStrip :points="ctx.site_strip" :anchor="anchorT" />
          </section>

          <section v-if="rows.length" aria-label="Anfragen dieses Besuchers">
            <h3 class="mb-1 text-sm font-medium">
              Anfragen dieses Besuchers, der Reihe nach
            </h3>
            <ol class="divide-y rounded-lg border" data-testid="context-requests">
              <li
                v-for="x in rows"
                :key="x.key"
                class="grid grid-cols-[4.5rem_1fr_auto] items-baseline gap-x-2 px-2 py-1.5"
                :class="x.anchor ? 'bg-muted font-medium' : ''"
                :data-anchor="x.anchor ? 'true' : undefined"
                :aria-current="x.anchor ? 'true' : undefined"
              >
                <span class="font-mono text-xs text-muted-foreground tabular-nums" :title="x.time">{{ x.offset || x.time }}</span>
                <span class="min-w-0">
                  <span class="block truncate"><span class="mr-1.5 rounded bg-muted px-1 py-0.5 font-mono text-[11px]">{{ x.r.method }}</span><span class="font-mono text-[13px]">{{ pathText(x.r.path) }}</span></span>
                  <span class="block text-xs text-muted-foreground">
                    {{ x.r.status }} · {{ formatMs(x.r.duration_ms) }}<template v-if="x.r.rules?.length"> · Regel {{ x.r.rules.join(', ') }}</template><template v-if="x.anchor"> · dieses Ereignis</template>
                  </span>
                </span>
                <RequestOutcomeBadge :outcome="x.r.outcome" :title="REQUEST_OUTCOMES[x.r.outcome].detail" />
              </li>
            </ol>
            <p v-if="ctx.truncated" class="mt-1 text-xs text-muted-foreground">
              Mehr als {{ formatNumber(1000) }} Anfragen in diesem Zeitraum, gezeigt werden die ersten {{ formatNumber(1000) }}.
            </p>
          </section>

          <div class="flex flex-wrap gap-2 border-t pt-4">
            <Button as-child size="sm" variant="outline">
              <RouterLink :to="{ path: '/events', query: { event: ctx.event_id, time: '7d' } }">
                Ereignis öffnen
                <ArrowRight aria-hidden="true" />
              </RouterLink>
            </Button>
            <Button v-if="listLink" as-child size="sm" variant="ghost">
              <RouterLink :to="listLink" data-testid="context-visitor-list">
                Alle Anfragen dieses Besuchers
              </RouterLink>
            </Button>
          </div>
        </template>
      </div>
    </SheetContent>
  </Sheet>
</template>
