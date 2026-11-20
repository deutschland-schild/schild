<script setup lang="ts">
import type { WebsiteSummary } from '@/api/websites'
import { formatMs, formatNumber, Sparkline, StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { useWebsiteKpis, useWebsiteSeries } from '@/api/websites'
import { ratioText } from '@/lib/monitoring'
import { websitePath } from '@/lib/nav'
import { reasonText, runsOnText, STATUS, WEBSITE_COPY, websiteName } from '@/lib/websites'

/**
 * One website on the start page (D36): status in words with its reasons, where it runs, and its last 24 hours:
 * requests, share stopped, response time (p95) and the requests as a small trend. 24 hours, not the last
 * minute: on a small website the last minute is empty most of the time (initiator 2026-11-15).
 */
const props = defineProps<{ website: WebsiteSummary, observe?: boolean }>()
const w = computed(() => props.website)
// The 24 hour numbers come from the stored rings: they are there after a restart, also before the website's first
// request since then (now is the in-memory part and still missing).
const tracked = computed(() => w.value.protection !== 'unprotected' && w.value.tracked && !w.value.reasons.some(r => r.code === 'monitoring_off'))
const spark = useWebsiteSeries(() => ({ site: w.value.id, range: '24h' as const, filters: [], metrics: ['traffic.requests:rate'] }), tracked)
const trend = computed(() => spark.data.value?.series[0]?.values ?? [])
const reasons = computed(() => w.value.reasons)
const kpis = useWebsiteKpis(() => ({ site: w.value.id, range: '24h' as const, filters: [] }), tracked)
const day = computed(() => kpis.data.value?.current)
const requests = computed(() => day.value?.requests.value ?? null)
const share = computed(() => {
  const n = requests.value
  const part = props.observe ? day.value?.would_block.value : day.value?.stopped.value
  return n && part !== null && part !== undefined ? part / n : null
})
</script>

<template>
  <RouterLink
    :to="websitePath(w.id)"
    class="group flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 transition-colors hover:bg-muted/40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
    :data-website="w.id"
    data-testid="website-card"
  >
    <div class="flex items-start justify-between gap-2">
      <div class="min-w-0">
        <p class="truncate text-base font-semibold group-hover:underline group-hover:underline-offset-4">
          {{ websiteName(w) }}
        </p>
        <p class="truncate text-xs text-muted-foreground">
          {{ runsOnText(w.runs_on) }}<template v-if="w.runs_on.length === 1">
            ({{ w.runs_on[0]!.node }})
          </template>
        </p>
      </div>
      <StatusPill :tone="STATUS[w.status].tone" size="sm">
        {{ STATUS[w.status].label }}
      </StatusPill>
    </div>
    <ul v-if="reasons.length" class="space-y-0.5 text-sm" data-testid="card-reasons">
      <li v-for="(r, i) in reasons.slice(0, 3)" :key="i" class="truncate">
        {{ reasonText(r) }}
      </li>
      <li v-if="reasons.length > 3" class="text-xs text-muted-foreground">
        und {{ reasons.length - 3 }} weitere
      </li>
    </ul>
    <template v-if="tracked">
      <dl class="grid grid-cols-3 gap-2 text-sm">
        <div>
          <dt class="text-xs text-muted-foreground">
            {{ WEBSITE_COPY.requests24h }}
          </dt>
          <dd class="text-lg font-semibold tabular-nums" data-testid="card-requests">
            {{ requests === null ? '–' : formatNumber(requests) }}
          </dd>
        </div>
        <div>
          <dt class="text-xs text-muted-foreground">
            {{ observe ? 'erkannt' : WEBSITE_COPY.stoppedShare }}
          </dt>
          <dd class="text-lg font-semibold tabular-nums">
            {{ ratioText(share) }}
          </dd>
        </div>
        <div>
          <dt class="text-xs text-muted-foreground" :title="WEBSITE_COPY.p95Explain">
            {{ WEBSITE_COPY.p95 }}
          </dt>
          <dd class="text-lg font-semibold tabular-nums" :title="WEBSITE_COPY.p95Explain">
            {{ formatMs(day?.latency_p95_ms.value ?? null) }}
          </dd>
        </div>
      </dl>
      <Sparkline :values="trend" :label="`Anfragen von ${websiteName(w)}, letzte 24 Stunden`" :width="320" :height="36" class="h-9 w-full" />
    </template>
    <p v-else class="text-sm text-muted-foreground">
      {{ w.protection === 'unprotected' ? WEBSITE_COPY.unprotected : !w.tracked ? WEBSITE_COPY.untracked : WEBSITE_COPY.noNumbers }}
    </p>
  </RouterLink>
</template>
