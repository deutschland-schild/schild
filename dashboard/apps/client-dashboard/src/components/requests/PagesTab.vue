<script setup lang="ts">
import type { PageAlert } from '@/api/requests'
import type { WebsiteRangeKey } from '@/api/websites'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatMs, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import { isRingBusy, usePageAlerts } from '@/api/requests'
import EstimateNote from '@/components/monitoring/EstimateNote.vue'
import { TONES } from '@/lib/monitoring'
import { REQUESTS_COPY } from '@/lib/requests'

/**
 * Seiten (getPageAlerts, MVP-22): every page with its requests and alert rate next to each other, the
 * status mix and p95 from the request ring, and a calm "bitte ansehen" where alerts in observe mode were
 * answered 2xx by the app. A click on a page filters the whole Zugriffe page.
 */
const props = withDefaults(defineProps<{
  site: string
  range: WebsiteRangeKey
  observe?: boolean
  activePath?: string | null
  /** Errors & slow view: sort by 5xx, then by p95. */
  mode?: 'pages' | 'errors' | 'slow'
}>(), { observe: false, activePath: null, mode: 'pages' })
const emit = defineEmits<{ filter: [expr: string] }>()

const q = usePageAlerts(() => ({ site: props.site, range: props.range, top: 40 }))
const total = (p: PageAlert) => p.status ? p.status.s1xx + p.status.s2xx + p.status.s3xx + p.status.s4xx + p.status.s5xx : 0
const rows = computed(() => {
  let items = [...(q.data.value?.items ?? [])]
  if (props.mode === 'errors') items = items.filter(p => (p.status?.s5xx ?? 0) > 0).sort((a, b) => (b.status!.s5xx / Math.max(1, total(b))) - (a.status!.s5xx / Math.max(1, total(a))))
  if (props.mode === 'slow') items = items.filter(p => typeof p.latency_p95_ms === 'number').sort((a, b) => (b.latency_p95_ms ?? 0) - (a.latency_p95_ms ?? 0)).slice(0, 10)
  return items.map((p) => {
    const n = total(p)
    const seg = (v: number) => n ? (v / n) * 100 : 0
    return {
      p,
      share5xx: n ? p.status!.s5xx / n : null,
      bar: p.status ? [
        { w: seg(p.status.s2xx + p.status.s1xx), c: TONES.wash, label: '2xx' },
        { w: seg(p.status.s3xx), c: TONES.light, label: '3xx' },
        { w: seg(p.status.s4xx), c: TONES.deep, label: '4xx' },
        { w: seg(p.status.s5xx), c: TONES.neutral, label: '5xx' },
      ] : [],
      statusTitle: p.status ? `2xx ${formatNumber(p.status.s2xx)} · 3xx ${formatNumber(p.status.s3xx)} · 4xx ${formatNumber(p.status.s4xx)} · 5xx ${formatNumber(p.status.s5xx)}` : 'Nur für die letzten 48 Stunden',
    }
  })
})
const estimate = computed(() => rows.value.some(r => r.p.error > 0))
const title = computed(() => props.mode === 'errors' ? 'Seiten mit Serverfehlern (5xx)' : props.mode === 'slow' ? 'Langsamste Seiten' : 'Seiten')
</script>

<template>
  <Card class="min-w-0" :data-testid="mode === 'pages' ? 'pages-tab' : `pages-${mode}`">
    <CardHeader>
      <div class="flex flex-wrap items-center gap-2">
        <CardTitle>{{ title }}</CardTitle>
        <EstimateNote v-if="estimate" text="Näherungswert: Seiten außerhalb der Rangliste können etwas zu hoch erscheinen." />
      </div>
      <CardDescription v-if="mode === 'pages'">
        Anfragen und Alarme pro Seite. Status und Antwortzeit stammen aus den einzelnen Anfragen. Klick auf eine Seite filtert die ganze Ansicht.
      </CardDescription>
      <CardDescription v-else-if="mode === 'errors'">
        Seiten, auf denen deine App mit 5xx geantwortet hat, nach Anteil.
      </CardDescription>
      <CardDescription v-else>
        Antwortzeit je Seite: 95 von 100 Anfragen waren schneller.
      </CardDescription>
    </CardHeader>
    <CardContent>
      <div v-if="q.isPending.value" class="space-y-2">
        <Skeleton v-for="i in 6" :key="i" class="h-8 w-full" />
      </div>
      <ErrorState v-else-if="q.isError.value" title="Die Seiten lassen sich gerade nicht laden" :description="isRingBusy(q.error.value) ? REQUESTS_COPY.busy : errorMessage(q.error.value)" :retrying="q.isFetching.value" @retry="q.refetch()" />
      <p v-else-if="!rows.length" class="text-sm text-muted-foreground">
        {{ mode === 'errors' ? 'Keine Serverfehler in diesem Zeitraum.' : 'Noch keine Anfragen in diesem Zeitraum.' }}
      </p>
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm tabular-nums" :class="mode === 'pages' ? 'min-w-[640px]' : ''">
          <caption class="sr-only">
            {{ title }}
          </caption>
          <thead class="text-xs text-muted-foreground">
            <tr>
              <th scope="col" class="pb-1.5 text-left font-medium">
                Seite
              </th>
              <th scope="col" class="w-24 pb-1.5 text-right font-medium">
                Anfragen
              </th>
              <template v-if="mode === 'pages'">
                <th scope="col" class="w-24 pb-1.5 text-right font-medium" title="Erkennungen geteilt durch Anfragen">
                  Alarmquote
                </th>
                <th scope="col" class="w-24 pb-1.5 text-right font-medium">
                  {{ observe ? 'Erkannt' : 'Gesperrt' }}
                </th>
              </template>
              <th v-if="mode !== 'slow'" scope="col" class="w-32 pb-1.5 pl-3 text-left font-medium">
                Status
              </th>
              <th scope="col" class="w-24 pb-1.5 text-right font-medium" title="95 von 100 Anfragen waren schneller.">
                Antwortzeit
              </th>
            </tr>
          </thead>
          <tbody class="divide-y">
            <tr v-for="r in rows" :key="r.p.path" :class="r.p.review && mode === 'pages' ? 'bg-status-info-subtle/50' : ''" :data-page="r.p.path">
              <th scope="row" class="max-w-0 py-1.5 pr-2 text-left font-normal">
                <button
                  type="button"
                  class="block max-w-full truncate rounded-sm font-mono text-xs hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                  :class="activePath === r.p.path ? 'font-semibold' : ''"
                  :aria-pressed="activePath === r.p.path"
                  :title="`${r.p.path}: als Filter setzen`"
                  @click="emit('filter', `path:${r.p.path}`)"
                >
                  {{ r.p.path }}
                </button>
                <span v-if="r.p.review && mode === 'pages'" class="mt-0.5 block w-fit rounded-md border border-status-info/40 px-1.5 text-[11px] font-medium text-status-info" :title="REQUESTS_COPY.reviewText" data-testid="page-review">
                  {{ REQUESTS_COPY.review }}: {{ formatNumber(r.p.observe_followed_by_2xx ?? 0) }} Alarme mit 2xx beantwortet
                </span>
              </th>
              <td class="py-1.5 text-right">
                {{ formatNumber(r.p.requests) }}
              </td>
              <template v-if="mode === 'pages'">
                <td class="py-1.5 text-right" :class="r.p.detections ? '' : 'text-muted-foreground'">
                  {{ r.p.detections ? formatPercent(r.p.rate) : '–' }}
                </td>
                <td class="py-1.5 text-right text-muted-foreground">
                  {{ formatNumber(observe ? r.p.would_block : r.p.blocked) }}
                </td>
              </template>
              <td v-if="mode !== 'slow'" class="py-1.5 pl-3">
                <span v-if="r.bar.length" class="flex h-2 w-full gap-px overflow-hidden rounded-sm" :title="r.statusTitle" role="img" :aria-label="r.statusTitle">
                  <span v-for="s in r.bar.filter(b => b.w > 0)" :key="s.label" :style="{ width: `${s.w}%`, background: s.c }" />
                </span>
                <span v-else class="text-xs text-muted-foreground">–</span>
                <span v-if="mode === 'errors' && r.share5xx !== null" class="text-xs text-muted-foreground">{{ formatPercent(r.share5xx) }} 5xx</span>
              </td>
              <td class="py-1.5 text-right">
                {{ typeof r.p.latency_p95_ms === 'number' ? formatMs(r.p.latency_p95_ms) : '–' }}
              </td>
            </tr>
          </tbody>
        </table>
        <p v-if="mode !== 'slow'" class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <span>Status:</span>
          <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm border" :style="{ background: TONES.wash }" />2xx</span>
          <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm" :style="{ background: TONES.light }" />3xx</span>
          <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm" :style="{ background: TONES.deep }" />4xx</span>
          <span class="inline-flex items-center gap-1"><span class="size-2.5 rounded-sm" :style="{ background: TONES.neutral }" />5xx</span>
        </p>
      </div>
    </CardContent>
  </Card>
</template>
