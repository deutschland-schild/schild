<script setup lang="ts">
import type { ChartMarker } from './TrafficAttackChart.vue'
import type { WebsiteRangeKey } from '@/api/websites'
import type { KpiKey } from '@/lib/websites'
import { Button, Card, CardContent, CardHeader, CardTitle, ErrorState, formatDecimal, formatMs, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { ArrowRight, Radio } from '@lucide/vue'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import {
  ALERT_FILTER_DIMENSIONS,
  isFilterUnavailable,
  ringRange,
  seriesResolutionFor,
  useAlerts,
  useAnnotations,
  useWebsiteKpis,
  useWebsiteSeries,
} from '@/api/websites'
import { wouldBlockNote } from '@/lib/labels'
import { timeLabels } from '@/lib/monitoring'
import { websitePath } from '@/lib/nav'
import { ANNOTATION_GLYPH, annotationLabel, annotationLink, filterChip, fillQuietBuckets, kpiOf, WEBSITE_COPY } from '@/lib/websites'
import AlertFeed from './AlertFeed.vue'
import KpiRow from './KpiRow.vue'
import TrafficAttackChart from './TrafficAttackChart.vue'

/**
 * Top of the Zugriffe Überblick (D36, modelled on Plausible; D68 moved it here from the old Überblick
 * page): KPI row with the previous period (a click picks the chart metric, URL key metric), the main
 * chart of traffic and alarms on one time axis with markers and gaps, and "Letzte Alarme" next to it.
 * With the monitoring off only "Letzte Alarme" stays: they come from the stored events.
 */
const props = defineProps<{
  site: string
  range: WebsiteRangeKey
  /** All filters of the page. */
  filters: string[]
  ring: boolean
  /** The breakdowns ignore the filters (no request ring, or beyond its window). */
  panelsUnfiltered: boolean
  observe: boolean
  metric: KpiKey
  monitoringOff?: boolean
}>()
const emit = defineEmits<{ 'update:metric': [key: KpiKey], 'range': [key: WebsiteRangeKey], 'filters': [filters: string[]] }>()

const metric = computed(() => kpiOf(props.metric))
const q = computed(() => ({ site: props.site, range: props.range, filters: props.filters }))
const on = computed(() => !props.monitoringOff)
const kpisQ = useWebsiteKpis(q, on)
const comboUnavailable = computed(() => isFilterUnavailable(kpisQ.error.value))

// ---------------------------------------------------------------- main chart
/** Without the request ring (or beyond its window) a filter only works on requests and attacks: the chart then shows requests and says so. */
const chartFallback = computed(() => props.panelsUnfiltered && !metric.value.filterable)
const chartMetric = computed(() => chartFallback.value ? kpiOf('requests') : metric.value)
const mainMetrics = computed(() => chartMetric.value.key === 'error_rate' ? ['traffic.status_5xx:rate', 'traffic.requests:rate'] : [chartMetric.value.metric])
/**
 * Without the request ring a filtered series comes from the per-website lists of the 10 min ring: 10m up to
 * 48 h (no 409 per click, D36 re-measurement D), auto for 7 and 14 days (never 400 too_many_points).
 */
const seriesResolution = computed(() => seriesResolutionFor(props.range, props.filters.length > 0, props.ring && !props.panelsUnfiltered))
const mainQ = useWebsiteSeries(() => ({ ...q.value, metrics: mainMetrics.value, resolution: seriesResolution.value }), on)
const attackQ = useWebsiteSeries(() => ({ ...q.value, metrics: ['traffic.stopped:rate', 'traffic.would_block:rate'], resolution: seriesResolution.value }), on)
const mainUnavailable = computed(() => isFilterUnavailable(mainQ.error.value))
const annotationsQ = useAnnotations(() => ({ site: props.site, range: props.range }), on)

const grid = computed(() => {
  const r = attackQ.data.value ?? mainQ.data.value
  if (!r) return null
  const from = Date.parse(r.from)
  return { from, stepS: r.step_s, points: r.points, partial: r.partial ?? [], ...timeLabels(from, r.step_s, r.points) }
})
const perMin = (v: number | null | undefined) => typeof v === 'number' ? v * 60 : null
function seriesValues(metricId: string, stat: string, src = mainQ.data.value) {
  return src?.series.find(s => s.metric === metricId && s.stat === stat)?.values ?? []
}
const mainValues = computed<(number | null)[]>(() => {
  const m = chartMetric.value
  if (!mainQ.data.value) return []
  if (m.key === 'error_rate') {
    const err = seriesValues('traffic.status_5xx', 'rate')
    const req = seriesValues('traffic.requests', 'rate')
    return req.map((r, i) => r === null || err[i] === null || err[i] === undefined ? null : r === 0 ? 0 : err[i]! / r)
  }
  const [id, stat] = m.metric.split(':')
  const vals = mainQ.data.value.series.find(s => s.metric === id && (!stat || s.stat === stat))?.values ?? []
  if (m.unit === 'perMin') return vals.map(perMin)
  return m.unit === 'count' ? fillQuietBuckets(vals, gapRanges.value) : vals
})
const stopped = computed(() => seriesValues('traffic.stopped', 'rate', attackQ.data.value).map(perMin))
const would = computed(() => seriesValues('traffic.would_block', 'rate', attackQ.data.value).map(perMin))
const perMinFmt = (n: number) => formatDecimal(n)
const mainFormat = computed(() => {
  switch (chartMetric.value.unit) {
    case 'ms': return formatMs
    case 'ratio': return (n: number) => formatPercent(n)
    case 'perMin': return perMinFmt
    default: return (n: number) => formatNumber(Math.round(n))
  }
})
const axisFormat = computed(() => chartMetric.value.unit === 'ms' ? formatMs : chartMetric.value.unit === 'ratio' ? (n: number) => formatPercent(n) : undefined)
/** Monitoring gaps as bucket ranges, also when a gap began before the chart's range. */
const gapRanges = computed(() => {
  const g = grid.value
  if (!g) return []
  const idx = (t: string) => Math.floor((Date.parse(t) - g.from) / (g.stepS * 1000))
  return (annotationsQ.data.value?.items ?? [])
    .filter(a => a.kind === 'monitoring_gap')
    .map(a => ({ from: idx(a.t), until: a.until ? idx(a.until) : g.points - 1 }))
})
const markers = computed<ChartMarker[]>(() => {
  const g = grid.value
  if (!g) return []
  const idx = (t: string) => Math.floor((Date.parse(t) - g.from) / (g.stepS * 1000))
  return (annotationsQ.data.value?.items ?? [])
    .map(a => ({ a, index: idx(a.t) }))
    .filter(x => x.index >= 0 && x.index < g.points)
    .map(({ a, index }) => ({
      index,
      kind: a.kind,
      label: annotationLabel(a),
      glyph: ANNOTATION_GLYPH[a.kind],
      to: annotationLink(a, props.site),
      ...(a.kind === 'monitoring_gap' && a.until ? { untilIndex: Math.min(g.points - 1, idx(a.until)) } : {}),
    }))
})

// ---------------------------------------------------------------- alerts
const alertFilter = computed(() => props.filters.find(f => (ALERT_FILTER_DIMENSIONS as readonly string[]).includes(f.slice(0, f.indexOf(':')))))
const alertsIgnored = computed(() => props.filters.filter(f => f !== alertFilter.value).map(filterChip).filter(c => c !== null))
const alertsQ = useAlerts(() => ({ site: props.site, range: props.range, filter: alertFilter.value }))
const eventsPath = computed(() => websitePath(props.site, 'events'))
</script>

<template>
  <!-- Letzte Alarme come from the stored events, not from the monitoring: they work with it off. -->
  <Card v-if="monitoringOff" class="min-w-0 gap-3 py-4" data-testid="alerts-card">
    <CardHeader class="px-4">
      <div class="flex items-center justify-between gap-2">
        <CardTitle class="text-base">
          Letzte Alarme
        </CardTitle>
        <RouterLink :to="eventsPath" class="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground" data-testid="alerts-to-events">
          Alle Ereignisse <ArrowRight class="size-3" aria-hidden="true" />
        </RouterLink>
      </div>
      <p class="text-xs text-muted-foreground">
        {{ WEBSITE_COPY.alertsWithoutMonitoring }}
      </p>
    </CardHeader>
    <CardContent class="max-h-[340px] overflow-y-auto px-4">
      <AlertFeed :items="alertsQ.data.value?.items ?? []" :loading="alertsQ.isPending.value" :site="site" :ring="ring" />
    </CardContent>
  </Card>
  <div v-else data-testid="traffic-headline">
    <div v-if="comboUnavailable" class="mb-4 rounded-xl border border-dashed bg-card p-4" data-testid="filter-unavailable-page">
      <p class="font-medium">
        {{ WEBSITE_COPY.filterUnavailableTitle }}
      </p>
      <p class="mt-1 text-sm text-muted-foreground">
        {{ WEBSITE_COPY.filterUnavailable }}
      </p>
      <div class="mt-3 flex flex-wrap gap-2">
        <Button size="sm" variant="outline" @click="emit('range', ringRange())">
          {{ WEBSITE_COPY.to48h }}
        </Button>
        <Button size="sm" variant="ghost" @click="emit('filters', filters.slice(0, 1))">
          Nur den ersten Filter behalten
        </Button>
      </div>
    </div>
    <ErrorState
      v-else-if="kpisQ.isError.value && !kpisQ.data.value"
      title="Die Zahlen lassen sich gerade nicht laden"
      :description="errorMessage(kpisQ.error.value)"
      :retrying="kpisQ.isFetching.value"
      @retry="kpisQ.refetch()"
    />
    <KpiRow v-else :kpis="kpisQ.data.value" :active="metric.key" :loading="kpisQ.isPending.value" :observe="observe" :ring="ring" class="mb-4" @select="(k: KpiKey) => emit('update:metric', k)" />

    <div class="mb-4 grid gap-4 xl:grid-cols-3">
      <Card v-if="!comboUnavailable" class="min-w-0 gap-3 py-4 xl:col-span-2">
        <CardHeader class="px-4">
          <CardTitle class="text-base">
            {{ chartMetric.chartLabel }} und Alarme
          </CardTitle>
          <p v-if="chartFallback" class="text-xs text-muted-foreground" data-testid="chart-fallback">
            {{ ring ? `${metric.label} mit Filter gibt es nur für einen kürzeren Zeitraum. Darum zeigt das Diagramm hier die Anfragen.` : WEBSITE_COPY.chartFallback(metric.label) }}
          </p>
        </CardHeader>
        <CardContent class="px-4">
          <div v-if="mainUnavailable" class="rounded-lg border border-dashed p-4 text-sm" data-testid="chart-unavailable">
            <p class="text-muted-foreground">
              {{ metric.label }}: {{ WEBSITE_COPY.filterUnavailableShort }}
            </p>
            <div class="mt-2 flex flex-wrap gap-2">
              <Button v-if="ring" size="sm" variant="outline" @click="emit('range', ringRange())">
                {{ WEBSITE_COPY.to48h }}
              </Button>
              <Button size="sm" variant="ghost" @click="emit('update:metric', 'requests')">
                Anfragen zeigen
              </Button>
            </div>
          </div>
          <Skeleton v-else-if="!grid" class="h-[300px] w-full" />
          <TrafficAttackChart
            v-else
            :times="grid.times"
            :labels="grid.short"
            :long-labels="grid.long"
            :values="mainValues"
            :partial="grid.partial"
            :stopped="stopped"
            :would="would"
            :label="chartMetric.chartLabel"
            attacks-label="Alarme pro Minute"
            :format="mainFormat"
            :axis-format="axisFormat"
            :attack-format="perMinFmt"
            :max="chartMetric.unit === 'ratio' ? 0.01 : undefined"
            :markers="markers"
            :would-note="wouldBlockNote(observe)"
          />
        </CardContent>
      </Card>
      <Card class="min-w-0 gap-3 py-4" :class="comboUnavailable ? 'xl:col-span-3' : ''" data-testid="alerts-card">
        <CardHeader class="px-4">
          <div class="flex items-center justify-between gap-2">
            <CardTitle class="flex items-center gap-2 text-base">
              Letzte Alarme
              <Radio class="size-3.5 text-status-success" aria-hidden="true" />
              <span class="sr-only">(aktualisiert sich alle 10 Sekunden)</span>
            </CardTitle>
            <RouterLink :to="eventsPath" class="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground" data-testid="alerts-to-events">
              Alle Ereignisse <ArrowRight class="size-3" aria-hidden="true" />
            </RouterLink>
          </div>
          <p v-if="alertsIgnored.length" class="text-xs text-muted-foreground">
            Ohne Filter {{ alertsIgnored.map(c => `${c.label}: ${c.value}`).join(', ') }} (gibt es hier nicht).
          </p>
        </CardHeader>
        <CardContent class="max-h-[340px] overflow-y-auto px-4">
          <AlertFeed :items="alertsQ.data.value?.items ?? []" :loading="alertsQ.isPending.value" :site="site" :ring="ring" />
        </CardContent>
      </Card>
    </div>
  </div>
</template>
