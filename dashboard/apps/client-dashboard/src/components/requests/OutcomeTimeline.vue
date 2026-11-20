<script setup lang="ts">
import type { TimeSeries } from '@schild/ui'
import type { WebsiteRangeKey } from '@/api/websites'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatDecimal, Skeleton, TimeChart } from '@schild/ui'
import { computed } from 'vue'
import { errorMessage } from '@/api/client'
import { isFilterUnavailable, seriesResolutionFor, useWebsiteSeries } from '@/api/websites'
import EstimateNote from '@/components/monitoring/EstimateNote.vue'
import GapNote from '@/components/monitoring/GapNote.vue'
import { wouldBlockNote } from '@/lib/labels'
import { COPY, OUTCOME_COLORS, restartMarkers, timeLabels } from '@/lib/monitoring'
import { WEBSITE_COPY } from '@/lib/websites'

/**
 * Überblick of Zugriffe (MVP-22): every request and every alert of the website on one time axis, stacked
 * by what schild did (durchgelassen, erkannt, gesperrt; 503 neutral). Counted from the monitoring rings
 * (exact), under a filter from the request ring within 48 h. One axis, one hue in steps, no red.
 */
const props = defineProps<{
  site: string
  range: WebsiteRangeKey
  filters: string[]
  /** Filters work from the request ring (48 h); else the rings answer one filter with 10 min points. */
  ringAnswers: boolean
  observe?: boolean
}>()
const emit = defineEmits<{ range: [key: WebsiteRangeKey] }>()

const metrics = computed(() => [
  'traffic.requests:rate',
  'traffic.would_block:rate',
  'traffic.stopped:rate',
  // fail_closed has no filter; without filters it is its own neutral layer.
  ...(props.filters.length ? [] : ['traffic.fail_closed:rate']),
])
const q = useWebsiteSeries(() => ({
  site: props.site,
  range: props.range,
  filters: props.filters,
  metrics: metrics.value,
  // One filter without the ring: only the 10 min ring has per-website lists. 7 and 14 days read it via auto.
  resolution: seriesResolutionFor(props.range, props.filters.length > 0, props.ringAnswers),
}))
const unavailable = computed(() => isFilterUnavailable(q.error.value))
const r = computed(() => q.data.value)
const perMin = (v: number | null | undefined) => typeof v === 'number' ? v * 60 : null
const vals = (id: string) => (r.value?.series.find(s => s.metric === id)?.values ?? []).map(perMin)
const series = computed<TimeSeries[]>(() => {
  const req = vals('traffic.requests')
  const would = vals('traffic.would_block')
  const stopped = vals('traffic.stopped')
  const fail = vals('traffic.fail_closed')
  const passed = req.map((x, i) => x === null ? null : Math.max(0, x - (would[i] ?? 0) - (stopped[i] ?? 0) - (fail[i] ?? 0)))
  return [
    { id: 'passed', label: 'Durchgelassen', values: passed, color: OUTCOME_COLORS.passed, stack: true },
    { id: 'would', label: 'Erkannt', values: would, color: OUTCOME_COLORS.would, stack: true },
    { id: 'stopped', label: 'Gesperrt', values: stopped, color: OUTCOME_COLORS.stopped, stack: true },
    ...(props.filters.length ? [] : [{ id: 'fail', label: 'Mit 503 beantwortet', values: fail, color: OUTCOME_COLORS.failClosed, stack: true }]),
  ]
})
const labels = computed(() => r.value ? timeLabels(Date.parse(r.value.from), r.value.step_s, r.value.points) : { short: [], long: [], times: [] })
const markers = computed(() => r.value ? restartMarkers(r.value.restarts.map(t => Date.parse(t)), Date.parse(r.value.from), r.value.step_s, r.value.points) : [])
const estimate = computed(() => !!r.value?.series.some(s => !s.exact))
const gap = computed(() => (r.value?.restarts.length ?? 0) > 0)
const hasData = computed(() => series.value.some(s => s.values.some(v => v !== null)))
</script>

<template>
  <Card class="min-w-0" data-testid="requests-timeline">
    <CardHeader>
      <div class="flex flex-wrap items-center gap-2">
        <CardTitle>Anfragen und Alarme pro Minute</CardTitle>
        <EstimateNote v-if="estimate" :text="`${WEBSITE_COPY.estimate}: Mit Filter kommen die Zahlen aus Ranglisten oder einem Teil der gespeicherten Anfragen.`" />
        <GapNote v-if="gap" />
      </div>
      <CardDescription>
        Jede Anfrage an diese Website nach dem, was Schild mit ihr gemacht hat. {{ wouldBlockNote(!!observe) }}
      </CardDescription>
    </CardHeader>
    <CardContent>
      <div v-if="unavailable" class="rounded-lg border border-dashed p-4 text-sm" data-testid="timeline-unavailable">
        <p class="text-muted-foreground">
          {{ WEBSITE_COPY.filterUnavailable }}
        </p>
        <Button size="sm" variant="outline" class="mt-2" @click="emit('range', '48h')">
          {{ WEBSITE_COPY.to48h }}
        </Button>
      </div>
      <ErrorState v-else-if="q.isError.value && !r" title="Das Diagramm lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" :retrying="q.isFetching.value" @retry="q.refetch()" />
      <Skeleton v-else-if="!r" class="h-[240px] w-full" />
      <p v-else-if="!hasData" class="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
        {{ COPY.empty }}
      </p>
      <TimeChart
        v-else
        :series="series"
        :labels="labels.short"
        :long-labels="labels.long"
        :times="labels.times"
        label="Anfragen und Alarme pro Minute"
        :markers="markers"
        :height="240"
        :format="(n: number) => formatDecimal(n)"
        total-label="Alle Anfragen"
      />
    </CardContent>
  </Card>
</template>
