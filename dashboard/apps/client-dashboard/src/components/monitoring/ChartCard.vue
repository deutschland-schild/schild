<script setup lang="ts">
import type { TimeSeries } from '@schild/ui'
import type { MergedSeries } from '@/api/monitoring'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Skeleton, TimeChart } from '@schild/ui'
import { computed } from 'vue'
import { COPY, restartMarkers, timeLabels } from '@/lib/monitoring'
import EstimateNote from './EstimateNote.vue'

/** One monitoring chart in a card: title, description, optional "Näherungswert", gaps and restarts. */
const props = defineProps<{
  title: string
  description?: string
  data: MergedSeries | undefined
  series: TimeSeries[]
  loading?: boolean
  format?: (n: number) => string
  axisFormat?: (n: number) => string
  max?: number
  /** Show "Näherungswert" with this bound (e.g. "25 %"). */
  estimate?: string
  /** Full sentence instead of "kann um bis zu {estimate} abweichen" (bounds that are typical, not hard). */
  estimateSentence?: string
  estimateDetail?: string
  height?: number
  testid?: string
  /** Text instead of "Noch keine Werte …" when the chart can never fill here (e.g. host values off Linux). */
  emptyText?: string
}>()

const labels = computed(() => props.data ? timeLabels(props.data.from, props.data.stepS, props.data.points) : { short: [], long: [], times: [] })
const markers = computed(() => props.data ? restartMarkers(props.data.restarts, props.data.from, props.data.stepS, props.data.points) : [])
const hasData = computed(() => props.series.some(s => s.values.some(v => v !== null)))
</script>

<template>
  <Card class="min-w-0" :data-testid="testid">
    <CardHeader>
      <div class="flex flex-wrap items-center gap-2">
        <CardTitle>{{ title }}</CardTitle>
        <EstimateNote v-if="estimate || estimateSentence" :bound="estimate" :text="estimateSentence" :detail="estimateDetail" />
      </div>
      <CardDescription v-if="description">
        {{ description }}
      </CardDescription>
    </CardHeader>
    <CardContent>
      <Skeleton v-if="loading && !data" class="w-full" :style="{ height: `${height ?? 200}px` }" />
      <p v-else-if="!hasData" class="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
        {{ emptyText ?? COPY.empty }}
      </p>
      <TimeChart
        v-else
        :series="series"
        :labels="labels.short"
        :long-labels="labels.long"
        :times="labels.times"
        :label="title"
        :markers="markers"
        :height="height ?? 200"
        v-bind="{ ...(format ? { format } : {}), ...(axisFormat ? { axisFormat } : {}), ...(max !== undefined ? { max } : {}) }"
      >
        <template v-if="$slots.caption" #caption>
          <slot name="caption" />
        </template>
      </TimeChart>
    </CardContent>
  </Card>
</template>
