<script setup lang="ts">
import type { BreakdownDimension, RangeKey } from '@/api/monitoring'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { computed } from 'vue'
import { RANGES, useBreakdown } from '@/api/monitoring'
import { explainRule } from '@/lib/explain'
import { COPY, eventsLinkFor, keyLabel, OUTCOME_COLORS } from '@/lib/monitoring'
import EstimateNote from './EstimateNote.vue'
import GapNote from './GapNote.vue'

/**
 * Top entries of one traffic dimension (getTrafficBreakdown) as a compact table: requests, share,
 * stopped or "erkannt", for pages also the detections. Rows link to Ereignisse with the same
 * filter where one exists (that is where IP addresses are). Scrolls horizontally on small screens.
 */
const props = withDefaults(defineProps<{
  by: BreakdownDimension
  title: string
  description?: string
  range: RangeKey
  site?: string
  observe?: boolean
  top?: number
  sites?: Map<string, string>
}>(), { description: undefined, site: undefined, observe: false, top: 8, sites: undefined })

const q = useBreakdown(() => ({ by: props.by, range: props.range, site: props.site || undefined, top: props.top }))
const b = computed(() => q.data.value)
const total = computed(() => b.value?.total.requests ?? 0)
const isRule = computed(() => props.by === 'rule')
const showDetections = computed(() => props.by === 'path')
const max = computed(() => Math.max(1, ...(b.value?.items ?? []).map(i => i.requests)))

const rows = computed(() => (b.value?.items ?? []).map(i => ({
  ...i,
  name: isRule.value ? `${explainRule(i.key).title} · ${i.key}` : keyLabel(props.by, i.key, i.label, props.sites),
  share: total.value ? i.requests / total.value : null,
  bad: props.observe ? i.would_block : i.stopped + i.would_block,
  detShare: i.detections && i.requests ? i.detections / i.requests : null,
  to: eventsLinkFor(props.by, i.key, RANGES[props.range]),
  mono: props.by === 'path',
})))
const badLabel = computed(() => isRule.value ? (props.observe ? 'davon erkannt' : 'davon gesperrt') : props.observe ? 'Erkannt' : 'Gesperrt')
const countLabel = computed(() => isRule.value ? 'Erkennungen' : 'Anfragen')
</script>

<template>
  <Card class="min-w-0" :data-testid="`breakdown-${by}`">
    <CardHeader>
      <div class="flex flex-wrap items-center gap-2">
        <CardTitle>{{ title }}</CardTitle>
        <EstimateNote v-if="b && !b.exact" text="Jede Zahl kann um bis zu den Wert in der Spalte „±“ zu hoch sein." detail="Pro Zeitabschnitt merkt sich Schild nur die 64 häufigsten Einträge. Seltene Einträge können dadurch etwas zu hoch erscheinen." />
        <GapNote v-if="b?.partial" :kind="b.gap_kind" />
      </div>
      <CardDescription v-if="description">
        {{ description }}
      </CardDescription>
    </CardHeader>
    <CardContent>
      <div v-if="q.isPending.value" class="space-y-2">
        <Skeleton v-for="i in 5" :key="i" class="h-6 w-full" />
      </div>
      <p v-else-if="!rows.length" class="text-sm text-muted-foreground">
        {{ COPY.empty }}
      </p>
      <div v-else class="-mx-2 overflow-x-auto" tabindex="0" role="region" :aria-label="title">
        <table class="w-full min-w-[28rem] text-sm tabular-nums">
          <caption class="sr-only">
            {{ title }}
          </caption>
          <thead class="text-xs text-muted-foreground">
            <tr>
              <th scope="col" class="px-2 pb-2 text-left font-medium">
                {{ by === 'path' ? 'Seite' : 'Name' }}
              </th>
              <th scope="col" class="px-2 pb-2 text-right font-medium">
                {{ countLabel }}
              </th>
              <th v-if="!isRule" scope="col" class="px-2 pb-2 text-right font-medium">
                Anteil
              </th>
              <th scope="col" class="px-2 pb-2 text-right font-medium">
                {{ badLabel }}
              </th>
              <th v-if="showDetections" scope="col" class="px-2 pb-2 text-right font-medium">
                Erkennungen
              </th>
              <th v-if="b && !b.exact" scope="col" class="px-2 pb-2 text-right font-medium">
                ±
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in rows" :key="r.key" class="border-t align-top">
              <th scope="row" class="w-1/2 max-w-0 px-2 py-1.5 text-left font-normal">
                <RouterLink v-if="r.to" :to="r.to" :class="['block truncate underline-offset-4 hover:underline', r.mono ? 'font-mono text-xs' : '']" :title="r.name">
                  {{ r.name }}
                </RouterLink>
                <span v-else :class="['block truncate', r.mono ? 'font-mono text-xs' : '']" :title="r.name">{{ r.name }}</span>
                <span class="mt-1 block h-1 rounded-full bg-muted" aria-hidden="true">
                  <span class="block h-full rounded-full" :style="{ width: `${(r.requests / max) * 100}%`, background: OUTCOME_COLORS.data }" />
                </span>
              </th>
              <td class="px-2 py-1.5 text-right">
                {{ formatNumber(r.requests) }}
              </td>
              <td v-if="!isRule" class="px-2 py-1.5 text-right text-muted-foreground">
                {{ formatPercent(r.share) }}
              </td>
              <td class="px-2 py-1.5 text-right">
                {{ r.bad ? formatNumber(r.bad) : '–' }}
              </td>
              <td v-if="showDetections" class="px-2 py-1.5 text-right">
                <template v-if="r.detections">
                  {{ formatNumber(r.detections) }} <span class="text-xs text-muted-foreground">({{ formatPercent(r.detShare) }})</span>
                </template>
                <template v-else>
                  –
                </template>
              </td>
              <td v-if="b && !b.exact" class="px-2 py-1.5 text-right text-muted-foreground">
                {{ r.error ? `±${formatNumber(r.error)}` : '0' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="b && b.other.requests > 0" class="mt-2 text-xs text-muted-foreground">
        Weitere: {{ formatNumber(b.other.requests) }} {{ isRule ? 'Erkennungen' : 'Anfragen' }}
      </p>
      <p v-if="b && b.bot_verification === false" class="mt-2 text-xs text-muted-foreground" data-testid="bots-unverified">
        {{ COPY.botsUnverified }}
      </p>
    </CardContent>
  </Card>
</template>
