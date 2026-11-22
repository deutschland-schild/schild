<script setup lang="ts">
import type { KpiKey } from '@/lib/websites'
import type { KpiValue, WebsiteKpis } from '@/api/websites'
import { formatMs, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { ArrowDownRight, ArrowRight, ArrowUpRight } from '@lucide/vue'
import { computed } from 'vue'
import { WOULD_BLOCK_MIXED } from '@/lib/labels'
import { changeText, combineGapKind, gapCopy, KPIS, WEBSITE_COPY } from '@/lib/websites'
import GapNote from '../monitoring/GapNote.vue'

/**
 * KPI row of the website overview (Plausible-style, D36): six numbers over the range, each with the change
 * against the previous period of the same length; a click makes it the metric of the main chart.
 * Changes are shown in ink, never green or red: more requests are neither good nor bad by themselves.
 * "≈" marks an estimate (exact false); a window schild did not fully count (partial, contracts v0.5)
 * gets a separate, calm "Lücke im Zeitraum" note below the row.
 */
const props = defineProps<{ kpis?: WebsiteKpis, active: KpiKey, loading?: boolean, observe?: boolean, ring?: boolean }>()
const emit = defineEmits<{ select: [key: KpiKey] }>()

function fmt(key: KpiKey, v: number | null | undefined): string {
  if (v === null || v === undefined) return '–'
  if (key === 'latency_p95_ms') return formatMs(v) // gitleaks:allow (KPI id)
  if (key === 'error_rate') return formatPercent(v)
  return formatNumber(Math.round(v))
}
const UNAVAILABLE = computed<Record<string, string>>(() => ({
  // Without the request ring (MVP-22) these KPIs have no filtered value at all.
  filter_needs_requests: props.ring ? 'mit Filter nur 48 Std.' : 'mit Filter nicht verfügbar',
  no_data: 'noch keine Daten',
  monitoring_off: 'Messung aus',
}))

const tiles = computed(() => KPIS.map((d) => {
  // In Beobachten nothing is stopped: the tile shows what Schild would have blocked.
  const src = d.key === 'stopped' && props.observe ? 'would_block' : d.key
  const cur: KpiValue | undefined = props.kpis?.current[src]
  const prev: KpiValue | undefined = props.kpis?.previous[src]
  const ch = changeText(cur?.value, prev?.value)
  // In a cluster the visitors of the metric rings are the largest estimate of the servers, never their sum
  // (ClusterScope.clients_at_least): a lower bound. The request ring counts them over all servers.
  const atLeast = d.key === 'visitors' && !!props.kpis?.cluster?.clients_at_least && props.kpis.source === 'rings'
  const label = d.key === 'stopped' && props.observe ? 'Erkannt' : atLeast ? 'Besucher (mindestens)' : d.label
  return { d, label, cur, ch, estimate: cur ? !cur.exact && cur.value !== null : false, partial: !!cur?.partial && cur.value !== null }
}))
const would = computed(() => props.kpis?.current.would_block)
const anyPartial = (set?: WebsiteKpis['current']) => !!set && Object.values(set).some(v => v?.partial && v.value !== null)
const gap = computed(() => anyPartial(props.kpis?.current))
const gapPrevious = computed(() => anyPartial(props.kpis?.previous))
/** Neustart only when every partial value of the current period says restart; lost wins. */
const gapKind = computed(() => combineGapKind(Object.values(props.kpis?.current ?? {}).filter(v => v?.value !== null)))
</script>

<template>
  <div>
    <div class="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-3 xl:grid-cols-6" role="group" aria-label="Kennzahlen" data-testid="kpi-row">
      <button
        v-for="t in tiles"
        :key="t.d.key"
        type="button"
        :aria-pressed="active === t.d.key"
        :class="['relative flex min-w-0 flex-col gap-1 bg-card px-4 py-3 text-left transition-colors hover:bg-muted/60 focus-visible:z-10 focus-visible:outline-2 focus-visible:outline-ring']"
        :data-kpi="t.d.key"
        @click="emit('select', t.d.key)"
      >
        <span v-if="active === t.d.key" class="absolute inset-x-0 top-0 h-0.5" :style="{ background: 'var(--tone-main)' }" aria-hidden="true" />
        <span class="truncate text-xs font-medium text-muted-foreground" :title="t.d.hint">{{ t.label }}<span v-if="t.d.hint" class="sr-only">: {{ t.d.hint }}</span></span>
        <Skeleton v-if="loading && !kpis" class="h-7 w-20" />
        <span v-else class="flex items-baseline gap-1 text-2xl font-semibold tracking-tight tabular-nums">
          <span v-if="t.estimate" class="text-base font-normal text-muted-foreground" :title="WEBSITE_COPY.estimate">≈</span>
          <span data-slot="kpi-value">{{ fmt(t.d.key, t.cur?.value) }}</span>
          <span v-if="t.partial" class="sr-only">({{ gapCopy(t.cur?.gap_kind).label }})</span>
        </span>
        <span class="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
          <template v-if="t.cur?.unavailable">{{ UNAVAILABLE[t.cur.unavailable] ?? '–' }}</template>
          <span v-else-if="t.ch" class="inline-flex items-center gap-0.5 tabular-nums" :title="WEBSITE_COPY.previousPeriod" data-slot="kpi-change">
            <ArrowUpRight v-if="t.ch.dir === 'up'" class="size-3" aria-hidden="true" />
            <ArrowDownRight v-else-if="t.ch.dir === 'down'" class="size-3" aria-hidden="true" />
            <ArrowRight v-else class="size-3" aria-hidden="true" />
            {{ t.ch.text }}<span class="sr-only"> {{ WEBSITE_COPY.previousPeriod }}</span>
          </span>
          <span v-if="t.d.key === 'stopped' && !observe && would && would.value" class="tabular-nums" data-testid="kpi-would-block" :title="WOULD_BLOCK_MIXED">erkannt {{ formatNumber(would.value) }}</span>
        </span>
      </button>
    </div>
    <div v-if="gap || gapPrevious" class="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground" data-testid="kpi-gap">
      <GapNote v-if="gap" :kind="gapKind" :detail="gapPrevious ? `${WEBSITE_COPY.gapDetail} ${WEBSITE_COPY.gapPrevious}` : undefined" />
      <span v-else>{{ WEBSITE_COPY.gapPrevious }}</span>
    </div>
  </div>
</template>
