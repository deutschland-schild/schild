<script setup lang="ts">
import type { Overview } from '@/api/types'
import { Button, ErrorState, formatBytes, formatDecimal, formatMs, LiveIndicator, StatCard } from '@schild/ui'
import { ArrowRight } from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { errorMessage } from '@/api/client'
import type { MergedSeries } from '@/api/monitoring'
import { isMonitoringOff, monitoringOff, useMetricSeries, useMonitoringNow, useServerSnapshot, valuesOf } from '@/api/monitoring'
import { useMonitoringStream } from '@/composables/useMonitoringStream'
import { baselineView } from '@/lib/summary'
import { COPY, hintContext, hintView, ratioText } from '@/lib/monitoring'
import HintList from './HintList.vue'

/**
 * "Gerade jetzt" on the server overview (MVP-21, "/" since 2026-10-29): one status line, the totals of
 * all websites (requests, stopped, response time) and the server (CPU, memory, disk, network) as tiles
 * with a 60-minute sparkline, and the hints. Tile values come from the live stream (once per second), sparklines every 10 s.
 * Live numbers are not an aria-live region; only new hints are announced, politely.
 */
const props = defineProps<{ overview?: Overview }>()

// D36: website numbers live on the website pages; this section shows the whole server (all websites).
const site = computed(() => '')

const nowQ = useMonitoringNow(() => site.value || undefined)
const off = computed(() => monitoringOff.value || isMonitoringOff(nowQ.error.value))
const on = computed(() => !off.value && !nowQ.isError.value)
const live = useMonitoringStream(() => site.value || undefined, on)
const now = computed(() => nowQ.data.value)
const server = computed(() => live.server.value ?? now.value?.server ?? null)
const observe = computed(() => props.overview?.profile === 'test')

const spark = useMetricSeries(() => ({
  metrics: ['traffic.requests:rate', 'traffic.stopped:rate', 'traffic.would_block:rate', 'traffic.requests:sum', 'traffic.latency_total:p95', 'server.cpu_usage:avg', 'server.memory_used:avg', 'server.disk_used_ratio:avg', 'server.net_rx_bytes', 'server.net_tx_bytes'],
  range: '1h',
  site: site.value || undefined,
}), on)
/** Sum of all series (every interface, both directions) per point; a gap in any of them stays a gap. */
function sumByIndex(d: MergedSeries | undefined, metrics: string[]): (number | null)[] {
  const all = (d?.series ?? []).filter(x => metrics.includes(x.metric))
  if (!all.length) return []
  return all[0]!.values.map((_, i) => all.some(x => x.values[i] === null || x.values[i] === undefined) ? null : all.reduce((a, x) => a + (x.values[i] ?? 0), 0))
}
// Gaps stay null so the sparkline keeps its 60-minute time axis (a restart is a gap, not a jump).
const trend = computed(() => {
  const d = spark.data.value
  const req = valuesOf(d, 'traffic.requests', 'rate')
  const stop = valuesOf(d, observe.value ? 'traffic.would_block' : 'traffic.stopped', 'rate')
  return {
    rps: req,
    stopped: stop.map((v, i) => v === null || req[i] === null || req[i] === undefined ? null : req[i] === 0 ? 0 : v / req[i]!),
    latency: valuesOf(d, 'traffic.latency_total', 'p95'),
    cpu: valuesOf(d, 'server.cpu_usage', 'avg'),
    memory: valuesOf(d, 'server.memory_used', 'avg'),
    disk: valuesOf(d, 'server.disk_used_ratio', 'avg', server.value?.disk?.mount),
    network: sumByIndex(d, ['server.net_rx_bytes', 'server.net_tx_bytes']),
  }
})

const r = computed(() => live.rolling.value)
const rps = computed(() => r.value?.requestsPerS ?? now.value?.traffic.requests_per_s ?? null)
const stoppedShare = computed(() => observe.value
  ? (r.value?.wouldBlockShare ?? now.value?.traffic.would_block_share ?? null)
  : (r.value?.stoppedShare ?? now.value?.traffic.stopped_share ?? null))
const wouldShare = computed(() => r.value?.wouldBlockShare ?? now.value?.traffic.would_block_share ?? null)
const p95 = computed(() => r.value?.latencyTotalP95 ?? now.value?.traffic.latency_total_p95_ms ?? null)
const overheadP95 = computed(() => r.value?.latencyOverheadP95 ?? now.value?.traffic.latency_overhead_p95_ms ?? null)
const hints = computed(() => now.value?.hints ?? [])
const needsSnapshot = computed(() => hints.value.some(h => h.code === 'cpu_throttled' || h.code === 'store_near_cap' || h.code === 'store_cap_unreachable'))
const snap = useServerSnapshot(needsSnapshot)
const ctx = computed(() => ({ ...hintContext(snap.data.value, overheadP95.value), cores: server.value?.cores ?? snap.data.value?.cpu?.cores ?? null }))

const network = computed(() => {
  const s = server.value
  if (!s || s.net_rx_bytes_per_s === null || s.net_tx_bytes_per_s === null) return null
  return { total: s.net_rx_bytes_per_s + s.net_tx_bytes_per_s, rx: s.net_rx_bytes_per_s, tx: s.net_tx_bytes_per_s }
})
const pct = (v: number | null | undefined) => v === null || v === undefined ? null : formatDecimal(v * 100)
const statusLine = computed(() => {
  const parts: string[] = []
  if (props.overview) parts.push(baselineView(props.overview).title)
  if (rps.value !== null) parts.push(`${formatDecimal(rps.value)} Anfragen pro Sekunde`)
  if (stoppedShare.value !== null) parts.push(`${ratioText(stoppedShare.value)} ${observe.value ? 'erkannt und durchgelassen' : 'gestoppt'}`)
  parts.push(hints.value.length ? (hints.value.length === 1 ? '1 Hinweis' : `${hints.value.length} Hinweise`) : 'alles im üblichen Rahmen')
  return parts.join(' · ')
})
const stoppedHint = computed(() => {
  if (observe.value) return 'Im Testprofil kommt alles durch.'
  const w = wouldShare.value
  return w ? `dazu ${ratioText(w)} im Probelauf` : 'Anteil der letzten 60 Sekunden'
})
const cpuHint = computed(() => {
  const s = server.value
  if (!s?.cores) return undefined
  return `${s.cores} Kerne${s.load1 !== null ? ` · Last ${formatDecimal(s.load1)}` : ''}`
})

// Announce new hints once (politely); live numbers are never announced.
const announcement = ref('')
const seen = new Set<string>()
watch(hints, (hs) => {
  const fresh = hs.filter(h => !seen.has(`${h.code}:${h.object ?? ''}`))
  for (const h of hs) seen.add(`${h.code}:${h.object ?? ''}`)
  if (fresh.length && seen.size > fresh.length) announcement.value = `Neuer Hinweis: ${hintView(fresh[0]!, ctx.value).text}`
}, { immediate: true })

</script>

<template>
  <section aria-labelledby="now-title" class="mb-6" data-testid="now">
    <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
      <div class="flex items-center gap-2">
        <h2 id="now-title" class="text-sm font-medium text-muted-foreground">
          Gerade jetzt
        </h2>
        <LiveIndicator v-if="on" :state="live.state.value" />
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <Button as-child variant="link" size="sm" class="h-auto p-0">
          <RouterLink to="/server/load">
            Auslastung im Verlauf
            <ArrowRight aria-hidden="true" />
          </RouterLink>
        </Button>
      </div>
    </div>

    <p v-if="off" class="rounded-xl border bg-card p-4 text-sm text-muted-foreground" data-testid="monitoring-off">
      {{ COPY.monitoringOff }}
    </p>
    <ErrorState
      v-else-if="nowQ.isError.value && !now"
      title="Die aktuellen Werte lassen sich gerade nicht laden"
      :description="errorMessage(nowQ.error.value)"
      :retrying="nowQ.isFetching.value"
      @retry="nowQ.refetch()"
    />
    <template v-else>
      <p class="mb-3 text-base text-pretty" data-testid="now-status">
        {{ now ? statusLine : 'Lädt …' }}
      </p>
      <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="Anfragen pro Sekunde"
          :value="rps === null ? null : formatDecimal(rps)"
          :loading="!now"
          :trend="trend.rps"
          trend-label="Anfragen pro Sekunde, letzte 60 Minuten"
          hint="Mittel der letzten 60 Sekunden"
          data-testid="tile-rps"
        />
        <StatCard
          :label="observe ? 'Erkannt' : 'Gestoppt'"
          :value="pct(stoppedShare)"
          unit="%"
          :loading="!now"
          :trend="trend.stopped"
          :trend-label="`${observe ? 'Erkannt' : 'Gestoppt'}, Anteil, letzte 60 Minuten`"
          :hint="stoppedHint"
          data-testid="tile-stopped"
        />
        <StatCard
          label="Antwortzeit"
          :value="p95 === null ? null : formatMs(p95)"
          :loading="!now"
          :trend="trend.latency"
          trend-label="Antwortzeit, letzte 60 Minuten"
          :hint="overheadP95 !== null ? `95 von 100 schneller · davon Schild ${formatMs(overheadP95)}` : '95 von 100 Anfragen schneller'"
          data-testid="tile-latency"
        />
        <StatCard
          label="CPU"
          :value="pct(server?.cpu_usage)"
          unit="%"
          :loading="!now"
          :trend="trend.cpu"
          trend-label="CPU-Auslastung, letzte 60 Minuten"
          :hint="cpuHint"
          data-testid="tile-cpu"
        />
        <StatCard
          label="Arbeitsspeicher"
          :value="pct(server?.memory_used_ratio)"
          unit="%"
          :loading="!now"
          :trend="trend.memory"
          trend-label="Belegter Arbeitsspeicher, letzte 60 Minuten"
          :hint="server?.memory_available_bytes != null ? `${formatBytes(server.memory_available_bytes)} frei` : undefined"
          data-testid="tile-memory"
        />
        <StatCard
          label="Festplatte"
          :value="pct(server?.disk?.used_ratio)"
          unit="%"
          :loading="!now"
          :trend="trend.disk"
          trend-label="Belegung der vollsten Festplatte, letzte 60 Minuten"
          :hint="server?.disk ? `${server.disk.mount}, am vollsten` : undefined"
          data-testid="tile-disk"
        />
        <StatCard
          label="Netzwerk"
          :value="network ? formatBytes(network.total) : null"
          unit="/s"
          :loading="!now"
          :trend="trend.network"
          trend-label="Gesendet und empfangen zusammen, letzte 60 Minuten"
          :hint="network ? `${formatBytes(network.tx)}/s gesendet` : undefined"
          data-testid="tile-network"
        />
      </div>
      <p v-if="now && !server" class="mt-2 text-xs text-muted-foreground">
        Serverwerte gibt es hier nicht (kein Linux oder monitoring.host: false). Traffic und Antwortzeiten werden trotzdem gezählt.
      </p>

      <h3 class="mt-5 mb-2 text-sm font-medium text-muted-foreground">
        Hinweise
      </h3>
      <HintList :hints="hints" :context="ctx" />
      <p class="sr-only" aria-live="polite">
        {{ announcement }}
      </p>
    </template>
  </section>
</template>
