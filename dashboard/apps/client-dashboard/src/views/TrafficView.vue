<script setup lang="ts">
import type { TimeSeries } from '@schild/ui'
import type { RangeKey } from '@/api/monitoring'
import { ErrorState, formatDecimal, formatMs, PageHeader } from '@schild/ui'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage } from '@/api/client'
import { isMonitoringOff, monitoringOff, rangeOf, useMetricSeries, useMonitoringNow, valuesOf } from '@/api/monitoring'
import { useOverview } from '@/api/queries'
import { useWebsite } from '@/api/websites'
import BreakdownCard from '@/components/monitoring/BreakdownCard.vue'
import ChartCard from '@/components/monitoring/ChartCard.vue'
import RangeSiteBar from '@/components/monitoring/RangeSiteBar.vue'
import WebsiteHeader from '@/components/websites/WebsiteHeader.vue'
import { bytesPerSecond, COPY, OUTCOME_COLORS, TONES } from '@/lib/monitoring'

/**
 * Traffic (MVP-21): every request that reached Schild, counted exactly (not the sampled events),
 * charts over 1 h to 14 days and top lists. Time range and website live in the URL (time, website).
 */
const route = useRoute()
const router = useRouter()
function setQuery(patch: Record<string, string | undefined>) {
  const query = { ...route.query }
  for (const [k, v] of Object.entries(patch)) {
    if (!v) delete query[k]
    else query[k] = v
  }
  void router.replace({ query })
}
const range = computed({ get: () => rangeOf(route.query.time).key, set: (v: RangeKey) => setQuery({ time: v === '6h' ? undefined : v }) })
// D36: the website comes from the URL (/w/<id>/charts).
const site = computed(() => typeof route.params.site === 'string' ? route.params.site : '')
const websiteQ = useWebsite(site)
const siteOrUndef = computed(() => site.value || undefined)
const r = computed(() => rangeOf(range.value))

const overview = useOverview()
const observe = computed(() => overview.data.value?.profile === 'test')
const nowQ = useMonitoringNow(undefined)
const off = computed(() => monitoringOff.value || isMonitoringOff(nowQ.error.value))
const sitesNow = computed(() => nowQ.data.value?.sites ?? [])
const siteNames = computed(() => new Map(sitesNow.value.map(s => [s.site, s.label ?? s.site])))

const counters = useMetricSeries(() => ({
  metrics: [
    'traffic.forwarded', 'traffic.would_block', 'traffic.stopped', 'traffic.fail_closed',
    'traffic.blocked_waf', 'traffic.blocked_behaviour', 'traffic.rate_limited', 'traffic.rejected_limit',
    'traffic.status_2xx', 'traffic.status_3xx', 'traffic.status_4xx', 'traffic.status_5xx',
    'traffic.bytes_in', 'traffic.bytes_out', 'traffic.page_views', 'traffic.detections',
  ],
  range: range.value,
  site: siteOrUndef.value,
}), () => !off.value)
const other = useMetricSeries(() => ({
  metrics: [
    'traffic.latency_total:p50', 'traffic.latency_total:p95', 'traffic.latency_total:p99', 'traffic.latency_upstream:p95', 'traffic.latency_overhead:p95',
    'traffic.clients_unique', 'traffic.clients_new',
    'traffic.upstream_errors:sum', 'traffic.upstream_timeouts:sum', 'traffic.fail_closed:sum',
    // D57: in this query, the counters above are at max_series (16).
    'traffic.blocked_crawler',
  ],
  range: range.value,
  site: siteOrUndef.value,
}), () => !off.value)

const c = computed(() => counters.data.value)
const o = computed(() => other.data.value)
const v = (metric: string, stat?: string) => valuesOf(c.value, metric, stat)
const w = (metric: string, stat?: string) => valuesOf(o.value, metric, stat)
const minus = (a: (number | null)[], b: (number | null)[]) => a.map((x, i) => x === null || b[i] === null ? null : Math.max(0, x - b[i]!))

const requestsSeries = computed<TimeSeries[]>(() => [
  { id: 'passed', label: 'Durchgelassen', values: minus(v('traffic.forwarded'), v('traffic.would_block')), color: OUTCOME_COLORS.passed, stack: true },
  { id: 'would', label: 'Erkannt', values: v('traffic.would_block'), color: OUTCOME_COLORS.would, stack: true },
  { id: 'stopped', label: 'Gesperrt', values: v('traffic.stopped'), color: OUTCOME_COLORS.stopped, stack: true },
  { id: 'failclosed', label: 'Mit 503 beantwortet', values: v('traffic.fail_closed'), color: OUTCOME_COLORS.failClosed, stack: true },
])
// Reasons for a stop: steps of one hue (legend, tooltip and table name them); 503 stays neutral grey.
const stopSeries = computed<TimeSeries[]>(() => [
  { id: 'waf', label: 'Regeln (WAF)', values: v('traffic.blocked_waf'), color: TONES.deep, stack: true },
  { id: 'behaviour', label: 'Verhalten', values: v('traffic.blocked_behaviour'), color: TONES.mid, stack: true },
  { id: 'rate', label: 'Zu viele Anfragen', values: v('traffic.rate_limited'), color: TONES.light, stack: true },
  { id: 'limits', label: 'Zu groß oder ungültig', values: v('traffic.rejected_limit'), color: TONES.wash, stack: true },
  { id: 'crawler', label: 'Crawler-Regeln', values: w('traffic.blocked_crawler'), color: TONES.main, stack: true },
  { id: 'fail', label: 'Mit 503 beantwortet', values: v('traffic.fail_closed'), color: OUTCOME_COLORS.failClosed, stack: true },
])
const detectionSeries = computed<TimeSeries[]>(() => [
  { id: 'pageviews', label: 'Seitenaufrufe', values: v('traffic.page_views'), color: TONES.main, fill: true },
  { id: 'detections', label: 'Erkennungen der Regeln', values: v('traffic.detections'), color: TONES.neutral },
])
const statusSeries = computed<TimeSeries[]>(() => [
  { id: '2xx', label: '2xx Erfolg', values: v('traffic.status_2xx'), color: TONES.wash, stack: true },
  { id: '3xx', label: '3xx Weiterleitung', values: v('traffic.status_3xx'), color: TONES.light, stack: true },
  { id: '4xx', label: '4xx Fehler der Anfrage', values: v('traffic.status_4xx'), color: TONES.deep, stack: true },
  { id: '5xx', label: '5xx Fehler des Servers', values: v('traffic.status_5xx'), color: TONES.neutral, stack: true },
])
const latencySeries = computed<TimeSeries[]>(() => [
  // p50, p95, p99 in words: how many of 100 requests were faster.
  { id: 'p95', label: 'Gesamt, 95 von 100 schneller', values: w('traffic.latency_total', 'p95'), color: TONES.main, fill: true },
  { id: 'p50', label: 'Gesamt, die Hälfte schneller', values: w('traffic.latency_total', 'p50'), color: TONES.main, dashed: true },
  { id: 'p99', label: 'Gesamt, 99 von 100 schneller', values: w('traffic.latency_total', 'p99'), color: TONES.neutral, dashed: true },
  { id: 'app', label: 'davon App, 95 von 100 schneller', values: w('traffic.latency_upstream', 'p95'), color: TONES.neutral },
  { id: 'schild', label: 'davon Schild, 95 von 100 schneller', values: w('traffic.latency_overhead', 'p95'), color: TONES.deep },
])
const bytesSeries = computed<TimeSeries[]>(() => [
  { id: 'out', label: 'Ausgehend', values: v('traffic.bytes_out'), color: TONES.main, fill: true },
  { id: 'in', label: 'Eingehend', values: v('traffic.bytes_in'), color: TONES.neutral },
])
const appErrorSeries = computed<TimeSeries[]>(() => [
  { id: '502', label: 'Keine Antwort (502)', values: w('traffic.upstream_errors', 'sum'), color: TONES.main },
  { id: '504', label: 'Zu spät (504)', values: w('traffic.upstream_timeouts', 'sum'), color: TONES.deep, dashed: true },
  { id: '503', label: 'Von Schild mit 503 beantwortet', values: w('traffic.fail_closed', 'sum'), color: TONES.neutral, dashed: true },
])
const clientSeries = computed<TimeSeries[]>(() => [
  { id: 'unique', label: 'Verschiedene Adressen', values: w('traffic.clients_unique'), color: TONES.main, fill: true },
  { id: 'new', label: 'Davon neu', values: w('traffic.clients_new'), color: TONES.deep, dashed: true },
])
const stepText = computed(() => r.value.stepS === 10 ? '10 Sekunden' : r.value.stepS === 60 ? 'Minute' : '10 Minuten')
const perSec = (n: number) => `${formatDecimal(n)}/s`
const loading = computed(() => counters.isPending.value)
const err = computed(() => counters.isError.value && !off.value ? counters.error.value : null)
</script>

<template>
  <div>
    <WebsiteHeader v-if="site" :id="site" :website="websiteQ.data.value?.website" title="Diagramme">
      <template #actions>
        <RangeSiteBar v-model:range="range" no-sites />
      </template>
    </WebsiteHeader>
    <PageHeader v-else title="Diagramme" description="Alle Websites zusammen: wie viele Anfragen kommen, was Schild mit ihnen macht und wie schnell die Apps antworten. Gezählt wird jede Anfrage, nicht nur die gespeicherten Ereignisse.">
      <template #actions>
        <RangeSiteBar v-model:range="range" no-sites />
      </template>
    </PageHeader>

    <p v-if="off" class="rounded-xl border bg-card p-4 text-sm text-muted-foreground" data-testid="monitoring-off">
      {{ COPY.monitoringOff }}
    </p>
    <ErrorState
      v-else-if="err && !c"
      title="Die Traffic-Werte lassen sich gerade nicht laden"
      :description="errorMessage(err)"
      :retrying="counters.isFetching.value"
      @retry="counters.refetch()"
    />
    <template v-else>
      <div class="grid gap-4 lg:grid-cols-2">
        <ChartCard
          class="lg:col-span-2"
          title="Anfragen pro Sekunde"
          :description="observe ? 'Im Testprofil kommt alles durch. „Erkannt“ zeigt, was Schild sonst gesperrt hätte.' : 'Jede Anfrage, die Schild erreicht hat, nach dem, was Schild mit ihr gemacht hat.'"
          :data="c"
          :series="requestsSeries"
          :loading="loading"
          :format="perSec"
          :height="240"
          testid="chart-requests"
        />
        <ChartCard title="Was Schild gestoppt hat" description="Gesperrte Anfragen pro Sekunde nach Grund." :data="c" :series="stopSeries" :loading="loading" :format="perSec" testid="chart-stopped" />
        <ChartCard title="Erkennungen und Seitenaufrufe" description="Wie oft die Regeln angeschlagen haben, neben den Aufrufen echter Seiten durch Browser (pro Sekunde)." :data="c" :series="detectionSeries" :loading="loading" :format="perSec" testid="chart-detections" />
        <ChartCard title="Statuscodes" description="Was die Besucher als Antwort bekommen haben, pro Sekunde (Antworten von Schild eingeschlossen)." :data="c" :series="statusSeries" :loading="loading" :format="perSec" testid="chart-status" />
        <ChartCard
          title="Antwortzeit"
          description="Wie lange eine Antwort dauert: gesamt, davon deine App und davon Schild."
          :data="o"
          :series="latencySeries"
          :loading="other.isPending.value"
          :format="formatMs"
          :axis-format="formatMs"
          estimate="25 %"
          estimate-detail="Schild zählt Antwortzeiten in Stufen. Angezeigt wird die Obergrenze der Stufe, der wahre Wert liegt also etwas darunter."
          testid="chart-latency"
        />
        <ChartCard title="Datenmenge" description="Inhalt der Anfragen und Antworten. Kopfzeilen und Verschlüsselung zählen nicht mit; die Gesamtmenge steht unter Server." :data="c" :series="bytesSeries" :loading="loading" :format="bytesPerSecond" :axis-format="bytesPerSecond" testid="chart-bytes" />
        <ChartCard :title="`Fehler der App (pro ${stepText})`" description="Anfragen, die deine App nicht oder zu spät beantwortet hat, und Anfragen, die Schild nicht rechtzeitig prüfen konnte." :data="o" :series="appErrorSeries" :loading="other.isPending.value" testid="chart-app-errors" />
        <ChartCard
          :title="`Besucher (pro ${stepText})`"
          :description="`Verschiedene Adressen je Zeitabschnitt, ohne erkannte Bots: nur wer mit einem Browser kam und durchgelassen wurde. „Neu“ heißt: in den letzten 7 Tagen nicht gesehen, ${COPY.sinceRestart} gezählt.`"
          :data="o"
          :series="clientSeries"
          :loading="other.isPending.value"
          :estimate-sentence="COPY.clientsEstimate"
          estimate-detail="Schild schätzt die Zahl der Adressen, ohne sie zu speichern. Werte aus verschiedenen Zeitabschnitten lassen sich nicht addieren."
          testid="chart-clients"
        />
      </div>

      <h2 class="mt-8 mb-3 text-lg font-semibold tracking-tight">
        Woher und wohin
      </h2>
      <div class="grid gap-4 lg:grid-cols-2">
        <BreakdownCard by="path" title="Häufigste Seiten" description="Seiten als Muster ({id} statt der echten Nummer), mit den Erkennungen der Regeln je Seite." :range="range" :site="site" :observe="observe" :top="10" class="lg:col-span-2" />
        <BreakdownCard by="rule" title="Regeln mit den meisten Erkennungen" description="Wie oft jede Regel angeschlagen hat." :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="country" title="Länder" :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="asn" title="Netze (ASN)" description="Der Anbieter, aus dessen Netz die Anfragen kommen." :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="net_class" title="Netzarten" :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="referrer" title="Herkunft" description="Von welcher Website die Besucher kamen, nur die Domain. KI-Assistenten sind zusammengefasst." :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="bot_category" title="Bots und Programme" description="Was die Anfragen über sich selbst sagen." :range="range" :site="site" :observe="observe" :top="13" />
        <BreakdownCard by="ua_class" title="Clients" :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="browser" title="Browser" :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="os" title="Betriebssysteme" :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="device" title="Geräte" :range="range" :site="site" :observe="observe" />
        <BreakdownCard by="method" title="Methoden" :range="range" :site="site" :observe="observe" />
        <BreakdownCard v-if="sitesNow.length > 1 && !site" by="site" title="Websites" :range="range" :observe="observe" :sites="siteNames" />
      </div>
      <p class="mt-6 text-xs text-muted-foreground">
        Alle Zahlen hier sind Summen. Einzelne Anfragen mit Adresse findest du unter Anfragen und Ereignisse; die Links in den Tabellen öffnen sie mit dem passenden Filter.
      </p>
    </template>
  </div>
</template>
