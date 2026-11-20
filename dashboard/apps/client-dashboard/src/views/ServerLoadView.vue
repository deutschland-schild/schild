<script setup lang="ts">
import type { TimeSeries } from '@schild/ui'
import type { RangeKey, ServerSnapshot } from '@/api/monitoring'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatBytes, formatDateTime, formatDecimal, formatDuration, formatMs, formatNumber, Skeleton } from '@schild/ui'
import { Info } from '@lucide/vue'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage } from '@/api/client'
import { isMonitoringOff, monitoringOff, rangeOf, useMetricSeries, useServerSnapshot, valuesOf } from '@/api/monitoring'
import ChartCard from '@/components/monitoring/ChartCard.vue'
import RangeSiteBar from '@/components/monitoring/RangeSiteBar.vue'
import ServerHeader from '@/components/ServerHeader.vue'
import { versionText } from '@/lib/labels'
import { bytesPerSecond, COPY, OUTCOME_COLORS, ratioText, TONES } from '@/lib/monitoring'

/**
 * Server, tab "Auslastung" (/server/load, MVP-21): CPU, load, memory, disks, network, connections, open files and
 * Schild itself, sampled every 10 s from /proc and /sys. Says what is visible in this environment.
 */
const route = useRoute()
const router = useRouter()
const range = computed({
  get: () => rangeOf(route.query.time).key,
  set: (v: RangeKey) => {
    const query = { ...route.query }
    if (v === '6h') delete query.time
    else query.time = v
    void router.replace({ query })
  },
})

const snapQ = useServerSnapshot()
const s = computed<ServerSnapshot | undefined>(() => snapQ.data.value)
const off = computed(() => monitoringOff.value || isMonitoringOff(snapQ.error.value))
const series = useMetricSeries(() => ({
  metrics: [
    'server.cpu_usage:avg', 'server.cpu_usage:max', 'server.cpu_iowait', 'server.load1', 'server.load5',
    'server.memory_used', 'server.swap_used', 'server.disk_used_ratio', 'server.net_rx_bytes', 'server.net_tx_bytes',
    'server.tcp_established', 'server.tcp_time_wait', 'process.cpu_usage', 'process.rss',
  ],
  range: range.value,
}), () => !off.value)
const d = computed(() => series.data.value)
const v = (metric: string, stat?: string, object?: string) => valuesOf(d.value, metric, stat, object)
const objects = (metric: string) => (d.value?.series ?? []).filter(x => x.metric === metric && x.object).map(x => x.object!)
const sumObjects = (metric: string) => {
  const all = (d.value?.series ?? []).filter(x => x.metric === metric)
  if (!all.length) return v(metric)
  return all[0]!.values.map((_, i) => all.some(x => x.values[i] === null) ? null : all.reduce((a, x) => a + (x.values[i] ?? 0), 0))
}

const cpuSeries = computed<TimeSeries[]>(() => [
  { id: 'avg', label: 'Mittel', values: v('server.cpu_usage', 'avg'), color: TONES.main, fill: true },
  { id: 'max', label: 'Höchstwert', values: v('server.cpu_usage', 'max'), color: TONES.main, dashed: true },
  { id: 'iowait', label: 'Warten auf Festplatte', values: v('server.cpu_iowait'), color: TONES.neutral },
])
const loadSeries = computed<TimeSeries[]>(() => {
  const cores = s.value?.cpu?.cores ?? null
  const n = d.value?.points ?? 0
  return [
    { id: 'load1', label: 'Last (1 Minute)', values: v('server.load1'), color: TONES.main, fill: true },
    { id: 'load5', label: 'Last (5 Minuten)', values: v('server.load5'), color: TONES.deep },
    ...(cores ? [{ id: 'cores', label: `Kerne (${cores})`, values: Array.from({ length: n }, () => cores), color: TONES.neutral, dashed: true }] : []),
  ]
})
const memSeries = computed<TimeSeries[]>(() => [
  { id: 'used', label: 'Belegt', values: v('server.memory_used'), color: TONES.main, fill: true },
  { id: 'swap', label: 'Ausgelagert (Swap)', values: v('server.swap_used'), color: TONES.neutral },
])
// Mounts are nominal: up to three tones, then dashes; legend, tooltip and table name each one.
const MOUNT_STYLES = [{ color: TONES.main }, { color: TONES.deep }, { color: TONES.neutral }, { color: TONES.main, dashed: true }, { color: TONES.deep, dashed: true }, { color: TONES.neutral, dashed: true }]
const diskSeries = computed<TimeSeries[]>(() => objects('server.disk_used_ratio').map((o, i) => ({ id: o, label: o, values: v('server.disk_used_ratio', 'avg', o), ...MOUNT_STYLES[i % MOUNT_STYLES.length]! })))
const netSeries = computed<TimeSeries[]>(() => [
  { id: 'tx', label: 'Gesendet', values: sumObjects('server.net_tx_bytes'), color: TONES.main, fill: true },
  { id: 'rx', label: 'Empfangen', values: sumObjects('server.net_rx_bytes'), color: TONES.neutral },
])
const tcpSeries = computed<TimeSeries[]>(() => [
  { id: 'est', label: 'Aufgebaut', values: v('server.tcp_established'), color: TONES.main, fill: true },
  { id: 'tw', label: 'Am Schließen (TIME_WAIT)', values: v('server.tcp_time_wait'), color: TONES.neutral },
])
const procSeries = computed<TimeSeries[]>(() => [
  { id: 'cpu', label: 'CPU von Schild', values: v('process.cpu_usage'), color: TONES.main, fill: true },
])

const pct = (r: number | null | undefined) => ratioText(r)
const AREA: Record<string, string> = {
  cpu: 'CPU', memory: 'Arbeitsspeicher', load: 'Last', container: 'Container-Limits', mounts: 'Festplatten', disk_io: 'Lesen und Schreiben',
  interfaces: 'Netzwerk', tcp: 'Verbindungen', conntrack: 'Verbindungstabelle der Firewall', files: 'Offene Dateien', os: 'Betriebssystem',
}
const REASON: Record<string, string> = {
  not_linux: 'kein Linux', host_off: 'abgeschaltet (monitoring.host: false)', container_hidden: 'aus dem Container nicht sichtbar', no_permission: 'keine Leserechte',
  not_present: 'vom Kernel nicht bereitgestellt', cgroup_v1: 'nur mit cgroup v2',
}
const visibility = computed(() => {
  const e = s.value?.environment
  if (!e) return []
  const out: string[] = []
  if (e.os_family !== 'linux') out.push('Schild läuft nicht unter Linux. Serverwerte gibt es hier nicht, Traffic und die Werte von Schild selbst schon.')
  else if (e.container && !e.lxcfs) out.push(COPY.container)
  else if (e.container && e.lxcfs) out.push('Schild läuft in einem Container mit lxcfs. CPU und Arbeitsspeicher zeigen den Container.')
  else out.push('Schild läuft direkt auf dem Server. Alle Werte beschreiben den ganzen Server.')
  if (e.container && e.net_namespace === 'own') out.push(COPY.ownNetwork)
  else if (e.container && e.net_namespace === 'host') out.push('Netzwerk, Verbindungen und die Verbindungstabelle zeigen den ganzen Server (network_mode: host).')
  else if (e.container) out.push('Ob Netzwerkwerte den Server oder nur den Container zeigen, ließ sich nicht sicher erkennen.')
  if (e.container) out.push('Festplatten zeigen, was der Container sieht. Weitere Festplatten des Servers bindest du schreibgeschützt ein und trägst sie unter monitoring.mounts ein.')
  return out
})
/** Off Linux there are no host values at all: say so instead of "the first appear after about 10 seconds". */
const hostEmpty = computed(() => s.value?.environment && s.value.environment.os_family !== 'linux'
  ? 'Serverwerte misst Schild nur unter Linux. Auf diesem System bleibt das Diagramm deshalb leer.'
  : undefined)
const unavailable = computed(() => (s.value?.unavailable ?? []).map(u => `${AREA[u.area] ?? u.area}: ${REASON[u.reason] ?? u.reason}`))
const maxPerCore = computed(() => s.value?.cpu?.per_core ?? [])
const fileRatio = (a?: number, b?: number) => a !== undefined && b ? a / b : null
</script>

<template>
  <div>
    <ServerHeader description="Wie ausgelastet der Server ist: CPU, Arbeitsspeicher, Festplatten, Netzwerk und Schild selbst. Schild liest die Werte alle 10 Sekunden.">
      <template #actions>
        <RangeSiteBar v-model:range="range" no-sites />
      </template>
    </ServerHeader>

    <p v-if="off" class="rounded-xl border bg-card p-4 text-sm text-muted-foreground" data-testid="monitoring-off">
      {{ COPY.monitoringOff }}
    </p>
    <ErrorState
      v-else-if="snapQ.isError.value && !s"
      title="Die Serverwerte lassen sich gerade nicht laden"
      :description="errorMessage(snapQ.error.value)"
      :retrying="snapQ.isFetching.value"
      @retry="snapQ.refetch()"
    />
    <div v-else-if="!s" class="grid gap-4 lg:grid-cols-2">
      <Skeleton v-for="i in 4" :key="i" class="h-48" />
    </div>
    <template v-else>
      <section class="mb-4 flex gap-3 rounded-xl border bg-card p-4 text-sm" aria-labelledby="visible-title" data-testid="visibility">
        <Info class="mt-0.5 size-4 shrink-0 text-status-info" aria-hidden="true" />
        <div class="space-y-1">
          <h2 id="visible-title" class="font-medium">
            Was du hier siehst
          </h2>
          <p v-for="t in visibility" :key="t" class="text-muted-foreground">
            {{ t }}
          </p>
          <p v-if="unavailable.length" class="text-muted-foreground">
            Nicht verfügbar: {{ unavailable.join(' · ') }}.
          </p>
        </div>
      </section>

      <dl class="mb-6 grid gap-4 rounded-xl border bg-card p-4 text-sm sm:grid-cols-2 lg:grid-cols-4" data-testid="server-facts">
        <div>
          <dt class="text-muted-foreground">
            Betriebssystem
          </dt>
          <dd class="mt-1 font-medium">
            {{ s.os?.name ?? 'Unbekannt' }}
            <span v-if="s.os?.eol" class="block text-xs font-normal text-muted-foreground">Updates bis {{ new Date(s.os.eol).toLocaleDateString('de-DE') }}</span>
          </dd>
        </div>
        <div>
          <dt class="text-muted-foreground">
            Kernel
          </dt>
          <dd class="mt-1 font-mono text-xs">
            {{ s.os?.kernel ?? '–' }} · {{ s.os?.arch ?? '' }}
          </dd>
        </div>
        <div>
          <dt class="text-muted-foreground">
            Server läuft seit
          </dt>
          <dd class="mt-1 font-medium">
            {{ s.uptime_s != null ? formatDuration(s.uptime_s) : '–' }}
          </dd>
        </div>
        <div>
          <dt class="text-muted-foreground">
            Schild läuft seit
          </dt>
          <dd class="mt-1 font-medium" :title="formatDateTime(s.process.started_at)">
            {{ formatDuration((Date.parse(s.generated_at) - Date.parse(s.process.started_at)) / 1000) }}
            <span v-if="s.process.version" class="block text-xs font-normal text-muted-foreground">{{ versionText(s.process.version) }}</span>
          </dd>
        </div>
      </dl>

      <div class="grid gap-4 lg:grid-cols-2">
        <!-- CPU -->
        <Card class="min-w-0" data-testid="card-cpu">
          <CardHeader>
            <CardTitle>CPU</CardTitle>
            <CardDescription v-if="s.cpu">
              {{ pct(s.cpu.usage) }} ausgelastet · {{ s.cpu.cores }} Kerne · Nutzer {{ pct(s.cpu.user) }}, System {{ pct(s.cpu.system) }}, Warten auf Festplatte {{ pct(s.cpu.iowait) }}<template v-if="s.cpu.steal > 0.001">, abgezweigt vom Anbieter {{ pct(s.cpu.steal) }}</template>
            </CardDescription>
            <CardDescription v-else>
              Nicht verfügbar.
            </CardDescription>
          </CardHeader>
          <CardContent v-if="maxPerCore.length">
            <ul class="grid grid-cols-[repeat(auto-fill,minmax(4.5rem,1fr))] gap-2" aria-label="Auslastung je Kern">
              <li v-for="(c, i) in maxPerCore" :key="i" class="text-xs">
                <span class="flex justify-between text-muted-foreground"><span>Kern {{ i + 1 }}</span><span class="tabular-nums text-foreground">{{ formatNumber(Math.round(c * 100)) }} %</span></span>
                <span class="mt-1 block h-1.5 rounded-full bg-muted" aria-hidden="true"><span class="block h-full rounded-full" :style="{ width: `${c * 100}%`, background: OUTCOME_COLORS.data }" /></span>
              </li>
            </ul>
          </CardContent>
        </Card>
        <ChartCard title="CPU-Auslastung" :empty-text="hostEmpty" :data="d" :series="cpuSeries" :loading="series.isPending.value" :format="pct" :axis-format="pct" :max="1" testid="chart-cpu" />

        <ChartCard
          title="Last"
          :empty-text="hostEmpty"
          :description="s.cpu?.load1 !== undefined ? `Gerade ${formatDecimal(s.cpu.load1)} (1 Minute), ${formatDecimal(s.cpu.load5)} (5 Minuten), ${formatDecimal(s.cpu.load15)} (15 Minuten). Liegt die Last länger über der Zahl der Kerne, warten Prozesse auf Rechenzeit.` : undefined"
          :data="d"
          :series="loadSeries"
          :loading="series.isPending.value"
          :format="formatDecimal"
          testid="chart-load"
        />
        <ChartCard
          title="Arbeitsspeicher und Swap"
          :empty-text="hostEmpty"
          :description="s.memory ? `${formatBytes(s.memory.used_bytes)} von ${formatBytes(s.memory.total_bytes)} belegt, ${formatBytes(s.memory.available_bytes)} frei${s.memory.cached_bytes ? ` (davon ${formatBytes(s.memory.cached_bytes)} Zwischenspeicher)` : ''}. Swap: ${formatBytes(s.memory.swap_used_bytes)} von ${formatBytes(s.memory.swap_total_bytes)}.` : 'Nicht verfügbar.'"
          :data="d"
          :series="memSeries"
          :loading="series.isPending.value"
          :format="formatBytes"
          :axis-format="formatBytes"
          testid="chart-memory"
        />

        <!-- Disks -->
        <Card class="min-w-0 lg:col-span-2" data-testid="card-disks">
          <CardHeader>
            <CardTitle>Festplatten</CardTitle>
            <CardDescription>Belegung, Dateien (Inodes), Lesen und Schreiben je Festplatte.</CardDescription>
          </CardHeader>
          <CardContent>
            <p v-if="!s.mounts.length" class="text-sm text-muted-foreground">
              Keine Festplatten sichtbar.
            </p>
            <div v-else class="-mx-2 overflow-x-auto" tabindex="0" role="region" aria-label="Festplatten">
              <table class="w-full min-w-[40rem] text-sm tabular-nums">
                <caption class="sr-only">
                  Festplatten
                </caption>
                <thead class="text-xs text-muted-foreground">
                  <tr>
                    <th scope="col" class="px-2 pb-2 text-left font-medium">
                      Einhängepunkt
                    </th>
                    <th scope="col" class="px-2 pb-2 text-left font-medium">
                      Belegt
                    </th>
                    <th scope="col" class="px-2 pb-2 text-right font-medium">
                      Frei
                    </th>
                    <th scope="col" class="px-2 pb-2 text-right font-medium">
                      Inodes
                    </th>
                    <th scope="col" class="px-2 pb-2 text-right font-medium">
                      Lesen
                    </th>
                    <th scope="col" class="px-2 pb-2 text-right font-medium">
                      Schreiben
                    </th>
                    <th scope="col" class="px-2 pb-2 text-right font-medium">
                      Ausgelastet
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="m in s.mounts" :key="m.mount" class="border-t">
                    <th scope="row" class="px-2 py-2 text-left font-normal">
                      <span class="font-mono text-xs">{{ m.mount }}</span>
                      <span class="block text-xs text-muted-foreground">{{ m.device ?? '' }} · {{ m.fs_type }} · {{ formatBytes(m.size_bytes) }}</span>
                    </th>
                    <td class="px-2 py-2">
                      <span :class="m.used_ratio >= 0.9 ? 'font-medium text-status-warning' : ''">{{ pct(m.used_ratio) }}</span>
                      <span class="mt-1 block h-1.5 w-28 rounded-full bg-muted" aria-hidden="true"><span class="block h-full rounded-full" :style="{ width: `${m.used_ratio * 100}%`, background: m.used_ratio >= 0.9 ? 'var(--warning)' : OUTCOME_COLORS.data }" /></span>
                    </td>
                    <td class="px-2 py-2 text-right">
                      {{ formatBytes(m.avail_bytes) }}
                    </td>
                    <td class="px-2 py-2 text-right">
                      {{ m.inodes_total ? pct(fileRatio(m.inodes_used, m.inodes_total)) : '–' }}
                    </td>
                    <td class="px-2 py-2 text-right">
                      {{ bytesPerSecond(m.read_bytes_per_s) }}
                    </td>
                    <td class="px-2 py-2 text-right">
                      {{ bytesPerSecond(m.write_bytes_per_s) }}
                    </td>
                    <td class="px-2 py-2 text-right">
                      {{ pct(m.busy) }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
        <ChartCard title="Belegung der Festplatten" :empty-text="hostEmpty" :data="d" :series="diskSeries" :loading="series.isPending.value" :format="pct" :axis-format="pct" :max="1" class="lg:col-span-2" testid="chart-disks" />

        <!-- Network -->
        <Card class="min-w-0" data-testid="card-network">
          <CardHeader>
            <CardTitle>Netzwerk</CardTitle>
            <CardDescription>Je Schnittstelle, alles was über die Leitung geht.</CardDescription>
          </CardHeader>
          <CardContent>
            <p v-if="!s.interfaces.length" class="text-sm text-muted-foreground">
              Keine Schnittstellen sichtbar.
            </p>
            <ul v-else class="divide-y text-sm">
              <li v-for="i in s.interfaces" :key="i.name" class="flex flex-wrap justify-between gap-x-4 gap-y-1 py-2">
                <span class="font-mono text-xs">{{ i.name }}</span>
                <span class="tabular-nums">↓ {{ bytesPerSecond(i.rx_bytes_per_s) }} · ↑ {{ bytesPerSecond(i.tx_bytes_per_s) }}</span>
                <span class="w-full text-xs text-muted-foreground">
                  {{ formatDecimal(i.rx_packets_per_s + i.tx_packets_per_s) }} Pakete/s · Fehler {{ formatDecimal(i.errors_per_s) }}/s · verworfen {{ formatDecimal(i.drops_per_s) }}/s
                </span>
              </li>
            </ul>
          </CardContent>
        </Card>
        <ChartCard title="Netzwerk gesamt" :empty-text="hostEmpty" :data="d" :series="netSeries" :loading="series.isPending.value" :format="bytesPerSecond" :axis-format="bytesPerSecond" testid="chart-network" />

        <!-- Connections -->
        <Card class="min-w-0" data-testid="card-tcp">
          <CardHeader>
            <CardTitle>Verbindungen</CardTitle>
            <CardDescription v-if="s.tcp">
              TCP-Verbindungen nach Zustand<template v-if="s.tcp.source === 'sockstat'"> (nur Summen verfügbar)</template>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p v-if="!s.tcp" class="text-sm text-muted-foreground">
              Nicht verfügbar.
            </p>
            <dl v-else class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
              <div><dt class="text-xs text-muted-foreground">Aufgebaut</dt><dd class="tabular-nums">{{ formatNumber(s.tcp.established) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Im Aufbau</dt><dd class="tabular-nums">{{ formatNumber(s.tcp.syn_recv + s.tcp.syn_sent) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Am Schließen</dt><dd class="tabular-nums">{{ formatNumber(s.tcp.time_wait + s.tcp.fin_wait + s.tcp.close_wait + s.tcp.last_ack + s.tcp.closing) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Offene Ports</dt><dd class="tabular-nums" data-testid="tcp-listen" :title="s.tcp.listen === null ? 'Mit sehr vielen Verbindungen zählt Schild nur Summen; offene Ports sind dann nicht bekannt.' : undefined">{{ s.tcp.listen === null ? 'unbekannt' : formatNumber(s.tcp.listen) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Abgewiesen (Warteschlange voll)</dt><dd class="tabular-nums">{{ formatDecimal(s.tcp.listen_drops_per_s ?? 0) }}/s</dd></div>
              <div><dt class="text-xs text-muted-foreground">Neu gesendet</dt><dd class="tabular-nums">{{ formatDecimal(s.tcp.retransmits_per_s ?? 0) }}/s</dd></div>
              <div class="col-span-2 sm:col-span-3">
                <dt class="text-xs text-muted-foreground">
                  Verbindungstabelle der Firewall
                </dt>
                <dd class="tabular-nums">
                  {{ s.conntrack ? `${formatNumber(s.conntrack.count)} von ${formatNumber(s.conntrack.max)} (${pct(s.conntrack.count / s.conntrack.max)})` : 'nicht sichtbar' }}
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
        <ChartCard title="Verbindungen" :empty-text="hostEmpty" :data="d" :series="tcpSeries" :loading="series.isPending.value" :format="formatNumber" testid="chart-tcp" />

        <!-- Files and Schild itself -->
        <Card class="min-w-0" data-testid="card-files">
          <CardHeader>
            <CardTitle>Offene Dateien</CardTitle>
          </CardHeader>
          <CardContent>
            <dl class="grid grid-cols-2 gap-4 text-sm">
              <div>
                <dt class="text-xs text-muted-foreground">
                  Ganzer Server
                </dt>
                <dd class="tabular-nums">
                  {{ s.files ? `${formatNumber(s.files.open)} von ${formatNumber(s.files.max)}` : 'nicht verfügbar' }}
                </dd>
              </div>
              <div>
                <dt class="text-xs text-muted-foreground">
                  Schild
                </dt>
                <dd class="tabular-nums">
                  {{ formatNumber(s.process.open_files) }} von {{ formatNumber(s.process.open_files_limit) }}
                </dd>
              </div>
            </dl>
            <template v-if="s.container">
              <h3 class="mt-5 mb-2 text-sm font-medium">
                Container von Schild
              </h3>
              <dl class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <dt class="text-xs text-muted-foreground">
                    CPU-Limit
                  </dt>
                  <dd class="tabular-nums">
                    {{ s.container.cpu_limit_cores ? `${formatDecimal(s.container.cpu_limit_cores)} Kerne` : 'kein Limit' }} · genutzt {{ pct(s.container.cpu_usage) }}<template v-if="s.container.cpu_throttled > 0">, gebremst {{ pct(s.container.cpu_throttled) }}</template>
                  </dd>
                </div>
                <div>
                  <dt class="text-xs text-muted-foreground">
                    Speicher-Limit
                  </dt>
                  <dd class="tabular-nums">
                    {{ formatBytes(s.container.memory_used_bytes) }} von {{ s.container.memory_limit_bytes ? formatBytes(s.container.memory_limit_bytes) : 'unbegrenzt' }}
                  </dd>
                </div>
              </dl>
            </template>
          </CardContent>
        </Card>
        <Card class="min-w-0" data-testid="card-schild">
          <CardHeader>
            <CardTitle>Schild selbst</CardTitle>
            <CardDescription>{{ pct(s.process.cpu_usage) }} der CPU, {{ formatBytes(s.process.rss_bytes) }} Arbeitsspeicher.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl class="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
              <div><dt class="text-xs text-muted-foreground">Prüfplätze belegt</dt><dd class="tabular-nums">{{ s.schild.eval_slots_used }} von {{ s.schild.eval_slots_max }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Warteschlange der Ereignisse</dt><dd class="tabular-nums">{{ formatNumber(s.schild.event_queue_used) }} von {{ formatNumber(s.schild.event_queue_capacity) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Nicht gespeicherte Ereignisse (1 Stunde)</dt><dd class="tabular-nums">{{ formatNumber(s.schild.events_dropped_1h) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Speicher der Ereignisse</dt><dd class="tabular-nums">{{ formatBytes(s.schild.store_bytes) }} von {{ formatBytes(s.schild.store_max_bytes) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Speicher der Messwerte</dt><dd class="tabular-nums">{{ formatBytes(s.schild.metrics_store_bytes) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Dauer einer Messung</dt><dd class="tabular-nums">{{ formatMs(s.schild.sampler_ms) }} (erlaubt {{ formatMs(s.schild.sampler_budget_ms) }})</dd></div>
              <div><dt class="text-xs text-muted-foreground">Go-Routinen · Threads</dt><dd class="tabular-nums">{{ formatNumber(s.process.goroutines) }} · {{ formatNumber(s.process.threads) }}</dd></div>
              <div><dt class="text-xs text-muted-foreground">Speicherbereinigung p99</dt><dd class="tabular-nums">{{ formatMs(s.process.gc_pause_p99_ms) }}</dd></div>
            </dl>
          </CardContent>
        </Card>
        <ChartCard title="CPU von Schild" description="Anteil an allen Kernen." :data="d" :series="procSeries" :loading="series.isPending.value" :format="pct" :axis-format="pct" class="lg:col-span-2" testid="chart-process" />
      </div>
      <p class="mt-6 text-xs text-muted-foreground">
        Stand {{ s.sampled_at ? formatDateTime(s.sampled_at) : '–' }}, neue Werte alle 10 Sekunden.
      </p>
    </template>
  </div>
</template>
