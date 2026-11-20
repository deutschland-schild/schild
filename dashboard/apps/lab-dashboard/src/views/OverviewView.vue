<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { Worker } from '@/api/types'
import {
  BarList,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  formatNumber,
  PageHeader,
  RelativeTime,
  StatCard,
  StatusPill,
} from '@schild/ui'
import { computed, h } from 'vue'
import { useProposals, useRelays, useSettings, useWithdrawals } from '@/api/queries'
import AckLatency from '@/components/AckLatency.vue'
import AlertList from '@/components/AlertList.vue'
import QueryState from '@/components/QueryState.vue'
import { useHealthHistory } from '@/composables/useHealthHistory'
import { computeAlerts } from '@/lib/alerts'
import { ACK_P99_TARGET_MS, QUEUE_LABEL, REJECT_REASON_LABEL, WORKER_STATUS } from '@/lib/labels'

const { health, history } = useHealthHistory()
const relays = useRelays()
const withdrawals = useWithdrawals()
const review = useProposals('review')
const settings = useSettings()

const h0 = computed(() => health.data.value)
const alerts = computed(() => computeAlerts({
  health: h0.value,
  relays: relays.data.value?.items,
  withdrawals: withdrawals.items.value,
  review: review.items.value,
  checkpointTtlS: settings.data.value?.publish.checkpoint_ttl_s,
}))

const queueTotal = computed(() => {
  const d = h0.value?.queue.depth
  return d ? d.new_pattern + d.repeat + d.baseline : 0
})
const queueItems = computed(() => {
  const d = h0.value?.queue.depth
  if (!d) return []
  return (['new_pattern', 'repeat', 'baseline'] as const).map(k => ({ id: k, label: `${QUEUE_LABEL[k].text} · ${QUEUE_LABEL[k].hint}`, value: d[k] }))
})
const rejectItems = computed(() => Object.entries(h0.value?.ingest.rejected_by_reason ?? {})
  .map(([k, v]) => ({ id: k, label: REJECT_REASON_LABEL[k] ?? k, value: v }))
  .sort((a, b) => b.value - a.value))

const fmtMs = (v?: number) => (v === undefined ? '–' : `${v.toLocaleString('de-DE', { maximumFractionDigits: 1 })}`)

const workerColumns: ColumnDef<Worker, any>[] = [
  { accessorKey: 'name', header: 'Worker', cell: ({ row }) => h('span', { class: 'font-medium' }, row.original.name) },
  { accessorKey: 'status', header: 'Status', cell: ({ row }) => h(StatusPill, { tone: WORKER_STATUS[row.original.status].tone, size: 'sm' }, () => WORKER_STATUS[row.original.status].text) },
  { accessorKey: 'processed_per_s', header: 'Pro Sekunde', meta: { class: 'text-right tabular-nums' }, cell: ({ row }) => formatNumber(row.original.processed_per_s ?? 0) },
  { accessorKey: 'lag_s', header: 'Rückstand', meta: { class: 'text-right tabular-nums' }, cell: ({ row }) => `${fmtMs(row.original.lag_s ?? 0)} s` },
  { accessorKey: 'last_error', header: 'Letzter Fehler', enableSorting: false, meta: { hideOnMobile: true }, cell: ({ row }) => row.original.last_error ?? '–' },
]
</script>

<template>
  <div class="space-y-6">
    <PageHeader title="Überblick" :description="h0 ? `Eingang, Warteschlange und Feed von ${h0.lab} (Betreiber ${h0.operator}).` : 'Eingang, Warteschlange und Feed des Labs.'">
      <template v-if="h0" #meta>
        <StatusPill v-if="h0.profile === 'test'" tone="info" size="sm">
          Testprofil
        </StatusPill>
        <span class="text-xs text-muted-foreground">Stand <RelativeTime :value="h0.generated_at" :interval="5000" /></span>
      </template>
    </PageHeader>

    <QueryState :pending="health.isPending.value" :error="health.error.value" :rows="4" :retrying="health.isFetching.value" @retry="health.refetch()">
      <template v-if="h0">
        <AlertList :alerts="alerts" />

        <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Eingang"
            :value="Math.round(h0.ingest.rate_per_s * 60)"
            unit="Signale/min"
            :hint="`${formatNumber(h0.ingest.accepted_24h)} angenommen in 24 h`"
            :trend="history.rate"
            trend-label="Signale pro Minute, letzte Messungen"
          />
          <StatCard
            label="Ack-Latenz p99"
            :value="fmtMs(h0.ack_ms.p99)"
            unit="ms"
            :tone="h0.ack_ms.p99 >= ACK_P99_TARGET_MS ? 'danger' : 'success'"
            :hint="`p50 ${fmtMs(h0.ack_ms.p50)} ms · Ziel unter ${ACK_P99_TARGET_MS} ms`"
            :trend="history.p99"
            trend-label="Ack-Latenz p99, letzte Messungen"
            data-testid="stat-ack"
          />
          <StatCard
            label="Warteschlange"
            :value="queueTotal"
            :tone="h0.queue.full ? 'danger' : 'neutral'"
            :hint="h0.queue.full ? 'Voll: Clients bekommen retry_after' : `von ${formatNumber(h0.queue.max_depth)} · älteste ${fmtMs(h0.queue.oldest_age_s)} s`"
            :trend="history.queue"
            trend-label="Warteschlange gesamt, letzte Messungen"
          />
          <StatCard
            label="Feed"
            :value="`Bündel ${h0.feed.bundle_version}`"
            :hint="`Rückzug ${h0.feed.withdrawal_seq} · Checkpoint ${h0.feed.checkpoint_seq} · ${h0.feed.subscribers} Feed-Verbindungen`"
          />
        </div>

        <div class="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Ack-Latenz</CardTitle>
              <CardDescription>Zeit bis zur Quittung an den Client. Das Dashboard läuft getrennt vom Eingang.</CardDescription>
            </CardHeader>
            <CardContent>
              <AckLatency :ack="h0.ack_ms" />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Warteschlange nach Priorität</CardTitle>
              <CardDescription>
                Neue Muster zuerst, Grundrauschen zuletzt.
                <template v-if="h0.queue.full">
                  <strong class="text-status-danger">Voll.</strong>
                </template>
              </CardDescription>
            </CardHeader>
            <CardContent>
              <BarList :items="queueItems" label="Warteschlange nach Priorität" />
            </CardContent>
          </Card>
        </div>

        <div class="grid gap-4 lg:grid-cols-3">
          <div class="min-w-0 space-y-2 lg:col-span-2">
            <h2 class="font-bold">
              Worker
            </h2>
            <DataTable :columns="workerColumns" :data="h0.workers" label="Worker" :get-row-id="(w: Worker) => w.name" hide-column-menu max-height="none" :page-sizes="[25]" />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Abgelehnt in 24 h</CardTitle>
              <CardDescription>
                {{ formatNumber(h0.ingest.rejected_24h) }} abgelehnt, {{ formatNumber(h0.ingest.duplicate_24h) }} doppelt<template v-if="h0.ingest.retry_after_sent_24h">, {{ formatNumber(h0.ingest.retry_after_sent_24h) }} × später erneut</template>.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <BarList v-if="rejectItems.length" :items="rejectItems" label="Ablehnungen nach Grund" color="var(--chart-3)" />
              <p v-else class="text-sm text-muted-foreground">
                Nichts abgelehnt.
              </p>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Feed</CardTitle>
            <CardDescription>Was Relays und Clients von diesem Lab bekommen.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl class="grid gap-4 text-sm sm:grid-cols-4">
              <div>
                <dt class="text-muted-foreground">
                  Aktuelles Bündel
                </dt>
                <dd class="font-medium tabular-nums">
                  <RouterLink :to="`/published/${h0.feed.bundle_version}`" class="underline-offset-4 hover:underline">
                    Version {{ h0.feed.bundle_version }}
                  </RouterLink>
                </dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Rückzüge
                </dt>
                <dd class="font-medium tabular-nums">
                  bis Nr. {{ h0.feed.withdrawal_seq }}
                </dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Letzter Checkpoint
                </dt>
                <dd class="font-medium tabular-nums">
                  Nr. {{ h0.feed.checkpoint_seq }}<template v-if="h0.feed.last_checkpoint_at">
                    · <RelativeTime :value="h0.feed.last_checkpoint_at" :interval="5000" />
                  </template>
                </dd>
              </div>
              <div>
                <dt class="text-muted-foreground">
                  Abonnenten
                </dt>
                <dd class="font-medium tabular-nums">
                  <RouterLink to="/relays" class="underline-offset-4 hover:underline">
                    {{ h0.feed.subscribers }} {{ h0.feed.subscribers === 1 ? 'Verbindung' : 'Verbindungen' }} (Relays und Peers)
                  </RouterLink>
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </template>
    </QueryState>
  </div>
</template>
