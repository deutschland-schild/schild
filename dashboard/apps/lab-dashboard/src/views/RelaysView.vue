<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { Peer, Relay } from '@/api/types'
import type { RelayMemory } from '@/lib/frozen'
import { Card, DataTable, formatPercent, PageHeader, RelativeTime, StatusPill } from '@schild/ui'
import { computed, h } from 'vue'
import { useHealth, usePeers, useRelays } from '@/api/queries'
import QueryState from '@/components/QueryState.vue'
import { FROZEN_AFTER_S, observeRelays } from '@/lib/frozen'
import { PEER_STATUS, RELAY_STATUS } from '@/lib/labels'
import { subscriberKey } from '@/lib/relays'

const relays = useRelays()
const peers = usePeers()
const health = useHealth()

// Remembered for the session: how long each relay's last_event_id stood still.
const memory: RelayMemory = (globalThis as { __schildRelayMemory?: RelayMemory }).__schildRelayMemory ??= new Map()
const relayItems = computed(() => relays.data.value?.items ?? [])
const relayHealth = computed(() => observeRelays(relayItems.value, memory, relays.dataUpdatedAt.value || Date.now()))
const frozenCount = computed(() => Object.values(relayHealth.value).filter(x => x.frozen).length)

const MIN_OPERATORS = 2
const DEFAULT_OPERATORS = 3
const peerItems = computed(() => peers.data.value?.items ?? [])
const independentOperators = computed(() => {
  const ops = new Set<string>()
  if (health.data.value?.operator) ops.add(health.data.value.operator)
  for (const p of peerItems.value) if (p.independent !== false && p.status !== 'down' && !p.observe_only) ops.add(p.operator)
  return ops.size
})

const relayColumns: ColumnDef<Relay, any>[] = [
  { accessorKey: 'id', header: 'Abonnent', cell: ({ row }) => h('div', {}, [h('span', { class: 'font-medium' }, row.original.id), h('span', { class: 'block font-mono text-xs text-muted-foreground' }, row.original.url ?? '')]) },
  {
    id: 'kind',
    header: 'Art',
    enableSorting: false,
    cell: ({ row }) => (row.original.kind === 'peer_lab'
      ? h(StatusPill, { tone: 'neutral', size: 'sm', title: 'Ein Peer-Lab folgt dem Feed zum Mitzeichnen. Es verteilt nichts an Clients.' }, () => 'Peer-Lab')
      : h(StatusPill, { tone: 'info', size: 'sm' }, () => 'Relay')),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => {
      const fr = relayHealth.value[subscriberKey(row.original)]
      if (fr?.frozen) return h(StatusPill, { tone: 'warning', size: 'sm' }, () => 'Eingefroren?')
      return h(StatusPill, { tone: RELAY_STATUS[row.original.status].tone, size: 'sm' }, () => RELAY_STATUS[row.original.status].text)
    },
  },
  { accessorKey: 'lag_events', header: 'Rückstand', meta: { class: 'text-right tabular-nums' }, cell: ({ row }) => (row.original.lag_events ? `${row.original.lag_events} Ereignisse` : '–') },
  {
    accessorKey: 'last_event_id',
    header: 'Letztes Ereignis',
    meta: { hideOnMobile: true },
    cell: ({ row }) => h('div', {}, [
      h('span', { class: 'font-mono text-xs' }, row.original.last_event_id ?? '–'),
      row.original.status === 'disconnected' ? null : h('span', { class: 'block text-xs text-muted-foreground' }, `unverändert seit ${relayHealth.value[subscriberKey(row.original)]?.stillForS ?? 0} s`),
    ]),
  },
  { accessorKey: 'connected_since', header: 'Verbunden seit', meta: { hideOnMobile: true }, cell: ({ row }) => (row.original.connected_since ? h(RelativeTime, { value: row.original.connected_since, class: 'text-xs' }) : '–') },
]

const yesNo = (v: boolean) => (v ? 'ja' : 'nein')
const peerColumns: ColumnDef<Peer, any>[] = [
  { accessorKey: 'lab', header: 'Lab', cell: ({ row }) => h('div', {}, [h('span', { class: 'font-medium' }, row.original.lab), h('span', { class: 'block font-mono text-xs text-muted-foreground' }, row.original.endpoint)]) },
  { accessorKey: 'operator', header: 'Betreiber' },
  {
    accessorKey: 'independent',
    header: 'Unabhängig',
    cell: ({ row }) => (row.original.independent === false
      ? h(StatusPill, { tone: 'neutral', size: 'sm' }, () => 'Gleicher Betreiber')
      : h(StatusPill, { tone: 'success', size: 'sm' }, () => 'Unabhängig')),
  },
  { accessorKey: 'status', header: 'Status', cell: ({ row }) => h(StatusPill, { tone: PEER_STATUS[row.original.status].tone, size: 'sm' }, () => PEER_STATUS[row.original.status].text) },
  { id: 'flow', header: 'Austausch', enableSorting: false, meta: { hideOnMobile: true }, cell: ({ row }) => `annehmen: ${yesNo(row.original.accept_from)} · teilen: ${yesNo(row.original.share_with)}${row.original.observe_only ? ' · nur beobachten' : ''}` },
  { accessorKey: 'trust_weight', header: 'Gewicht', meta: { class: 'text-right tabular-nums', hideOnMobile: true }, cell: ({ row }) => formatPercent(row.original.trust_weight) },
  { accessorKey: 'last_seen', header: 'Zuletzt', meta: { hideOnMobile: true }, cell: ({ row }) => (row.original.last_seen ? h(RelativeTime, { value: row.original.last_seen, class: 'text-xs' }) : '–') },
]
</script>

<template>
  <div class="space-y-8">
    <PageHeader title="Relays & Peers" description="Wer den Feed dieses Labs verteilt und mit welchen Labs es Hinweise austauscht." />

    <section class="space-y-3" aria-labelledby="relays-h">
      <div class="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="relays-h" class="text-base font-semibold">
          Relays
        </h2>
        <p class="text-sm text-muted-foreground">
          Als eingefroren gilt ein Relay, dessen letztes Ereignis {{ FROZEN_AFTER_S / 60 }} Minuten stillsteht, obwohl das Lab jede Minute einen Checkpoint sendet.
          Peer-Labs folgen dem Feed nur zum Mitzeichnen; sie stehen mit in der Liste, zählen aber nicht als Relays.
        </p>
      </div>
      <p v-if="frozenCount" class="rounded-md bg-status-warning-subtle p-3 text-sm" role="status">
        {{ frozenCount === 1 ? '1 Relay steht still.' : `${frozenCount} Relays stehen still.` }} Clients merken das am abgelaufenen Checkpoint und wechseln auf andere Relays.
      </p>
      <QueryState :pending="relays.isPending.value" :error="relays.error.value" @retry="relays.refetch()">
        <DataTable :columns="relayColumns" :data="relayItems" label="Relays" :get-row-id="subscriberKey" hide-column-menu empty-title="Kein Relay abonniert den Feed" />
      </QueryState>
    </section>

    <section class="space-y-3" aria-labelledby="peers-h">
      <h2 id="peers-h" class="text-base font-semibold">
        Peers
      </h2>
      <Card class="flex-row flex-wrap items-center gap-x-6 gap-y-2 p-4 text-sm" data-testid="independence">
        <div>
          <p class="text-muted-foreground">
            Unabhängige Betreiber erreichbar
          </p>
          <p class="text-2xl font-bold tabular-nums">
            {{ independentOperators }}
          </p>
        </div>
        <p class="max-w-prose text-muted-foreground">
          Einschließlich dieses Labs. Bündel und Rückzüge brauchen Signaturen von mindestens {{ MIN_OPERATORS }} verschiedenen Betreibern, empfohlen sind {{ DEFAULT_OPERATORS }}. Labs desselben Betreibers zählen einmal.
          <template v-if="independentOperators < MIN_OPERATORS">
            <strong class="text-status-warning">Gerade sind es zu wenige.</strong>
          </template>
        </p>
        <p v-if="health.data.value?.profile === 'test'" class="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <StatusPill tone="info" size="sm">
            Testprofil
          </StatusPill>
          Simulierte Betreiber zählen nur zum Beobachten.
        </p>
      </Card>
      <QueryState :pending="peers.isPending.value" :error="peers.error.value" @retry="peers.refetch()">
        <DataTable :columns="peerColumns" :data="peerItems" label="Peers" :get-row-id="(p: Peer) => p.lab" empty-title="Keine Peers konfiguriert" />
      </QueryState>
    </section>
  </div>
</template>
