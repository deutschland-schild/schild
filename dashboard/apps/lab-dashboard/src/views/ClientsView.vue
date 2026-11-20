<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { Client, Issuer } from '@/api/types'
import {
  Button,
  DataTable,
  FilterBar,
  formatNumber,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  RelativeTime,
  StatusPill,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  toast,
} from '@schild/ui'
import { computed, h, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useClients, useIssuers, useRevokeClient, useRevokeIssuer, useUpdateClientQuota, useUpdateIssuerQuota } from '@/api/queries'
import PasswordConfirmDialog from '@/components/PasswordConfirmDialog.vue'
import QueryState from '@/components/QueryState.vue'
import QuotaDialog from '@/components/QuotaDialog.vue'
import UsageBar from '@/components/UsageBar.vue'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { useSession } from '@/composables/useSession'
import { useShortcuts } from '@/composables/useShortcuts'

const { canEdit } = useSession()
const tabQuery = useRouteQuery('tab')
const tab = computed({ get: () => tabQuery.value || 'issuers', set: v => (tabQuery.value = v === 'issuers' ? '' : v) })
const search = useRouteQuery('q')
const issuerFilter = useRouteQuery('issuer')

const issuers = useIssuers()
const clients = useClients(() => issuerFilter.value || undefined)
const issuerItems = computed(() => {
  const all = issuers.data.value?.items ?? []
  const q = search.value.trim().toLowerCase()
  return q ? all.filter(i => i.id.toLowerCase().includes(q)) : all
})
const clientItems = computed(() => {
  const q = search.value.trim().toLowerCase()
  return q ? clients.items.value.filter(c => c.keyid.toLowerCase().includes(q) || c.issuer.toLowerCase().includes(q)) : clients.items.value
})

// ---------- dialogs ----------
const revokeIssuerTarget = ref<Issuer | null>(null)
const revokeClientTarget = ref<Client | null>(null)
const quotaIssuer = ref<Issuer | null>(null)
const quotaClient = ref<Client | null>(null)
const open = (r: { value: unknown }) => computed({ get: () => !!r.value, set: (v: boolean) => { if (!v) r.value = null } })
const revokeIssuerOpen = open(revokeIssuerTarget)
const revokeClientOpen = open(revokeClientTarget)
const quotaIssuerOpen = open(quotaIssuer)
const quotaClientOpen = open(quotaClient)

const revokeIssuer = useRevokeIssuer()
const revokeClient = useRevokeClient()
const issuerQuota = useUpdateIssuerQuota()
const clientQuota = useUpdateClientQuota()

function startRevokeIssuer(i: Issuer) {
  revokeIssuer.reset()
  revokeIssuerTarget.value = i
}
function startRevokeClient(c: Client) {
  revokeClient.reset()
  revokeClientTarget.value = c
}
function onRevokeIssuer(v: { password: string, note?: string }) {
  const i = revokeIssuerTarget.value!
  revokeIssuer.mutate({ id: i.id, body: v }, {
    onSuccess: () => {
      revokeIssuerTarget.value = null
      toast.success(`Bürge ${i.id} gesperrt`, { description: `${formatNumber(i.clients)} Clients zählen ab sofort nicht mehr.` })
    },
  })
}
function onRevokeClient(v: { password: string, note?: string }) {
  const c = revokeClientTarget.value!
  revokeClient.mutate({ keyid: c.keyid, body: v }, {
    onSuccess: () => {
      revokeClientTarget.value = null
      toast.success(`Client ${c.keyid} gesperrt`)
    },
  })
}
function onIssuerQuota(quota: number) {
  const i = quotaIssuer.value!
  issuerQuota.mutate({ id: i.id, quota }, { onSuccess: () => { quotaIssuer.value = null; toast.success('Kontingent gespeichert') } })
}
function onClientQuota(quota: number) {
  const c = quotaClient.value!
  clientQuota.mutate({ keyid: c.keyid, quota }, { onSuccess: () => { quotaClient.value = null; toast.success('Kontingent gespeichert') } })
}

const rejectRatio = (i: Issuer) => (i.signals_24h || i.rejected_24h ? (i.rejected_24h ?? 0) / Math.max(1, (i.signals_24h ?? 0) + (i.rejected_24h ?? 0)) : 0)

const issuerColumns: ColumnDef<Issuer, any>[] = [
  { accessorKey: 'id', header: 'Bürge', enableHiding: false, cell: ({ row }) => h('span', { class: 'font-mono font-medium' }, row.original.id) },
  {
    accessorKey: 'revoked',
    header: 'Status',
    cell: ({ row }) => (row.original.revoked
      ? h('div', {}, [h(StatusPill, { tone: 'neutral', size: 'sm' }, () => 'Gesperrt'), row.original.revoked_at ? h(RelativeTime, { value: row.original.revoked_at, class: 'block text-xs text-muted-foreground' }) : null])
      : h(StatusPill, { tone: 'success', size: 'sm' }, () => 'Aktiv')),
  },
  { id: 'usage', header: 'Kontingent (24 h)', accessorFn: i => i.used_24h, cell: ({ row }) => h(UsageBar, { used: row.original.used_24h, quota: row.original.quota_per_day }) },
  { accessorKey: 'clients', header: 'Clients', meta: { class: 'text-right tabular-nums' }, cell: ({ row }) => h(RouterLink, { to: { path: '/clients', query: { tab: 'clients', issuer: row.original.id } }, class: 'underline-offset-4 hover:underline' }, () => formatNumber(row.original.clients)) },
  { accessorKey: 'patterns_24h', header: 'Muster', meta: { class: 'text-right tabular-nums', hideOnMobile: true }, cell: ({ row }) => formatNumber(row.original.patterns_24h ?? 0) },
  {
    accessorKey: 'rejected_24h',
    header: 'Abgelehnt',
    meta: { class: 'text-right tabular-nums' },
    cell: ({ row }) => h('span', { class: rejectRatio(row.original) > 0.2 ? 'font-medium text-status-warning' : '' }, formatNumber(row.original.rejected_24h ?? 0)),
  },
  {
    id: 'actions',
    header: () => h('span', { class: 'sr-only' }, 'Aktionen'),
    enableSorting: false,
    enableHiding: false,
    cell: ({ row }) => (canEdit.value && !row.original.revoked
      ? h('div', { class: 'flex justify-end gap-1' }, [
          h(Button, { size: 'sm', variant: 'ghost', onClick: () => { issuerQuota.reset(); quotaIssuer.value = row.original } }, () => 'Kontingent …'),
          h(Button, { 'size': 'sm', 'variant': 'outline', 'onClick': () => startRevokeIssuer(row.original), 'aria-label': `Bürge ${row.original.id} sperren` }, () => 'Sperren …'),
        ])
      : null),
  },
]

const clientColumns: ColumnDef<Client, any>[] = [
  { accessorKey: 'keyid', header: 'Schlüssel', enableHiding: false, cell: ({ row }) => h('div', {}, [h('span', { class: 'font-mono text-xs font-medium' }, row.original.keyid), row.original.test_key ? h(StatusPill, { tone: 'info', size: 'sm', class: 'ml-2' }, () => 'Testschlüssel') : null]) },
  { accessorKey: 'issuer', header: 'Bürge', cell: ({ row }) => h('span', { class: 'font-mono text-xs' }, row.original.issuer) },
  { accessorKey: 'revoked', header: 'Status', cell: ({ row }) => (row.original.revoked ? h(StatusPill, { tone: 'neutral', size: 'sm' }, () => 'Gesperrt') : h(StatusPill, { tone: 'success', size: 'sm' }, () => 'Aktiv')) },
  { id: 'usage', header: 'Kontingent (24 h)', accessorFn: c => c.used_24h, cell: ({ row }) => h(UsageBar, { used: row.original.used_24h, quota: row.original.quota_per_day }) },
  { accessorKey: 'last_seen_bucket', header: 'Zuletzt', meta: { hideOnMobile: true }, cell: ({ row }) => (row.original.last_seen_bucket ? h(RelativeTime, { value: row.original.last_seen_bucket, class: 'text-xs' }) : '–') },
  {
    id: 'actions',
    header: () => h('span', { class: 'sr-only' }, 'Aktionen'),
    enableSorting: false,
    enableHiding: false,
    cell: ({ row }) => (canEdit.value && !row.original.revoked
      ? h('div', { class: 'flex justify-end gap-1' }, [
          h(Button, { size: 'sm', variant: 'ghost', onClick: () => { clientQuota.reset(); quotaClient.value = row.original } }, () => 'Kontingent …'),
          h(Button, { 'size': 'sm', 'variant': 'outline', 'onClick': () => startRevokeClient(row.original), 'aria-label': `Client ${row.original.keyid} sperren` }, () => 'Sperren …'),
        ])
      : null),
  },
]

useShortcuts([
  { keys: '/', description: 'Suche fokussieren', group: 'Clients & Bürgen', run: () => document.querySelector<HTMLInputElement>('[data-search] input[type=search]')?.focus() },
])
</script>

<template>
  <div class="space-y-4">
    <PageHeader title="Clients & Bürgen" description="Bürgen stehen für ihre Clients ein. Gezählt wird nach Bürgen; wer gesperrt ist, zählt nicht mehr." />
    <Tabs v-model="tab" class="space-y-4">
      <TabsList>
        <TabsTrigger value="issuers">
          Bürgen
        </TabsTrigger>
        <TabsTrigger value="clients">
          Clients
        </TabsTrigger>
      </TabsList>
      <div data-search>
        <FilterBar v-model:search="search" :search-placeholder="tab === 'issuers' ? 'Bürge suchen …' : 'Schlüssel oder Bürge …'" search-label="Suchen">
          <NativeSelect v-if="tab === 'clients'" v-model="issuerFilter" aria-label="Bürge" class="h-9 w-48">
            <NativeSelectOption value="">
              Alle Bürgen
            </NativeSelectOption>
            <NativeSelectOption v-for="i in issuers.data.value?.items ?? []" :key="i.id" :value="i.id">
              {{ i.id }}
            </NativeSelectOption>
          </NativeSelect>
        </FilterBar>
      </div>
      <TabsContent value="issuers">
        <QueryState :pending="issuers.isPending.value" :error="issuers.error.value" @retry="issuers.refetch()">
          <DataTable :columns="issuerColumns" :data="issuerItems" label="Bürgen" :get-row-id="(i: Issuer) => i.id" empty-title="Keine Bürgen gefunden" />
        </QueryState>
      </TabsContent>
      <TabsContent value="clients">
        <QueryState :pending="clients.isPending.value" :error="clients.error.value" @retry="clients.refetch()">
          <DataTable :columns="clientColumns" :data="clientItems" label="Clients" :get-row-id="(c: Client) => c.keyid" empty-title="Keine Clients gefunden" cursor :has-more="clients.hasNextPage.value" :loading-more="clients.isFetchingNextPage.value" @load-more="clients.fetchNextPage()" />
        </QueryState>
      </TabsContent>
    </Tabs>

    <PasswordConfirmDialog
      v-model:open="revokeIssuerOpen"
      :title="`Bürgen ${revokeIssuerTarget?.id} sperren?`"
      :consequences="[
        `Alle ${formatNumber(revokeIssuerTarget?.clients ?? 0)} Clients dieses Bürgen zählen ab sofort nicht mehr.`,
        'Neue Hinweise von ihnen werden abgelehnt (Grund: gesperrt).',
        'Muster, die nur durch diesen Bürgen getragen wurden, fallen unter die Schwellen.',
      ]"
      confirm-label="Bürgen sperren"
      destructive
      :pending="revokeIssuer.isPending.value"
      :error="revokeIssuer.error.value"
      @confirm="onRevokeIssuer"
    />
    <PasswordConfirmDialog
      v-model:open="revokeClientOpen"
      :title="`Client ${revokeClientTarget?.keyid} sperren?`"
      :consequences="['Hinweise mit diesem Schlüssel werden ab sofort abgelehnt.', 'Der Bürge und seine anderen Clients bleiben aktiv.']"
      confirm-label="Client sperren"
      destructive
      :pending="revokeClient.isPending.value"
      :error="revokeClient.error.value"
      @confirm="onRevokeClient"
    />
    <QuotaDialog
      v-model:open="quotaIssuerOpen"
      :title="`Kontingent für ${quotaIssuer?.id}`"
      :current="quotaIssuer?.quota_per_day ?? 0"
      :used="quotaIssuer?.used_24h"
      :pending="issuerQuota.isPending.value"
      :error="issuerQuota.error.value"
      @confirm="onIssuerQuota"
    />
    <QuotaDialog
      v-model:open="quotaClientOpen"
      :title="`Kontingent für ${quotaClient?.keyid}`"
      :current="quotaClient?.quota_per_day ?? 0"
      :used="quotaClient?.used_24h"
      :pending="clientQuota.isPending.value"
      :error="clientQuota.error.value"
      @confirm="onClientQuota"
    />
  </div>
</template>
