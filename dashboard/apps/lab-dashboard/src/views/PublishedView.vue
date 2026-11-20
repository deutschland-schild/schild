<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { AssembleBundle, Bundle } from '@/api/types'
import { Button, DataTable, PageHeader, RelativeTime, StatusPill, toast } from '@schild/ui'
import { PackagePlus, Undo2 } from '@lucide/vue'
import { computed, h, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { useAssembleBundle, useBundles, useHealth, useProposals, useSettings, useWithdrawals } from '@/api/queries'
import AssembleDialog from '@/components/bundle/AssembleDialog.vue'
import RelayCoverage from '@/components/bundle/RelayCoverage.vue'
import QueryState from '@/components/QueryState.vue'
import SignatureProgress from '@/components/SignatureProgress.vue'
import { useSession } from '@/composables/useSession'
import { BUNDLE_STATUS } from '@/lib/labels'

const router = useRouter()
const { canEdit } = useSession()
const bundles = useBundles()
const approved = useProposals('approved')
const settings = useSettings()
const assemble = useAssembleBundle()
const open = ref(false)
const items = computed(() => bundles.items.value)
const current = computed(() => items.value.find(b => b.status === 'published'))
const collecting = computed(() => items.value.filter(b => b.status === 'collecting'))

// Withdrawals live on their own sub-page; the header shows how many wait for this lab's co-signature.
const withdrawals = useWithdrawals()
const health = useHealth()
const needsCosign = computed(() => {
  const lab = health.data.value?.lab
  return lab ? withdrawals.items.value.filter(w => w.status === 'collecting' && !w.signatures.some(s => s.lab === lab)).length : 0
})

const summary = (b: Bundle) => {
  const added = b.rules.filter(r => r.change === 'added').length
  const changed = b.rules.filter(r => r.change === 'changed').length
  return [`${b.rules.length} Regeln`, added && `${added} neu`, changed && `${changed} geändert`].filter(Boolean).join(' · ')
}

const columns: ColumnDef<Bundle, any>[] = [
  { accessorKey: 'version', header: 'Version', meta: { label: 'Version' }, cell: ({ row }) => h(RouterLink, { to: `/published/${row.original.version}`, class: 'font-mono font-medium underline-offset-4 hover:underline' }, () => `v${row.original.version}`) },
  { accessorKey: 'status', header: 'Status', meta: { label: 'Status' }, cell: ({ row }) => h(StatusPill, { tone: BUNDLE_STATUS[row.original.status].tone, size: 'sm' }, () => BUNDLE_STATUS[row.original.status].text) },
  { id: 'rules', header: 'Inhalt', enableSorting: false, meta: { label: 'Inhalt' }, cell: ({ row }) => h('span', { class: 'text-sm' }, summary(row.original)) },
  { id: 'signatures', header: 'Signaturen', enableSorting: false, meta: { label: 'Signaturen' }, cell: ({ row }) => h(SignatureProgress, { signatures: row.original.signatures, threshold: row.original.threshold, compact: true, collecting: row.original.status === 'collecting' }) },
  { accessorKey: 'issued_at', header: 'Erstellt', meta: { label: 'Erstellt', hideOnMobile: true }, cell: ({ row }) => h(RelativeTime, { value: row.original.issued_at, class: 'text-xs' }) },
  { accessorKey: 'expires', header: 'Läuft ab', meta: { label: 'Läuft ab', hideOnMobile: true }, cell: ({ row }) => h(RelativeTime, { value: row.original.expires, class: 'text-xs' }) },
]

function onAssemble(body: AssembleBundle) {
  assemble.mutate(body, {
    onSuccess: (b) => {
      open.value = false
      toast.success(`Bündel v${b.version} signiert`, { description: `Wartet auf ${b.threshold} Betreiber. Danach verteilen die Relays es.` })
      void router.push(`/published/${b.version}`)
    },
  })
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader title="Veröffentlicht" description="Bündel mit Netzregeln, ihre Signaturen und ihre Verteilung.">
      <template #actions>
        <Button as-child variant="outline" data-testid="open-withdrawals">
          <RouterLink to="/published/withdrawals">
            <Undo2 aria-hidden="true" /> Netzregeln zurückziehen
            <StatusPill v-if="needsCosign" tone="info" size="sm">
              {{ needsCosign }} zum Mitzeichnen
            </StatusPill>
          </RouterLink>
        </Button>
        <Button v-if="canEdit" @click="() => { assemble.reset(); open = true }">
          <PackagePlus aria-hidden="true" /> Neues Bündel …
        </Button>
      </template>
    </PageHeader>

    <QueryState :pending="bundles.isPending.value" :error="bundles.error.value" :retrying="bundles.isFetching.value" @retry="bundles.refetch()">
      <div class="grid gap-4 lg:grid-cols-2">
        <div class="rounded-xl border bg-card p-4">
          <h2 class="font-bold">
            Aktuell im Feed
          </h2>
          <template v-if="current">
            <p class="mt-1 text-2xl font-bold">
              <RouterLink :to="`/published/${current.version}`" class="underline-offset-4 hover:underline">
                Version {{ current.version }}
              </RouterLink>
            </p>
            <p class="text-sm text-muted-foreground">
              {{ summary(current) }} · läuft ab <RelativeTime :value="current.expires" />
            </p>
            <div class="mt-3">
              <SignatureProgress :signatures="current.signatures" :threshold="current.threshold" :collecting="false" />
            </div>
          </template>
          <p v-else class="mt-1 text-sm text-muted-foreground">
            Noch kein Bündel veröffentlicht.
          </p>
        </div>
        <div class="rounded-xl border bg-card p-4">
          <h2 class="mb-2 font-bold">
            Verteilung über Relays
          </h2>
          <RelayCoverage what="den aktuellen Stand" />
        </div>
      </div>

      <div v-if="collecting.length" class="rounded-xl border border-status-warning/40 bg-status-warning-subtle/40 p-4">
        <h2 class="font-bold">
          Sammelt Signaturen
        </h2>
        <ul class="mt-2 space-y-3">
          <li v-for="b in collecting" :key="b.version" class="flex flex-wrap items-center gap-3">
            <RouterLink :to="`/published/${b.version}`" class="font-mono font-medium underline-offset-4 hover:underline">
              v{{ b.version }}
            </RouterLink>
            <SignatureProgress :signatures="b.signatures" :threshold="b.threshold" compact />
          </li>
        </ul>
      </div>

      <DataTable
        :columns="columns"
        :data="items"
        label="Bündel"
        :get-row-id="(b: Bundle) => String(b.version)"
        empty-title="Noch keine Bündel"
        cursor
        :has-more="bundles.hasNextPage.value" :loading-more="bundles.isFetchingNextPage.value" @row-click="(b: Bundle) => router.push(`/published/${b.version}`)" @load-more="bundles.fetchNextPage()"
      />
    </QueryState>

    <AssembleDialog
      v-model:open="open"
      :approved="approved.items.value"
      :current="current"
      :default-hours="settings.data.value?.publish.bundle_validity_hours ?? 168"
      :pending="assemble.isPending.value"
      :error="assemble.error.value"
      @confirm="onAssemble"
    />
  </div>
</template>
