<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { LogEntry, LogKind } from '@/api/types'
import type { EntryCheck, RootCheck, SequenceIssue } from '@/lib/logverify'
import { Button, Card, DataTable, formatNumber, PageHeader, RelativeTime, Tabs, TabsList, TabsTrigger } from '@schild/ui'
import { ShieldCheck } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, h, reactive, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { fetchLogEntry, fetchWholeLog, keys, useLog } from '@/api/queries'
import CheckBadge from '@/components/CheckBadge.vue'
import LogEntryDetail from '@/components/LogEntryDetail.vue'
import QueryState from '@/components/QueryState.vue'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { checkEntry, checkRoot, checkSequence, signedHead } from '@/lib/logverify'
import { LOG_KIND } from '@/lib/labels'

const qc = useQueryClient()
const kindQuery = useRouteQuery('kind')
const kind = computed({ get: () => kindQuery.value || 'all', set: v => (kindQuery.value = v === 'all' ? '' : v) })
const log = useLog(() => (kind.value === 'all' ? undefined : kind.value as LogKind))
const items = computed(() => log.items.value)
const head = computed(() => log.head.value)

const results = reactive(new Map<number, EntryCheck>())
const issues = ref<SequenceIssue[] | null>(null)
const running = ref(false)
const done = ref(0)
/** RFC 6962 root checks (contracts v0.1): the head of the API and the head the newest checkpoint signs. */
const rootCheck = ref<{ head: RootCheck, size: number, signed: { result: RootCheck, size: number, index: number } | null } | null>(null)
const rootError = ref(false)
watch(kind, () => {
  results.clear()
  issues.value = null
})

async function verifyRoot() {
  rootCheck.value = null
  rootError.value = false
  try {
    const whole = await fetchWholeLog()
    const sh = signedHead(whole.items)
    rootCheck.value = {
      head: await checkRoot(whole.items, whole.head.size, whole.head.root),
      size: whole.head.size,
      signed: sh ? { result: await checkRoot(whole.items, sh.size, sh.root), size: sh.size, index: sh.index } : null,
    }
  }
  catch {
    rootError.value = true
  }
}

async function verify() {
  running.value = true
  done.value = 0
  results.clear()
  const list = [...items.value]
  issues.value = kind.value === 'all' ? checkSequence(list, head.value?.size) : []
  let next = 0
  const worker = async () => {
    while (next < list.length) {
      const e = list[next++]!
      try {
        const full = await qc.fetchQuery({ queryKey: keys.logEntry(e.index), queryFn: () => fetchLogEntry(e.index), staleTime: 60_000 })
        results.set(e.index, full.digest === e.digest ? await checkEntry(full) : 'mismatch')
      }
      catch {
        results.set(e.index, 'error')
      }
      done.value++
    }
  }
  await Promise.all([worker(), worker(), worker(), worker(), verifyRoot()])
  running.value = false
}

const counts = computed(() => {
  const c = { ok: 0, mismatch: 0, no_envelope: 0, error: 0 }
  for (const r of results.values()) c[r]++
  return c
})
const verified = computed(() => results.size > 0 && !running.value)

const refLink = (e: LogEntry) => {
  if (e.kind === 'proposal') return `/proposals/${e.ref}`
  if (e.kind === 'bundle') return `/published/${e.ref}`
  if (e.kind === 'withdrawal') return '/published/withdrawals'
  return undefined
}
const columns: ColumnDef<LogEntry, any>[] = [
  { accessorKey: 'index', header: 'Index', meta: { class: 'tabular-nums w-20' }, cell: ({ row }) => h('span', { class: 'font-mono' }, String(row.original.index)) },
  { accessorKey: 'time', header: 'Zeit', cell: ({ row }) => h(RelativeTime, { value: row.original.time, class: 'text-xs whitespace-nowrap' }) },
  { accessorKey: 'kind', header: 'Art', cell: ({ row }) => LOG_KIND[row.original.kind] },
  {
    accessorKey: 'ref',
    header: 'Bezug',
    cell: ({ row }) => {
      const to = refLink(row.original)
      return to ? h(RouterLink, { to, class: 'font-mono text-xs underline-offset-4 hover:underline' }, () => row.original.ref) : h('span', { class: 'font-mono text-xs' }, row.original.ref)
    },
  },
  { accessorKey: 'summary', header: 'Zusammenfassung', enableSorting: false, meta: { hideOnMobile: true }, cell: ({ row }) => h('span', { class: 'text-sm' }, row.original.summary) },
  { accessorKey: 'digest', header: 'Prüfsumme', enableSorting: false, meta: { hideOnMobile: true }, cell: ({ row }) => h('span', { class: 'font-mono text-xs', title: row.original.digest }, `${row.original.digest.slice(0, 19)}…`) },
  { id: 'check', header: 'Prüfung', enableSorting: false, cell: ({ row }) => h(CheckBadge, { result: results.get(row.original.index) }) },
]
</script>

<template>
  <div class="space-y-4">
    <PageHeader title="Öffentliches Log" description="Alles, was dieses Lab vorschlägt, veröffentlicht oder zurückzieht, in fester Reihenfolge. Ohne Daten von Clients.">
      <template #actions>
        <Button :disabled="running || !items.length" data-testid="verify-log" @click="verify">
          <ShieldCheck aria-hidden="true" /> {{ running ? `Prüfe … ${done} von ${items.length}` : 'Geladene Einträge prüfen' }}
        </Button>
      </template>
    </PageHeader>

    <Card class="grid gap-3 p-4 text-sm sm:grid-cols-[auto_1fr]">
      <div>
        <p class="text-muted-foreground">
          Kopf
        </p>
        <p class="text-lg font-bold tabular-nums">
          {{ head ? `${formatNumber(head.size)} Einträge` : '–' }}
        </p>
      </div>
      <div class="min-w-0">
        <p class="text-muted-foreground">
          Wurzel
        </p>
        <p class="font-mono text-xs break-all">
          {{ head?.root ?? '–' }}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          Merkle-Baum nach RFC 6962 über alle Einträge. „Prüfen“ rechnet die Wurzel im Browser nach und vergleicht sie mit dem Kopf und mit der Wurzel, die der neueste Checkpoint signiert.
        </p>
      </div>
    </Card>

    <div v-if="verified" class="rounded-md border p-3 text-sm" :class="counts.mismatch || issues?.length || rootCheck?.head === 'mismatch' || rootCheck?.signed?.result === 'mismatch' ? 'border-status-danger/40 bg-status-danger-subtle' : 'bg-card'" role="status" data-testid="verify-result">
      <p class="font-medium">
        {{ results.size }} Einträge geprüft:
        {{ counts.ok }} passen<template v-if="counts.mismatch">, <span class="text-status-danger">{{ counts.mismatch }} weichen ab</span></template><template v-if="counts.no_envelope">, {{ counts.no_envelope }} ohne Umschlag</template><template v-if="counts.error">, {{ counts.error }} nicht abrufbar</template>.
      </p>
      <p v-if="rootCheck" data-testid="root-check" :class="rootCheck.head === 'mismatch' || rootCheck.signed?.result === 'mismatch' ? 'text-status-danger' : 'text-muted-foreground'">
        <template v-if="rootCheck.head === 'ok'">
          Wurzel nachgerechnet: passt zum Kopf ({{ formatNumber(rootCheck.size) }} Einträge).
        </template>
        <template v-else-if="rootCheck.head === 'mismatch'">
          Wurzel nachgerechnet: weicht vom Kopf ab.
        </template>
        <template v-else>
          Wurzel nicht nachrechenbar: Das Log ließ sich nicht vollständig laden.
        </template>
        <template v-if="rootCheck.signed?.result === 'ok'">
          Der signierte Checkpoint (Eintrag {{ rootCheck.signed.index }}) bestätigt die ersten {{ formatNumber(rootCheck.signed.size) }} Einträge.
        </template>
        <template v-else-if="rootCheck.signed?.result === 'mismatch'">
          Der signierte Checkpoint (Eintrag {{ rootCheck.signed.index }}) nennt eine andere Wurzel.
        </template>
      </p>
      <p v-else-if="rootError" class="text-muted-foreground">
        Wurzel nicht nachrechenbar: Das Log ließ sich nicht laden.
      </p>
      <p v-if="kind !== 'all'" class="text-muted-foreground">
        Reihenfolge wird nur in der Ansicht „Alle“ geprüft.
      </p>
      <p v-else-if="!issues?.length" class="text-muted-foreground">
        Reihenfolge lückenlos, neuester Eintrag passt zum Kopf.
      </p>
      <ul v-else class="mt-1 list-disc pl-5 text-status-danger">
        <li v-for="i in issues" :key="`${i.index}-${i.text}`">
          {{ i.text }}
        </li>
      </ul>
    </div>

    <Tabs v-model="kind">
      <TabsList class="flex h-auto flex-wrap justify-start">
        <TabsTrigger value="all">
          Alle
        </TabsTrigger>
        <TabsTrigger v-for="(label, k) in LOG_KIND" :key="k" :value="k">
          {{ label }}
        </TabsTrigger>
      </TabsList>
    </Tabs>

    <QueryState :pending="log.isPending.value" :error="log.error.value" :retrying="log.isFetching.value" @retry="log.refetch()">
      <DataTable
        :columns="columns"
        :data="items"
        label="Log-Einträge"
        :get-row-id="(e: LogEntry) => String(e.index)"
        :detail-title="(e: LogEntry) => `Eintrag ${e.index}`"
        empty-title="Keine Einträge"
        cursor :has-more="log.hasNextPage.value" :loading-more="log.isFetchingNextPage.value" @load-more="log.fetchNextPage()"
      >
        <template #detail="{ row }">
          <LogEntryDetail :entry="row" />
        </template>
      </DataTable>
    </QueryState>
  </div>
</template>
