<script setup lang="ts">
import type { ColumnDef, FilterChip } from '@schild/ui'
import type { PatternStatus, PatternSummary } from '@/api/types'
import type { PatternFilter } from '@/api/queries'
import {
  Button,
  DataTable,
  FilterBar,
  flagEmoji,
  formatNumber,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  RelativeTime,
  StatusPill,
} from '@schild/ui'
import { Waypoints } from '@lucide/vue'
import { computed, h, ref, watch } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { usePatterns } from '@/api/queries'
import QueryState from '@/components/QueryState.vue'
import ShareMeter from '@/components/ShareMeter.vue'
import { useRouteQuery, useRouteQueryNumber } from '@/composables/useRouteQuery'
import { useShortcuts } from '@/composables/useShortcuts'
import { dominatedOpenPatterns, MAX_ISSUER_SHARE, MIN_TIP_ISSUERS } from '@/lib/evidence'
import { PATTERN_STATUS } from '@/lib/labels'

const router = useRouter()
const q = useRouteQuery('q')
const status = useRouteQuery('status')
const minIssuers = useRouteQueryNumber('min_issuers')
const country = useRouteQuery('country')
const asn = useRouteQueryNumber('asn')
const sort = useRouteQuery('sort')
const minIssuersText = useRouteQuery('min_issuers')

// Search is typed locally and written to the URL after a short pause.
const search = ref(q.value)
let t: ReturnType<typeof setTimeout> | undefined
watch(search, (v) => {
  clearTimeout(t)
  t = setTimeout(() => (q.value = v.trim()), 250)
})
watch(q, (v) => {
  if (v !== search.value.trim()) search.value = v
})

const filter = computed<PatternFilter>(() => ({
  q: q.value || undefined,
  status: (status.value || undefined) as PatternStatus | undefined,
  min_issuers: minIssuers.value,
  country: country.value || undefined,
  asn: asn.value,
  sort: (sort.value || 'last_seen') as PatternFilter['sort'],
}))
const patterns = usePatterns(filter)
const items = computed(() => patterns.items.value)

const chips = computed<FilterChip[]>(() => [
  ...(status.value ? [{ key: 'status', label: 'Status', value: PATTERN_STATUS[status.value as PatternStatus]?.text ?? status.value }] : []),
  ...(minIssuers.value !== undefined ? [{ key: 'min_issuers', label: 'Bürgen ab', value: String(minIssuers.value) }] : []),
  ...(country.value ? [{ key: 'country', label: 'Land', value: country.value }] : []),
  ...(asn.value !== undefined ? [{ key: 'asn', label: 'ASN', value: `AS${asn.value}` }] : []),
])
function removeChip(c: FilterChip) {
  if (c.key === 'status') status.value = ''
  if (c.key === 'min_issuers') minIssuers.value = undefined
  if (c.key === 'country') country.value = ''
  if (c.key === 'asn') asn.value = undefined
}
function clearAll() {
  void router.replace({ query: sort.value ? { sort: sort.value } : {} })
  search.value = ''
}

// Quick answers for the on-call question "which new pattern has the most issuers, and is one issuer dominant?"
const topNew = computed(() => [...items.value].filter(p => p.status === 'new').sort((a, b) => b.issuers - a.issuers)[0])
const dominated = computed(() => dominatedOpenPatterns(items.value).length)

const columns: ColumnDef<PatternSummary, any>[] = [
  {
    accessorKey: 'action_sig',
    header: 'Muster',
    meta: { label: 'Muster' },
    enableHiding: false,
    cell: ({ row }) => h('div', { class: 'min-w-0' }, [
      h(RouterLink, { to: `/signals/${row.original.pattern_id}`, class: 'font-mono text-[13px] font-medium underline-offset-4 hover:underline' }, () => row.original.action_sig),
      h('div', { class: 'truncate text-xs text-muted-foreground' }, row.original.categories?.join(', ') ?? ''),
    ]),
  },
  { accessorKey: 'status', header: 'Status', meta: { label: 'Status' }, cell: ({ row }) => h(StatusPill, { tone: PATTERN_STATUS[row.original.status].tone, size: 'sm' }, () => PATTERN_STATUS[row.original.status].text) },
  {
    accessorKey: 'issuers',
    header: 'Bürgen',
    meta: { label: 'Bürgen', class: 'text-right tabular-nums' },
    cell: ({ row }) => h('div', { class: 'text-right' }, [
      h('span', { class: row.original.issuers < MIN_TIP_ISSUERS ? 'text-muted-foreground' : 'font-medium' }, formatNumber(row.original.issuers)),
      row.original.clients !== undefined ? h('div', { class: 'text-xs text-muted-foreground' }, `${formatNumber(row.original.clients)} Clients`) : null,
    ]),
  },
  { accessorKey: 'max_issuer_share', header: 'Größter Anteil', meta: { label: 'Größter Anteil eines Bürgen' }, cell: ({ row }) => h(ShareMeter, { share: row.original.max_issuer_share, compact: true }) },
  { accessorKey: 'signals', header: 'Signale', meta: { label: 'Signale', class: 'text-right tabular-nums' }, cell: ({ row }) => formatNumber(row.original.signals) },
  {
    id: 'origin',
    header: 'Herkunft',
    enableSorting: false,
    meta: { label: 'Herkunft (Land, ASN)', hideOnMobile: true },
    cell: ({ row }) => h('div', { class: 'text-xs' }, [
      h('div', { title: row.original.top_countries?.map(c => c.key).join(', ') }, row.original.top_countries?.slice(0, 3).map(c => `${flagEmoji(String(c.key))} ${c.key}`).join('  ') || '–'),
      h('div', { class: 'text-muted-foreground' }, row.original.top_asns?.slice(0, 2).map(a => `AS${a.key}`).join(', ') ?? ''),
    ]),
  },
  { accessorKey: 'first_seen', header: 'Zuerst', meta: { label: 'Zuerst gesehen', hideOnMobile: true }, sortingFn: 'datetime', cell: ({ row }) => h(RelativeTime, { value: row.original.first_seen, class: 'text-xs whitespace-nowrap' }) },
  { accessorKey: 'last_seen', header: 'Zuletzt', meta: { label: 'Zuletzt gesehen' }, sortingFn: 'datetime', cell: ({ row }) => h(RelativeTime, { value: row.original.last_seen, class: 'text-xs whitespace-nowrap' }) },
  {
    accessorKey: 'proposal_id',
    header: 'Vorschlag',
    enableSorting: false,
    meta: { label: 'Vorschlag', hideOnMobile: true },
    cell: ({ row }) => (row.original.proposal_id ? h(RouterLink, { to: `/proposals/${row.original.proposal_id}`, class: 'text-xs underline-offset-4 hover:underline' }, () => row.original.proposal_id) : h('span', { class: 'text-xs text-muted-foreground' }, '–')),
  },
]

useShortcuts([
  { keys: '/', description: 'Suche fokussieren', group: 'Signale & Muster', run: () => document.querySelector<HTMLInputElement>('[data-search] input[type=search]')?.focus() },
])
</script>

<template>
  <div class="space-y-4">
    <PageHeader title="Signale & Muster" description="Hinweise der Clients, gruppiert nach Aktionssignatur. Gezählt wird nach Bürgen, nicht nach Clients." />

    <div v-if="items.length" class="flex flex-wrap gap-2 text-sm" data-testid="pattern-summary">
      <RouterLink v-if="topNew" :to="`/signals/${topNew.pattern_id}`" class="inline-flex flex-wrap gap-x-1.5 rounded-md border bg-card px-3 py-1.5 hover:bg-accent" data-testid="top-new">
        <span class="text-muted-foreground">Neu mit den meisten Bürgen:</span>
        <span class="font-mono font-medium">{{ topNew.action_sig }}</span>
        <span class="tabular-nums">({{ topNew.issuers }} Bürgen)</span>
      </RouterLink>
      <span class="inline-flex gap-x-1.5 rounded-md border bg-card px-3 py-1.5">
        <span class="text-muted-foreground" title="Nur offene Muster (neu oder beobachtet). Vorgeschlagene und veröffentlichte stützen sich auf eigene Belege der Labs.">Offen, ein Bürge über {{ Math.round(MAX_ISSUER_SHARE * 100) }} %:</span>
        <span class="font-medium tabular-nums" :class="dominated ? 'text-status-warning' : ''">{{ dominated }} Muster</span>
      </span>
    </div>

    <div data-search>
      <FilterBar v-model:search="search" :chips="chips" search-placeholder="Signatur oder Kategorie …" search-label="Muster suchen" @remove="removeChip" @clear="clearAll">
        <NativeSelect v-model="status" aria-label="Status" class="h-9 w-40">
          <NativeSelectOption value="">
            Alle Status
          </NativeSelectOption>
          <NativeSelectOption v-for="(l, k) in PATTERN_STATUS" :key="k" :value="k">
            {{ l.text }}
          </NativeSelectOption>
        </NativeSelect>
        <NativeSelect v-model="minIssuersText" aria-label="Mindestens Bürgen" class="h-9 w-40">
          <NativeSelectOption value="">
            Alle Bürgen
          </NativeSelectOption>
          <NativeSelectOption v-for="n in [2, 3, 5, 8]" :key="n" :value="String(n)">
            ab {{ n }} Bürgen
          </NativeSelectOption>
        </NativeSelect>
        <template #end>
          <NativeSelect v-model="sort" aria-label="Sortierung" class="h-9 w-44">
            <NativeSelectOption value="">
              Zuletzt gesehen
            </NativeSelectOption>
            <NativeSelectOption value="first_seen">
              Zuerst gesehen
            </NativeSelectOption>
            <NativeSelectOption value="issuers">
              Meiste Bürgen
            </NativeSelectOption>
            <NativeSelectOption value="signals">
              Meiste Signale
            </NativeSelectOption>
          </NativeSelect>
        </template>
      </FilterBar>
    </div>

    <QueryState :pending="patterns.isPending.value" :error="patterns.error.value" :retrying="patterns.isFetching.value" @retry="patterns.refetch()">
      <DataTable
        :columns="columns"
        :data="items"
        label="Muster"
        :loading="patterns.isFetching.value && !items.length"
        :get-row-id="(p: PatternSummary) => p.pattern_id"
        cursor :has-more="patterns.hasNextPage.value" :loading-more="patterns.isFetchingNextPage.value" empty-title="Keine Muster für diese Auswahl"
        empty-description="Lockere die Filter oder warte auf neue Hinweise."
        @load-more="patterns.fetchNextPage()"
        @row-click="(p: PatternSummary) => router.push(`/signals/${p.pattern_id}`)"
      >
        <template #empty>
          <div class="flex flex-col items-center gap-2 py-8 text-center">
            <Waypoints class="size-6 text-muted-foreground" aria-hidden="true" />
            <p class="font-medium">
              Keine Muster für diese Auswahl
            </p>
            <Button v-if="chips.length || q" variant="outline" size="sm" @click="clearAll">
              Filter entfernen
            </Button>
          </div>
        </template>
      </DataTable>
    </QueryState>
  </div>
</template>
