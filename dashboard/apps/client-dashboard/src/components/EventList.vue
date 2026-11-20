<script setup lang="ts">
import type { ColumnDef, FilterChip } from '@schild/ui'
import type { UrlField } from '@/composables/useEventFilters'
import type { EventSummary, Outcome } from '@/api/types'
import {
  Button,
  DataTable,
  ErrorState,
  FilterBar,
  formatNumber,
  Input,
  IpAddress,
  Label,
  LiveIndicator,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  Popover,
  PopoverContent,
  PopoverTrigger,
  RelativeTime,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@schild/ui'
import { Pause, Play, Radio, RefreshCw, SlidersHorizontal } from '@lucide/vue'
import { computed, h, nextTick, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useBlocks } from '@/api/blocks'
import { errorMessage } from '@/api/client'
import { useEvents } from '@/api/queries'
import { useWebsites } from '@/api/websites'
import IpActions from '@/components/blocks/IpActions.vue'
import CountryAsn from '@/components/CountryAsn.vue'
import EventDetailPanel from '@/components/EventDetailPanel.vue'
import OutcomePill from '@/components/OutcomePill.vue'
import SectionHeader from '@/components/SectionHeader.vue'
import SheetStepper from '@/components/SheetStepper.vue'
import { liveMatches, TIME_RANGES, useEventFilters } from '@/composables/useEventFilters'
import { useLiveEvents } from '@/composables/useLiveEvents'
import { useShortcuts } from '@/composables/useShortcuts'
import { explainRule, isEvaluationRule } from '@/lib/explain'
import { isCidr, isIP } from '@/lib/ip'
import { websiteName } from '@/lib/websites'
import { EVENT_TYPE_OPTIONS, eventHeadline, isRequestEvent, OUTCOME_ORDER, OUTCOMES } from '@/lib/labels'

/**
 * The filterable event list with live view and detail sheet (?event=<id>). On /events it is the page
 * itself and covers every website; on the Ereignisse page of a website (D68) it is a section with the
 * website fixed. Filters, live and the open event live in the URL either way.
 */
const props = defineProps<{
  /** Website the list is fixed to (its Ereignisse page); without it every website. */
  site?: string
}>()

const route = useRoute()
/** Addresses blocked now: their row offers no second block (review 2026-11-19). */
const blocksQ = useBlocks()
const blockedNow = computed(() => new Set((blocksQ.data.value?.items ?? []).map(b => b.client)))
const { filters, apiQuery, streamQuery, chips, update, clear, refresh } = useEventFilters(props.site === undefined ? undefined : () => props.site ?? '')

// ---------------------------------------------------------------- list
const list = useEvents(apiQuery)
const pages = computed(() => list.data.value?.pages ?? [])
const total = computed(() => pages.value[0]?.total_estimate)

// ---------------------------------------------------------------- live
const live = useLiveEvents(streamQuery)
const liveRows = computed(() => live.active.value ? live.events.value.filter(e => liveMatches(e, filters.value)) : [])
const rows = computed<EventSummary[]>(() => {
  const seen = new Set<string>()
  const out: EventSummary[] = []
  for (const e of [...liveRows.value, ...pages.value.flatMap(p => p.items)]) {
    if (seen.has(e.id)) continue
    seen.add(e.id)
    out.push(e)
  }
  return out
})
watch(() => route.query.live, (v) => {
  if (v === '1' && !live.active.value) live.start()
  if (v !== '1' && live.active.value) live.stop()
}, { immediate: true })
function toggleLive() {
  update({ live: live.active.value ? undefined : '1' })
}
function togglePause() {
  if (live.state.value === 'paused') live.resume()
  else live.pause()
}

// ---------------------------------------------------------------- search and filters
const search = ref(filters.value.q ?? '')
let searchTimer: ReturnType<typeof setTimeout> | undefined
watch(search, (v) => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => update({ q: v.trim() || undefined }), 350)
})
watch(() => filters.value.q, (v) => {
  if ((v ?? '') !== search.value.trim()) search.value = v ?? ''
})

const timeModel = computed({
  get: () => filters.value.time as string,
  set: v => update({ time: String(v) }),
})
const outcomeModel = computed({
  get: () => (filters.value.outcome ?? '') as string,
  set: v => update({ outcome: String(v) || undefined }),
})
const chipModel = computed<FilterChip[]>({
  get: () => chips.value,
  set: () => {},
})
function onRemoveChip(chip: FilterChip) {
  update({ [chip.key]: undefined })
}

const moreOpen = ref(false)
const draft = reactive({ ip: '', country: '', asn: '', path: '', rule: '', session: '', type: '' })
const draftErrors = computed(() => ({
  ip: draft.ip && !isIP(draft.ip.trim()) && !isCidr(draft.ip.trim()) ? 'IP-Adresse oder Bereich, z. B. 203.0.113.0/24' : null,
  country: draft.country && !/^[a-z]{2}$/i.test(draft.country.trim()) ? 'Zwei Buchstaben, z. B. DE oder NL' : null,
  asn: draft.asn && !/^(as)?\d+$/i.test(draft.asn.trim()) ? 'Eine Zahl, z. B. 64500' : null,
}))
watch(moreOpen, (v) => {
  if (!v) return
  draft.ip = filters.value.ip ?? ''
  draft.country = filters.value.country ?? ''
  draft.asn = filters.value.asn ?? ''
  draft.path = filters.value.path ?? ''
  draft.rule = filters.value.rule ?? ''
  draft.session = filters.value.session ?? ''
  draft.type = filters.value.type ?? ''
})
function applyMore() {
  if (Object.values(draftErrors.value).some(Boolean)) return
  update({
    ip: draft.ip.trim() || undefined,
    country: draft.country.trim().toUpperCase() || undefined,
    asn: draft.asn.trim().replace(/^as/i, '') || undefined,
    path: draft.path.trim() || undefined,
    rule: draft.rule.trim() || undefined,
    session: draft.session.trim() || undefined,
    type: draft.type || undefined,
  })
  moreOpen.value = false
}
const moreCount = computed(() => ['ip', 'country', 'asn', 'path', 'rule', 'session', 'type'].filter(k => filters.value[k as UrlField]).length)

function quickFilter(field: UrlField, value: string) {
  // A click on an address means this client: other filters would hide part of it.
  update({ ...(field === 'ip' ? { outcome: undefined, path: undefined, rule: undefined, country: undefined, asn: undefined } : {}), [field]: value, event: undefined })
}

// ---------------------------------------------------------------- detail sheet (deep link ?event=<id>)
const detailId = computed(() => typeof route.query.event === 'string' ? route.query.event : null)
const detailOpen = computed({
  get: () => !!detailId.value,
  set: (v) => {
    if (!v) update({ event: undefined })
  },
})
function openEvent(e: EventSummary | string) {
  update({ event: typeof e === 'string' ? e : e.id })
}

// ---------------------------------------------------------------- table
const websites = useWebsites()
/** The website of an event by name: its `site`, else the one its Host belongs to, else the Host as sent. */
function eventWebsite(e: EventSummary): { name: string, known: boolean } | null {
  const all = websites.data.value?.websites ?? []
  const w = all.find(x => x.id === e.site) ?? (e.host ? all.find(x => x.hosts.includes(e.host!)) : undefined)
  if (w) return { name: websiteName(w, w.id), known: true }
  const raw = e.site ?? e.host
  return raw ? { name: raw, known: false } : null
}
const websiteColumn: ColumnDef<EventSummary, unknown> = {
  id: 'website',
  header: 'Website',
  enableSorting: false,
  meta: { label: 'Website', hideOnMobile: true, class: 'max-w-44' },
  cell: ({ row }) => {
    const w = eventWebsite(row.original)
    if (!w) return h('span', { class: 'text-muted-foreground' }, '–')
    return h('span', { 'class': ['block max-w-40 truncate', w.known ? '' : 'font-mono text-[13px] text-muted-foreground'], 'title': w.name, 'data-testid': 'event-website' }, w.name)
  },
}
const allColumns: ColumnDef<EventSummary, unknown>[] = [
  {
    id: 'time',
    header: 'Zeit',
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Zeit', hideOnMobile: true, class: 'w-28 whitespace-nowrap' },
    cell: ({ row }) => h(RelativeTime, { value: row.original.time, class: 'tabular-nums text-muted-foreground' }),
  },
  {
    id: 'outcome',
    header: 'Ergebnis',
    enableSorting: false,
    meta: { label: 'Ergebnis', class: 'w-32' },
    cell: ({ row }) => row.original.outcome
      ? h(OutcomePill, { outcome: row.original.outcome, reason: row.original.would_block_reason })
      : h('span', { class: 'text-xs text-muted-foreground' }, 'Hinweis'),
  },
  {
    id: 'request',
    header: 'Anfrage',
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Anfrage', class: 'min-w-40 max-w-[18rem]' },
    cell: ({ row }) => {
      const e = row.original
      if (!isRequestEvent(e)) return h('span', { class: 'font-medium' }, eventHeadline(e))
      return h('div', { class: 'min-w-0' }, [
        h('p', { class: 'truncate' }, [
          h('span', { class: 'mr-1.5 rounded bg-muted px-1 py-0.5 font-mono text-[11px] font-medium' }, e.method),
          h('span', { class: 'font-mono text-[13px]' }, e.path),
        ]),
        e.incident ? h('p', { class: 'text-xs text-muted-foreground' }, `Vorfall ${e.incident}`) : null,
        // Small screens hide the time and IP columns: show both under the request instead.
        h('p', { class: 'truncate text-xs text-muted-foreground md:hidden' }, [
          props.site === undefined && eventWebsite(e) ? `${eventWebsite(e)!.name} · ` : null,
          e.ip ? h('span', { class: 'font-mono' }, e.ip) : null,
          e.ip ? ' · ' : null,
          h(RelativeTime, { value: e.time }),
        ]),
      ])
    },
  },
  {
    id: 'ip',
    header: 'IP',
    enableSorting: false,
    meta: { label: 'IP', hideOnMobile: true, class: 'max-w-52' },
    cell: ({ row }) => row.original.ip
      ? h(IpAddress, { ip: row.original.ip, country: row.original.geo?.country, asn: row.original.geo?.asn, asnOrg: row.original.geo?.as_org })
      : h('span', { class: 'text-muted-foreground' }, '–'),
  },
  {
    id: 'origin',
    header: 'Herkunft',
    enableSorting: false,
    meta: { label: 'Herkunft', hideOnMobile: true, class: 'max-w-56' },
    // Fixed width with ellipsis: the ASN line must not run into the next column.
    cell: ({ row }) => h(CountryAsn, { geo: row.original.geo, class: 'w-48 max-w-48' }),
  },
  {
    id: 'rules',
    header: 'Grund',
    enableSorting: false,
    meta: { label: 'Grund', hideOnMobile: true, class: 'max-w-64' },
    cell: ({ row }) => {
      const r = (row.original.rules ?? []).filter(x => !isEvaluationRule(x))
      if (!r.length) return h('span', { class: 'text-muted-foreground' }, '–')
      return h('span', { class: 'block max-w-48 truncate', title: r.join(', ') }, [
        explainRule(r[0]!).title,
        r.length > 1 ? h('span', { class: 'text-muted-foreground' }, ` +${r.length - 1}`) : null,
      ])
    },
  },
  {
    id: 'score',
    header: 'Score',
    enableSorting: false,
    meta: { label: 'Score', hideOnMobile: true, class: 'w-16 text-right tabular-nums' },
    cell: ({ row }) => row.original.score ?? '–',
  },
  {
    // Block the address or put it on Eigene IPs without opening the event (initiator 2026-11-18).
    id: 'actions',
    header: () => h('span', { class: 'sr-only' }, 'Aktionen'),
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Aktionen', class: 'w-10 text-right' },
    cell: ({ row }) => {
      const e = row.original
      if (!e.ip || !isRequestEvent(e)) return null
      const rule = (e.rules ?? []).find(x => !isEvaluationRule(x))
      // An own address (it came through because of Eigene IPs) is neither blocked nor added again.
      const own = e.would_block_reason === 'allowlist'
      return h(IpActions, { ip: e.ip, netClass: e.geo?.net_class, reason: `Ereignis ${e.id}: ${rule ? explainRule(rule).title : `Anfrage an ${e.path}`}`, allowLabel: e.incident ? `Vorfall ${e.incident}` : '', canBlock: !own && !blockedNow.value.has(e.ip), canAllow: !own, testid: 'row' })
    },
  },
]
// For every website the row says which one; on the page of one website that is known.
const columns = props.site === undefined ? [...allColumns.slice(0, 2), websiteColumn, ...allColumns.slice(2)] : allColumns


// The score is in the detail sheet; as a column it pushes the table wider than 1440 px. "Spalten" brings it back.
const columnVisibility = ref<Record<string, boolean>>({ score: false })

// ---------------------------------------------------------------- keyboard
const searchWrap = ref<HTMLElement | null>(null)
function focusSearch() {
  searchWrap.value?.querySelector<HTMLInputElement>('input[type="search"]')?.focus()
}
onMounted(() => {
  if (route.query.focus === 'search') {
    void nextTick(focusSearch)
    update({ focus: undefined })
  }
})
useShortcuts([
  { keys: '/', label: 'Suche fokussieren', group: 'Ereignisse', run: focusSearch },
  { keys: 'l', label: 'Live-Ansicht ein/aus', group: 'Ereignisse', run: toggleLive },
  { keys: 'p', label: 'Live-Ansicht pausieren/fortsetzen', group: 'Ereignisse', run: () => live.active.value && togglePause() },
  { keys: 'r', label: 'Neu laden', group: 'Ereignisse', run: () => refresh() },
])

const emptyText = computed(() => chips.value.length || filters.value.q
  ? { title: 'Keine Ereignisse für diese Filter', description: 'Entferne einen Filter oder wähle einen längeren Zeitraum.' }
  : { title: 'Noch keine Ereignisse', description: 'Sobald Anfragen an deine Website kommen, siehst du sie hier, mit IP, Herkunft und dem Grund, falls Schild etwas auffällt.' })
const intro = computed(() => props.site
  ? { title: 'Alle Ereignisse dieser Website', description: 'Alles, was Schild zu dieser Website notiert hat, mit Filtern und Live-Ansicht. IP-Adressen siehst nur du, hier lokal.' }
  : { title: 'Ereignisse', description: 'Alles, was Schild auf deinem Server notiert hat, für alle Websites. IP-Adressen siehst nur du, hier lokal.' })
</script>

<template>
  <div>
    <component
      :is="site ? SectionHeader : PageHeader"
      :title="intro.title"
      :description="intro.description"
      data-testid="events-header"
    >
      <template #actions>
        <LiveIndicator v-if="live.active.value" :state="live.state.value" data-testid="live-state" />
        <Button v-if="live.active.value" variant="outline" size="sm" :aria-label="live.state.value === 'paused' ? 'Live-Ansicht fortsetzen' : 'Live-Ansicht pausieren'" data-testid="live-pause" @click="togglePause">
          <Play v-if="live.state.value === 'paused'" aria-hidden="true" />
          <Pause v-else aria-hidden="true" />
          {{ live.state.value === 'paused' ? 'Fortsetzen' : 'Pausieren' }}
        </Button>
        <Button :variant="live.active.value ? 'secondary' : 'outline'" size="sm" :aria-pressed="live.active.value" data-testid="live-toggle" @click="toggleLive">
          <Radio aria-hidden="true" />
          {{ live.active.value ? 'Live beenden' : 'Live' }}
        </Button>
        <Button variant="ghost" size="sm" aria-label="Neu laden" :disabled="list.isFetching.value" @click="refresh()">
          <RefreshCw :class="list.isFetching.value ? 'motion-safe:animate-spin' : ''" aria-hidden="true" />
        </Button>
      </template>
    </component>

    <ErrorState
      v-if="list.isError.value && !rows.length"
      title="Die Ereignisse lassen sich gerade nicht laden"
      :description="errorMessage(list.error.value)"
      :retrying="list.isFetching.value"
      @retry="list.refetch()"
    />

    <DataTable
      v-else
      v-model:column-visibility="columnVisibility"
      cursor
      :has-more="list.hasNextPage.value"
      :loading-more="list.isFetchingNextPage.value"
      :columns="columns"
      :data="rows"
      label="Ereignisse"
      :loading="list.isPending.value"
      :get-row-id="(r: EventSummary) => r.id"
      max-height="68vh"
      :empty-title="emptyText.title"
      :empty-description="emptyText.description"
      @row-click="openEvent"
      @load-more="list.fetchNextPage()"
    >
      <template #toolbar>
        <div ref="searchWrap">
          <FilterBar
            v-model:search="search"
            :chips="chipModel"
            search-placeholder="Pfad, IP, Vorfall, Programm …"
            search-label="Ereignisse durchsuchen"
            @remove="onRemoveChip"
            @clear="clear"
          >
            <NativeSelect v-model="timeModel" aria-label="Zeitraum" data-testid="filter-time">
              <NativeSelectOption v-for="t in TIME_RANGES" :key="t.value" :value="t.value">
                {{ t.label }}
              </NativeSelectOption>
            </NativeSelect>
            <NativeSelect v-model="outcomeModel" aria-label="Ergebnis" data-testid="filter-outcome">
              <NativeSelectOption value="">
                Alle Ergebnisse
              </NativeSelectOption>
              <NativeSelectOption v-for="o in OUTCOME_ORDER" :key="o" :value="o">
                {{ OUTCOMES[o as Outcome].label }}
              </NativeSelectOption>
            </NativeSelect>
            <Popover v-model:open="moreOpen">
              <PopoverTrigger as-child>
                <Button variant="outline" size="sm" class="h-9" data-testid="filter-more">
                  <SlidersHorizontal aria-hidden="true" />
                  Weitere Filter<span v-if="moreCount" class="ml-0.5 rounded-full bg-primary px-1.5 text-xs text-primary-foreground">{{ moreCount }}</span>
                </Button>
              </PopoverTrigger>
              <PopoverContent align="start" class="w-80">
                <form class="grid gap-3" novalidate @submit.prevent="applyMore">
                  <div class="grid gap-1.5">
                    <Label for="f-ip">IP oder Bereich</Label>
                    <Input id="f-ip" v-model="draft.ip" placeholder="203.0.113.42 oder 203.0.113.0/24" class="font-mono" :aria-invalid="!!draftErrors.ip" />
                    <p v-if="draftErrors.ip" class="text-xs text-destructive">
                      {{ draftErrors.ip }}
                    </p>
                  </div>
                  <div class="grid grid-cols-2 gap-3">
                    <div class="grid gap-1.5">
                      <Label for="f-country">Land</Label>
                      <Input id="f-country" v-model="draft.country" placeholder="NL" maxlength="2" class="uppercase" :aria-invalid="!!draftErrors.country" />
                      <p v-if="draftErrors.country" class="text-xs text-destructive">
                        {{ draftErrors.country }}
                      </p>
                    </div>
                    <div class="grid gap-1.5">
                      <Label for="f-asn">Netz (ASN)</Label>
                      <Input id="f-asn" v-model="draft.asn" placeholder="64500" inputmode="numeric" :aria-invalid="!!draftErrors.asn" />
                      <p v-if="draftErrors.asn" class="text-xs text-destructive">
                        {{ draftErrors.asn }}
                      </p>
                    </div>
                  </div>
                  <div class="grid gap-1.5">
                    <Label for="f-path">Pfad beginnt mit</Label>
                    <Input id="f-path" v-model="draft.path" placeholder="/wp-login.php" class="font-mono" />
                  </div>
                  <div class="grid grid-cols-2 gap-3">
                    <div class="grid gap-1.5">
                      <Label for="f-rule">Regel</Label>
                      <Input id="f-rule" v-model="draft.rule" placeholder="930120" class="font-mono" />
                    </div>
                    <div class="grid gap-1.5">
                      <Label for="f-session">Sitzung</Label>
                      <Input id="f-session" v-model="draft.session" placeholder="s_…" class="font-mono" />
                    </div>
                  </div>
                  <div class="grid gap-1.5">
                    <Label for="f-type">Art</Label>
                    <NativeSelect id="f-type" v-model="draft.type" class="w-full">
                      <NativeSelectOption value="">
                        Alle Arten
                      </NativeSelectOption>
                      <NativeSelectOption v-for="t in EVENT_TYPE_OPTIONS" :key="t.value" :value="t.value">
                        {{ t.label }}
                      </NativeSelectOption>
                    </NativeSelect>
                  </div>
                  <div class="flex justify-end gap-2 pt-1">
                    <Button type="button" variant="ghost" size="sm" @click="moreOpen = false">
                      Abbrechen
                    </Button>
                    <Button type="submit" size="sm">
                      Anwenden
                    </Button>
                  </div>
                </form>
              </PopoverContent>
            </Popover>
          </FilterBar>
        </div>
        <p class="mt-2 text-xs text-muted-foreground" aria-live="polite">
          <template v-if="total !== undefined">
            {{ formatNumber(total) }} {{ total === 1 ? 'Ereignis' : 'Ereignisse' }} gefunden<template v-if="list.hasNextPage.value">, {{ formatNumber(rows.length) }} geladen</template>.
          </template>
          <template v-if="live.active.value && live.state.value === 'live'">
            Neue Ereignisse erscheinen oben.
          </template>
          <template v-else-if="live.active.value && live.state.value === 'paused'">
            Pausiert. Beim Fortsetzen holt Schild nach, was in der Zwischenzeit passiert ist.
          </template>
          <template v-else-if="live.active.value && live.state.value === 'offline'">
            Verbindung unterbrochen. Schild versucht es gleich wieder.
          </template>
        </p>
      </template>
    </DataTable>


    <Sheet v-model:open="detailOpen">
      <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-2xl xl:max-w-3xl" data-testid="event-sheet">
        <SheetHeader class="border-b">
          <SheetTitle>Ereignis</SheetTitle>
          <SheetDescription>Alle Details, die Schild lokal gespeichert hat.</SheetDescription>
          <SheetStepper :ids="rows.map(x => x.id)" :current="detailId" @select="openEvent" />
        </SheetHeader>
        <div class="p-4">
          <EventDetailPanel v-if="detailId" :id="detailId" @filter="quickFilter" @open="openEvent" />
        </div>
      </SheetContent>
    </Sheet>
  </div>
</template>
