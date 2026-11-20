<script setup lang="ts">
import type { ColumnDef } from '@schild/ui'
import type { RequestFilters, RequestRecord } from '@/api/requests'
import { DataTable, ErrorState, formatMs, NativeSelect, NativeSelectOption } from '@schild/ui'
import { X } from '@lucide/vue'
import { computed, h } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useBlocks } from '@/api/blocks'
import { errorMessage } from '@/api/client'
import { isRingBusy, listWindow, useRequestList } from '@/api/requests'
import IpActions from '@/components/blocks/IpActions.vue'
import EstimateNote from '@/components/monitoring/EstimateNote.vue'
import { BROWSERS, keyLabel, OS_FAMILIES } from '@/lib/monitoring'
import {
  CONTEXT_PARAM,
  LIST_ENDS,
  LIST_WINDOWS,
  listEndLabel,
  listEndOf,
  listWindowOf,
  OUTCOME_FILTER_LABELS,
  pathText,
  REQUEST_OUTCOME_KEYS,
  REQUESTS_COPY,
  RING_SECONDS,
  VERIFICATION,
  VERIFICATION_KEYS,
} from '@/lib/requests'
import { filterChip } from '@/lib/websites'
import RequestOutcomeBadge from './RequestOutcomeBadge.vue'
import VerificationBadge from './VerificationBadge.vue'

/**
 * Anfragen (queryRequests, MVP-22): single requests of the request ring, valid ones and alerts in one list,
 * newest first, in a window of at most 6 hours within the last 48 hours. The page's filter chips apply
 * where the API has the dimension (page, rule, country, status, bot category); outcome, bot, verification
 * are set here. A row with an event opens its Kontext; another row filters by that address.
 * An address filter shows the whole ring on every website of this server (D49), so its window has no controls.
 * A part of the User-Agent shows the whole ring of this website (D50). Both are page filters (D64), typed in
 * RequestSearch above the tabs. State in the URL: window, until, outcome, bot, verification, visitor.
 */
const props = defineProps<{ site: string, filters: string[] }>()
/** Addresses blocked now: their row offers no second block (review 2026-11-19). */
const blocksQ = useBlocks()
const blockedNow = computed(() => new Set((blocksQ.data.value?.items ?? []).map(b => b.client)))

const route = useRoute()
const router = useRouter()
function set(patch: Record<string, string | undefined>) {
  const query = { ...route.query }
  for (const [k, v] of Object.entries(patch)) {
    if (!v) delete query[k]
    else query[k] = v
  }
  void router.replace({ query })
}
const str = (k: string) => typeof route.query[k] === 'string' ? route.query[k] as string : ''
/** Sets the page filter of a dimension (ip, user_agent), replacing its value. */
function setFilter(dim: 'ip' | 'user_agent', value: string) {
  const rest = props.filters.filter(f => !f.startsWith(`${dim}:`))
  void router.replace({ query: { ...route.query, filter: [...rest, `${dim}:${value}`].slice(-4) } })
}
const filterValue = (dim: string) => props.filters.find(f => f.startsWith(`${dim}:`))?.slice(dim.length + 1) ?? ''

const windowKey = computed({ get: () => listWindowOf(route.query.window), set: v => set({ window: v === '1h' ? undefined : v }) })
const endHours = computed({ get: () => String(listEndOf(route.query.until)), set: v => set({ until: v === '0' ? undefined : v }) })
const outcome = computed({ get: () => str('outcome'), set: v => set({ outcome: v || undefined }) })
const verification = computed({ get: () => str('verification'), set: v => set({ verification: v || undefined }) })
const bot = computed(() => /^[a-z0-9][a-z0-9-]{1,47}$/.test(str('bot')) ? str('bot') : '')
const visitor = computed(() => /^v1-[0-9a-f]{16}$/.test(str('visitor')) ? str('visitor') : '')
const ip = computed(() => filterValue('ip'))
const ua = computed(() => filterValue('user_agent'))
const wholeRing = computed(() => !!ip.value || !!ua.value)

/** Page chips the list can apply (queryRequests has these dimensions), and the ones it cannot. */
const LIST_DIMENSIONS = ['path', 'rule', 'country', 'status_class', 'bot_category'] as const
const fromChips = computed(() => {
  const out: Record<string, string> = {}
  const skipped: string[] = []
  for (const f of props.filters) {
    const i = f.indexOf(':')
    const dim = f.slice(0, i)
    if ((LIST_DIMENSIONS as readonly string[]).includes(dim)) out[dim] = f.slice(i + 1)
    else if (dim !== 'ip' && dim !== 'user_agent') {
      const c = filterChip(f)
      if (c) skipped.push(`${c.label} ${c.value}`)
    }
  }
  return { out, skipped }
})
const listFilters = computed<RequestFilters>(() => ({
  ...fromChips.value.out,
  ...(outcome.value ? { outcome: outcome.value as RequestFilters['outcome'] } : {}),
  ...(verification.value ? { verification: verification.value as RequestFilters['verification'] } : {}),
  ...(bot.value ? { bot: bot.value } : {}),
  ...(visitor.value ? { visitor: visitor.value } : {}),
  ...(ip.value ? { ip: ip.value } : {}),
  ...(ua.value ? { user_agent: ua.value } : {}),
}))
const win = computed(() => wholeRing.value ? listWindow(RING_SECONDS, 0) : listWindow(LIST_WINDOWS[windowKey.value].seconds, Number(endHours.value)))
const list = useRequestList(() => ({ site: ip.value ? '' : props.site, ...win.value, filters: listFilters.value }))
const pages = computed(() => list.data.value?.pages ?? [])
const rows = computed(() => pages.value.flatMap(p => p.items))
const sampleRate = computed(() => Math.min(1, ...pages.value.map(p => p.sample_rate)))
const capped = computed(() => pages.value.at(-1)?.scan_capped === true)

const hms = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const dm = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit' })
const today = new Date().toDateString()
const timeText = (t: string) => {
  const d = new Date(t)
  return d.toDateString() === today ? hms.format(d) : `${dm.format(d)} ${hms.format(d)}`
}

/** The address opens everything of this client; a record from before D49 only has its visitor key. */
function clientAddress(r: RequestRecord) {
  if (!r.ip) return h('p', { class: 'truncate font-mono text-muted-foreground', title: 'Pseudonymer Besucherschlüssel, gilt nur für diesen Tag' }, r.visitor.slice(0, 11))
  return h('button', { 'type': 'button', 'class': 'block min-h-6 max-w-full truncate text-left font-mono text-muted-foreground underline underline-offset-4 hover:text-foreground', 'title': 'Alle Anfragen dieser Adresse', 'data-testid': 'list-ip-link', 'onClick': () => setFilter('ip', r.ip!) }, r.ip)
}

/** Foreign text, a Vue text node. A click shows every request with this User-Agent. */
function userAgentLine(r: RequestRecord) {
  if (!r.user_agent) return null
  return h('button', { 'type': 'button', 'class': 'block max-w-full truncate text-left font-mono text-[11px] text-muted-foreground hover:text-foreground', 'title': r.user_agent, 'data-testid': 'list-ua-link', 'onClick': () => setFilter('user_agent', r.user_agent!.slice(0, 512)) }, r.user_agent)
}

const columns: ColumnDef<RequestRecord, unknown>[] = [
  {
    id: 'time',
    header: 'Zeit',
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Zeit', class: 'w-28 whitespace-nowrap' },
    cell: ({ row }) => h('span', { class: 'font-mono text-xs tabular-nums text-muted-foreground' }, timeText(row.original.t)),
  },
  {
    id: 'outcome',
    header: 'Ergebnis',
    enableSorting: false,
    meta: { label: 'Ergebnis', class: 'w-32' },
    cell: ({ row }) => h(RequestOutcomeBadge, { outcome: row.original.outcome }),
  },
  {
    id: 'request',
    header: 'Anfrage',
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Anfrage', class: 'min-w-48 max-w-[22rem]' },
    cell: ({ row }) => {
      const r = row.original
      return h('div', { class: 'min-w-0' }, [
        h('p', { class: 'truncate' }, [
          h('span', { class: 'mr-1.5 rounded bg-muted px-1 py-0.5 font-mono text-[11px] font-medium' }, r.method),
          h('span', { class: 'font-mono text-[13px]', title: r.path }, pathText(r.path)),
        ]),
        h('p', { class: 'text-xs text-muted-foreground' }, [
          `${r.status} · ${formatMs(r.duration_ms)}`,
          r.rules?.length ? ` · Regel ${r.rules.join(', ')}` : '',
          ip.value ? ` · ${r.site}` : '',
          r.event_id ? ' · Kontext' : '',
        ].join('')),
      ])
    },
  },
  {
    id: 'origin',
    header: 'Herkunft',
    enableSorting: false,
    meta: { label: 'Herkunft', hideOnMobile: true, class: 'w-40' },
    cell: ({ row }) => h('div', { class: 'min-w-0 text-xs' }, [
      h('p', { class: 'truncate' }, keyLabel('country', row.original.country)),
      h('p', { class: 'truncate text-muted-foreground' }, keyLabel('referrer', row.original.referrer)),
    ]),
  },
  {
    id: 'client',
    header: 'Client',
    enableSorting: false,
    meta: { label: 'Client', hideOnMobile: true, class: 'w-48' },
    cell: ({ row }) => {
      const r = row.original
      if (r.bot) {
        return h('div', { class: 'min-w-0 text-xs' }, [
          h('p', { class: 'truncate font-medium' }, r.bot),
          r.verification ? h(VerificationBadge, { state: r.verification, name: r.bot }) : null,
          clientAddress(r),
          userAgentLine(r),
        ])
      }
      return h('div', { class: 'min-w-0 text-xs' }, [
        h('p', { class: 'truncate' }, r.browser !== 'none' ? `${BROWSERS[r.browser]} · ${OS_FAMILIES[r.os]}` : keyLabel('bot_category', r.bot_category)),
        clientAddress(r),
        userAgentLine(r),
      ])
    },
  },
  {
    // Block the address or put it on Eigene IPs from the row (initiator 2026-11-18); a record from before D49
    // has no address.
    id: 'actions',
    header: () => h('span', { class: 'sr-only' }, 'Aktionen'),
    enableSorting: false,
    enableHiding: false,
    meta: { label: 'Aktionen', class: 'w-10 text-right' },
    cell: ({ row }) => {
      const r = row.original
      if (!r.ip) return null
      return h(IpActions, { ip: r.ip, netClass: r.net_class, reason: r.event_id ? `Ereignis ${r.event_id}: Anfrage an ${r.path}` : `Anfrage an ${r.site}${r.path}`, canBlock: !blockedNow.value.has(r.ip), testid: 'row' })
    },
  },
]

/** A row with an event opens its Kontext; any other row shows that visitor's requests. */
function openRow(r: RequestRecord) {
  if (r.event_id) {
    void router.push({ query: { ...route.query, [CONTEXT_PARAM]: r.event_id } })
    return
  }
  if (r.ip) setFilter('ip', r.ip)
  else set({ visitor: r.visitor })
}
const emptyDescription = computed(() => REQUESTS_COPY.noRequests)
</script>

<template>
  <div class="space-y-3" data-testid="request-list">
    <div class="flex flex-wrap items-center gap-2">
      <NativeSelect v-if="!wholeRing" v-model="windowKey" aria-label="Zeitfenster" class="w-auto" data-testid="list-window">
        <NativeSelectOption v-for="(w, k) in LIST_WINDOWS" :key="k" :value="k">
          {{ w.label }}
        </NativeSelectOption>
      </NativeSelect>
      <NativeSelect v-if="!wholeRing" v-model="endHours" aria-label="Ende des Zeitfensters" class="w-auto" data-testid="list-end">
        <NativeSelectOption v-for="e in LIST_ENDS" :key="e" :value="String(e)">
          {{ listEndLabel(e) }}
        </NativeSelectOption>
      </NativeSelect>
      <NativeSelect v-model="outcome" aria-label="Ergebnis" class="w-auto" data-testid="list-outcome">
        <NativeSelectOption value="">
          Alle Ergebnisse
        </NativeSelectOption>
        <NativeSelectOption v-for="o in REQUEST_OUTCOME_KEYS" :key="o" :value="o">
          {{ OUTCOME_FILTER_LABELS[o] }}
        </NativeSelectOption>
      </NativeSelect>
      <NativeSelect v-model="verification" aria-label="Prüfung der Bots" class="w-auto" data-testid="list-verification">
        <NativeSelectOption value="">
          Alle Bots und Besucher
        </NativeSelectOption>
        <NativeSelectOption v-for="v in VERIFICATION_KEYS" :key="v" :value="v">
          Bots: {{ v === 'mismatch' ? 'gibt sich als jemand anderes aus' : VERIFICATION[v].label }}
        </NativeSelectOption>
      </NativeSelect>
      <span v-if="bot" class="inline-flex items-center gap-1 rounded-full border bg-card py-0.5 pr-1 pl-2.5 text-sm" data-testid="list-bot">
        <span class="text-muted-foreground">Bot:</span> {{ bot }}
        <button type="button" class="rounded-full p-0.5 hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring" :aria-label="`Filter Bot ${bot} entfernen`" @click="set({ bot: undefined })"><X class="size-3.5" aria-hidden="true" /></button>
      </span>
      <span v-if="visitor" class="inline-flex items-center gap-1 rounded-full border bg-card py-0.5 pr-1 pl-2.5 text-sm" data-testid="list-visitor">
        <span class="text-muted-foreground">Besucher:</span> <span class="font-mono text-xs">{{ visitor.slice(0, 11) }}</span>
        <button type="button" class="rounded-full p-0.5 hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring" aria-label="Filter Besucher entfernen" @click="set({ visitor: undefined })"><X class="size-3.5" aria-hidden="true" /></button>
      </span>
      <EstimateNote v-if="sampleRate < 1" :text="REQUESTS_COPY.sampled" data-testid="list-sampled" />
    </div>
    <p v-if="fromChips.skipped.length" class="text-xs text-muted-foreground" data-testid="list-skipped">
      {{ REQUESTS_COPY.filterNotInList(fromChips.skipped.join(', ')) }}
    </p>
    <p v-if="ip" class="text-xs text-muted-foreground" data-testid="list-ip-scope">
      {{ REQUESTS_COPY.ipScope }}
    </p>
    <p v-if="ua && !ip" class="text-xs text-muted-foreground" data-testid="list-ua-scope">
      {{ REQUESTS_COPY.uaScope }}
    </p>
    <p v-if="visitor" class="text-xs text-muted-foreground">
      Der Besucherschlüssel ist pseudonym und gilt nur für einen Tag. Am nächsten Tag hat derselbe Besucher einen anderen.
    </p>
    <ErrorState v-if="list.isError.value && !rows.length" title="Die Anfragen lassen sich gerade nicht laden" :description="isRingBusy(list.error.value) ? REQUESTS_COPY.busy : errorMessage(list.error.value)" :retrying="list.isFetching.value" @retry="list.refetch()" />
    <DataTable
      v-else
      cursor
      :has-more="list.hasNextPage.value"
      :loading-more="list.isFetchingNextPage.value"
      :columns="columns"
      :data="rows"
      label="Anfragen"
      :loading="list.isPending.value"
      :get-row-id="(r: RequestRecord, i: number) => `${r.t}-${r.visitor}-${i}`"
      max-height="64vh"
      hide-column-menu
      empty-title="Keine Anfragen"
      :empty-description="emptyDescription"
      @row-click="openRow"
      @load-more="list.fetchNextPage()"
    />
    <p v-if="capped" class="text-xs text-muted-foreground" data-testid="list-capped">
      {{ REQUESTS_COPY.scanCapped }}
    </p>
    <p class="text-xs text-muted-foreground">
      Zeilen mit „Kontext“ zeigen, was derselbe Besucher davor und danach getan hat. Ein Klick auf eine andere Zeile oder die IP zeigt alle Anfragen dieser Adresse.
    </p>
  </div>
</template>
