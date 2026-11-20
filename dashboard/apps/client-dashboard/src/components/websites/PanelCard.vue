<script setup lang="ts">
import type { BreakdownDimension, TopEntry } from '@/api/monitoring'
import type { WebsiteRangeKey } from '@/api/websites'
import { Button, Card, CardContent, CardHeader, CardTitle, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { ArrowUpRight, Filter } from '@lucide/vue'
import { computed, ref } from 'vue'
import { isFilterUnavailable, useWebsiteBreakdown, WEBSITE_RANGES } from '@/api/websites'
import { explainRule } from '@/lib/explain'
import { COPY, eventsLinkFor, keyLabel } from '@/lib/monitoring'
import { websitePath } from '@/lib/nav'
import { gapCopy, WEBSITE_COPY } from '@/lib/websites'

/**
 * One panel of the Zugriffe tabs (D36, Plausible-style) with optional tabs. A click on a row filters
 * the whole page by that value; the arrow opens the matching events (with addresses). Columns:
 * traffic (requests, share), origin (requests, gestoppt, erkannt, share stopped), attacks.
 */
export interface PanelTab {
  key: string
  label: string
  by: BreakdownDimension
  columns: 'traffic' | 'origin' | 'rules' | 'pages'
  top?: number
  /** Keep only these keys (e.g. KI-Assistenten among the referrers). */
  only?: (key: string) => boolean
  /** Sort the rows by attacks instead of requests. */
  byAttacks?: boolean
}

const props = defineProps<{
  title: string
  tabs: PanelTab[]
  site: string
  range: WebsiteRangeKey
  filters: string[]
  /** Filters of the page, for the row highlight (the panel may show unfiltered numbers). */
  activeFilters?: string[]
  /** Offer "Zeitraum verkürzen" (only when the request ring runs). */
  offerRange?: boolean
  observe?: boolean
  testid?: string
  description?: string
}>()
const emit = defineEmits<{ filter: [expr: string], range: [key: WebsiteRangeKey] }>()

const tabKey = ref(props.tabs[0]!.key)
const tab = computed(() => props.tabs.find(t => t.key === tabKey.value) ?? props.tabs[0]!)
const q = useWebsiteBreakdown(() => ({ site: props.site, range: props.range, filters: props.filters, by: tab.value.by, top: tab.value.top ?? (tab.value.only ? 16 : 8) }))
const b = computed(() => q.data.value)
const unavailable = computed(() => isFilterUnavailable(q.error.value))
const total = computed(() => b.value?.total.requests ?? 0)
const isRule = computed(() => tab.value.by === 'rule')

const rows = computed(() => {
  let items: TopEntry[] = [...(b.value?.items ?? [])]
  if (tab.value.only) items = items.filter(i => tab.value.only!(i.key))
  const bad = (i: TopEntry) => i.stopped + i.would_block
  if (tab.value.byAttacks) items = items.filter(i => (i.detections ?? bad(i)) > 0).sort((a, z) => (z.detections ?? bad(z)) - (a.detections ?? bad(a)))
  const max = Math.max(1, ...items.map(i => tab.value.byAttacks ? (i.detections ?? bad(i)) : i.requests))
  return items.slice(0, 8).map(i => ({
    ...i,
    name: isRule.value ? `${explainRule(i.key).title}` : keyLabel(tab.value.by, i.key, i.label),
    sub: isRule.value ? `Regel ${i.key}` : '',
    share: total.value ? i.requests / total.value : null,
    stoppedShare: i.requests ? i.stopped / i.requests : null,
    bar: ((tab.value.byAttacks ? (i.detections ?? bad(i)) : i.requests) / max) * 100,
    expr: `${tab.value.by}:${i.key}`,
    active: (props.activeFilters ?? props.filters).includes(`${tab.value.by}:${i.key}`),
    events: eventsLinkFor(tab.value.by, i.key, { key: '6h', label: '', seconds: WEBSITE_RANGES[props.range].seconds, resolution: '1m', stepS: 60, refetchMs: 0 }),
    mono: tab.value.by === 'path' || tab.value.by === 'ip' || tab.value.by === 'user_agent',
  }))
})
/** The row's events on the Ereignisse page of this website (D68). */
const eventsLink = (to: string | null) => to ? to.replace(/^\/events/, websitePath(props.site, 'events')) : null
const countHead = computed(() => isRule.value ? 'Erkennungen' : tab.value.columns === 'pages' ? 'Erkennungen' : 'Anfragen')
</script>

<template>
  <Card class="min-w-0 gap-3 py-4" :data-testid="testid">
    <CardHeader class="px-4">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <CardTitle class="text-base">
          {{ title }}
        </CardTitle>
        <div v-if="tabs.length > 1" role="tablist" :aria-label="title" class="flex flex-wrap gap-1 text-xs">
          <button
            v-for="t in tabs"
            :key="t.key"
            type="button"
            role="tab"
            :aria-selected="tabKey === t.key"
            :class="['rounded-md px-2 py-1 font-medium transition-colors focus-visible:outline-2 focus-visible:outline-ring', tabKey === t.key ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground']"
            :data-tab="t.key"
            @click="tabKey = t.key"
          >
            {{ t.label }}
          </button>
        </div>
      </div>
      <p v-if="description" class="text-xs text-muted-foreground">
        {{ description }}
      </p>
    </CardHeader>
    <CardContent class="px-4">
      <div v-if="unavailable" class="rounded-lg border border-dashed p-3 text-sm" data-testid="filter-unavailable">
        <p class="text-muted-foreground">
          {{ WEBSITE_COPY.filterUnavailableShort }}
        </p>
        <Button v-if="offerRange" variant="link" size="sm" class="mt-1 h-auto p-0" @click="emit('range', '48h')">
          {{ WEBSITE_COPY.to48h }}
        </Button>
      </div>
      <div v-else-if="q.isPending.value" class="space-y-2">
        <Skeleton v-for="i in 5" :key="i" class="h-7 w-full" />
      </div>
      <p v-else-if="!rows.length" class="py-2 text-sm text-muted-foreground">
        {{ COPY.empty }}
      </p>
      <table v-else class="w-full table-fixed text-sm tabular-nums">
        <caption class="sr-only">
          {{ title }}: {{ tab.label }}. {{ WEBSITE_COPY.filterHint }}
        </caption>
        <thead class="text-xs text-muted-foreground">
          <tr>
            <th scope="col" class="pb-1.5 text-left font-medium">
              {{ tab.label }}
            </th>
            <th scope="col" class="w-20 pb-1.5 text-right font-medium">
              {{ countHead }}
            </th>
            <template v-if="tab.columns === 'origin'">
              <th scope="col" class="w-20 pb-1.5 text-right font-medium">
                Gesperrt
              </th>
              <th scope="col" class="hidden w-20 pb-1.5 text-right font-medium sm:table-cell">
                Erkannt
              </th>
              <th scope="col" class="w-20 pb-1.5 text-right font-medium" title="Anteil der Anfragen, die Schild gesperrt hat">
                % gesperrt
              </th>
            </template>
            <th v-else-if="tab.columns === 'traffic'" scope="col" class="w-16 pb-1.5 text-right font-medium">
              Anteil
            </th>
            <th v-else scope="col" class="w-20 pb-1.5 text-right font-medium">
              {{ observe ? 'Erkannt' : 'Gesperrt' }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.key" :class="['group', r.active ? 'font-medium' : '']" :data-row="r.key">
            <th scope="row" class="relative py-0.5 pr-2 text-left font-normal">
              <span class="pointer-events-none absolute inset-y-0.5 left-0 rounded-sm" :style="{ width: `${r.bar}%`, background: 'var(--tone-wash)', opacity: 0.7 }" aria-hidden="true" />
              <span class="relative flex min-w-0 items-center gap-1">
                <button
                  type="button"
                  class="min-w-0 flex-1 truncate rounded-sm px-1.5 py-1 text-left hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                  :class="r.mono ? 'font-mono text-xs' : ''"
                  :title="`${r.name}${r.sub ? ` (${r.sub})` : ''} – als Filter setzen`"
                  :aria-pressed="r.active"
                  @click="emit('filter', r.expr)"
                >
                  <Filter v-if="r.active" class="mr-1 inline size-3" aria-hidden="true" />{{ r.name }}<span v-if="r.sub" class="text-xs text-muted-foreground"> · {{ r.sub }}</span>
                </button>
                <RouterLink
                  v-if="eventsLink(r.events)"
                  :to="eventsLink(r.events)!"
                  class="shrink-0 rounded-sm p-0.5 text-muted-foreground opacity-0 group-hover:opacity-100 focus-visible:opacity-100 focus-visible:outline-2 focus-visible:outline-ring"
                  :title="`Ereignisse zu „${r.name}“`"
                >
                  <ArrowUpRight class="size-3.5" aria-hidden="true" />
                  <span class="sr-only">Ereignisse zu „{{ r.name }}“</span>
                </RouterLink>
              </span>
            </th>
            <td class="py-0.5 text-right">
              {{ formatNumber(tab.columns === 'pages' ? (r.detections ?? 0) : r.requests) }}
            </td>
            <template v-if="tab.columns === 'origin'">
              <td class="py-0.5 text-right">
                {{ r.stopped ? formatNumber(r.stopped) : '–' }}
              </td>
              <td class="hidden py-0.5 text-right text-muted-foreground sm:table-cell">
                {{ r.would_block ? formatNumber(r.would_block) : '–' }}
              </td>
              <td class="py-0.5 text-right text-muted-foreground">
                {{ r.stoppedShare ? formatPercent(r.stoppedShare) : '–' }}
              </td>
            </template>
            <td v-else-if="tab.columns === 'traffic'" class="py-0.5 text-right text-muted-foreground">
              {{ formatPercent(r.share) }}
            </td>
            <td v-else class="py-0.5 text-right">
              {{ formatNumber(observe ? r.would_block : r.stopped) }}
            </td>
          </tr>
        </tbody>
      </table>
      <p v-if="b && (!b.exact || b.partial || b.bot_verification === false)" class="mt-2 text-xs text-muted-foreground">
        <template v-if="!b.exact">
          {{ WEBSITE_COPY.estimate }}: seltene Einträge können etwas zu hoch erscheinen.
        </template>
        <span v-if="b.partial" data-testid="panel-gap">
          {{ gapCopy(b.gap_kind).label }}: {{ gapCopy(b.gap_kind).text }}
        </span>
        <template v-if="b.bot_verification === false">
          {{ COPY.botsUnverified }}
        </template>
      </p>
      <slot name="footer" />
    </CardContent>
  </Card>
</template>
