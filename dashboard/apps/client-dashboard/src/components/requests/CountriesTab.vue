<script setup lang="ts">
import type { WebsiteRangeKey } from '@/api/websites'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, flagEmoji, formatNumber, formatPercent, Skeleton } from '@schild/ui'
import { computed } from 'vue'
import { useOverview } from '@/api/queries'
import { isFilterUnavailable, useWebsiteBreakdown } from '@/api/websites'
import EstimateNote from '@/components/monitoring/EstimateNote.vue'
import GapNote from '@/components/monitoring/GapNote.vue'
import { keyLabel } from '@/lib/monitoring'
import { geoDbText } from '@/lib/requests'
import { WEBSITE_COPY } from '@/lib/websites'
import WorldMap from './WorldMap.vue'

/**
 * Länder (MVP-22): requests per country as a list and on the built-in world map (no tile server). Each
 * row carries requests, erkannt and gesperrt side by side; a click filters the page by the country.
 * The source of the country data is named below ("Geo-Daten: <Anbieter>, Stand <Datum>").
 */
const props = defineProps<{ site: string, range: WebsiteRangeKey, filters: string[], activeCountry?: string | null, offerRange?: boolean }>()
const emit = defineEmits<{ filter: [expr: string], range: [key: WebsiteRangeKey] }>()

const q = useWebsiteBreakdown(() => ({ site: props.site, range: props.range, filters: props.filters, by: 'country', top: 100 }))
const b = computed(() => q.data.value)
const unavailable = computed(() => isFilterUnavailable(q.error.value))
const items = computed(() => (b.value?.items ?? []).filter(i => i.key !== 'ZZ'))
const unknown = computed(() => b.value?.items.find(i => i.key === 'ZZ') ?? null)
const total = computed(() => b.value?.total.requests ?? 0)
const overview = useOverview()
const geo = computed(() => geoDbText(overview.data.value?.geo_db))
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-[3fr_2fr]" data-testid="countries-tab">
    <Card class="min-w-0">
      <CardHeader>
        <div class="flex flex-wrap items-center gap-2">
          <CardTitle>Woher die Anfragen kommen</CardTitle>
          <EstimateNote v-if="b && !b.exact" :text="`${WEBSITE_COPY.estimate}: seltene Länder können etwas zu hoch erscheinen.`" />
          <GapNote v-if="b?.partial" :kind="b.gap_kind" />
        </div>
        <CardDescription>Nur das Land, keine Stadt oder Region. Klick auf ein Land filtert die ganze Ansicht.</CardDescription>
      </CardHeader>
      <CardContent>
        <div v-if="unavailable" class="rounded-lg border border-dashed p-4 text-sm">
          <p class="text-muted-foreground">
            {{ WEBSITE_COPY.filterUnavailableShort }}
          </p>
          <Button v-if="offerRange" size="sm" variant="outline" class="mt-2" @click="emit('range', '48h')">
            {{ WEBSITE_COPY.to48h }}
          </Button>
        </div>
        <WorldMap v-else :items="items" :active="activeCountry" @select="c => emit('filter', `country:${c}`)" />
        <p v-if="geo" class="mt-3 text-xs text-muted-foreground" data-testid="geo-db">
          {{ geo.line }}<template v-if="geo.error">
            · {{ geo.error }}
          </template>
          · Kartenumrisse: Natural Earth (gemeinfrei)
        </p>
      </CardContent>
    </Card>
    <Card class="min-w-0">
      <CardHeader>
        <CardTitle>Länder</CardTitle>
      </CardHeader>
      <CardContent>
        <div v-if="q.isPending.value" class="space-y-2">
          <Skeleton v-for="i in 8" :key="i" class="h-7 w-full" />
        </div>
        <div v-else-if="items.length" class="max-h-[480px] overflow-y-auto">
          <table class="w-full table-fixed text-sm tabular-nums">
            <caption class="sr-only">
              Anfragen nach Land
            </caption>
            <thead class="sticky top-0 bg-card text-xs text-muted-foreground">
              <tr>
                <th scope="col" class="pb-1.5 text-left font-medium">
                  Land
                </th>
                <th scope="col" class="w-20 pb-1.5 text-right font-medium">
                  Anfragen
                </th>
                <th scope="col" class="w-16 pb-1.5 text-right font-medium">
                  Anteil
                </th>
                <th scope="col" class="hidden w-16 pb-1.5 text-right font-medium sm:table-cell">
                  Erkannt
                </th>
                <th scope="col" class="w-16 pb-1.5 text-right font-medium">
                  Gesperrt
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="i in items" :key="i.key" :data-row="i.key">
                <th scope="row" class="truncate py-0.5 pr-2 text-left font-normal">
                  <button
                    type="button"
                    class="max-w-full truncate rounded-sm text-left hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                    :class="activeCountry === i.key ? 'font-semibold' : ''"
                    :aria-pressed="activeCountry === i.key"
                    @click="emit('filter', `country:${i.key}`)"
                  >
                    <span class="mr-1.5" aria-hidden="true">{{ flagEmoji(i.key) }}</span>{{ keyLabel('country', i.key) }}
                  </button>
                </th>
                <td class="py-0.5 text-right">
                  {{ formatNumber(i.requests) }}
                </td>
                <td class="py-0.5 text-right text-muted-foreground">
                  {{ total ? formatPercent(i.requests / total) : '–' }}
                </td>
                <td class="hidden py-0.5 text-right text-muted-foreground sm:table-cell">
                  {{ i.would_block ? formatNumber(i.would_block) : '–' }}
                </td>
                <td class="py-0.5 text-right text-muted-foreground">
                  {{ i.stopped ? formatNumber(i.stopped) : '–' }}
                </td>
              </tr>
            </tbody>
          </table>
          <p v-if="unknown" class="mt-2 text-xs text-muted-foreground">
            Ohne bekanntes Land: {{ formatNumber(unknown.requests) }} Anfragen.
          </p>
        </div>
        <p v-else-if="!unavailable" class="text-sm text-muted-foreground">
          Noch keine Anfragen in diesem Zeitraum.
        </p>
      </CardContent>
    </Card>
  </div>
</template>
