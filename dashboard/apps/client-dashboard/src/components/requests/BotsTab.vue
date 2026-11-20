<script setup lang="ts">
import type { BotOverview, BotVerification } from '@/api/requests'
import type { WebsiteRangeKey } from '@/api/websites'
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, formatBytes, formatNumber, RelativeTime, SegmentedControl, Skeleton } from '@schild/ui'
import { computed, ref } from 'vue'
import { errorMessage } from '@/api/client'
import { isRingBusy, ringWindow, useBotOverview } from '@/api/requests'
import EstimateNote from '@/components/monitoring/EstimateNote.vue'
import { blockedText } from '@/lib/crawlers'
import { websitePath } from '@/lib/nav'
import { AI_CATEGORIES, botCategoryLabel, RANGE_SOURCE, REQUESTS_COPY, robotsText, VERIFICATION_KEYS } from '@/lib/requests'
import { WEBSITE_COPY } from '@/lib/websites'
import VerificationBadge from './VerificationBadge.vue'

/**
 * Bots & KI-Crawler (getBotOverview, MVP-22): requests and bytes per category and per catalogue bot, last
 * seen, whether the address belongs to the operator ("bestätigt", "nicht prüfbar", "gibt sich als … aus",
 * "Prüfliste veraltet"), robots.txt behaviour ("hält sich daran: ja / nein / unklar"), catalogue version
 * and the age of each range snapshot. What the crawler policy of the website (D57) blocked, or would have
 * blocked, stands below the requests; the rules themselves are on the KI-Crawler page.
 */
const props = defineProps<{ site: string, range: WebsiteRangeKey, activeCategory?: string | null }>()
const emit = defineEmits<{ filter: [expr: string], requests: [query: Record<string, string>] }>()

const q = useBotOverview(() => ({ site: props.site, range: props.range }))
const o = computed<BotOverview | undefined>(() => q.data.value)
const clamped = computed(() => ringWindow(props.range).clamped)
const show = ref<'all' | 'ai'>('all')
const categories = computed(() => (o.value?.categories ?? []).filter(c => c.category !== 'likely_browser' && (show.value === 'all' || AI_CATEGORIES.has(c.category))))
const maxCat = computed(() => Math.max(1, ...categories.value.map(c => c.requests)))
const bots = computed(() => (o.value?.bots ?? []).filter(b => show.value === 'all' || AI_CATEGORIES.has(b.category)).map(b => ({
  b,
  states: VERIFICATION_KEYS.filter(k => b.verification[k] > 0).map(k => ({ k, n: b.verification[k] })) as { k: BotVerification, n: number }[],
})))
const sources = computed(() => [...new Set((o.value?.ranges ?? []).map(x => RANGE_SOURCE[x.source]))].join(', '))
const stale = computed(() => (o.value?.ranges ?? []).filter(r => r.stale))
const day = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })
const fmtDay = (t: string) => day.format(new Date(t))
const verifyText = computed(() => {
  const v = o.value?.verification
  if (!v) return ''
  if (!v.ranges && !v.fcrdns) return 'Die Prüfung der Adressen ist ausgeschaltet (bots.verify). Alle Bots gelten als nicht prüfbar.'
  return [v.ranges ? 'Adresslisten der Betreiber' : '', v.fcrdns ? 'Rückwärts-DNS' : ''].filter(Boolean).join(' und ')
})
</script>

<template>
  <div class="space-y-4" data-testid="bots-tab">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <p class="text-sm text-muted-foreground" data-testid="bots-crawler-control">
        {{ REQUESTS_COPY.crawlerControl[0] }}
        <RouterLink v-if="site" :to="websitePath(site, 'ai-crawlers')" class="font-medium text-foreground underline underline-offset-4 hover:no-underline">{{ WEBSITE_COPY.crawlers }}</RouterLink><template v-else>{{ WEBSITE_COPY.crawlers }}</template>
        {{ REQUESTS_COPY.crawlerControl[1] }}
      </p>
      <SegmentedControl v-model="show" :options="[{ value: 'all', label: 'Alle Bots' }, { value: 'ai', label: 'Nur KI-Crawler', testid: 'bots-ai' }]" label="Auswahl" />
    </div>
    <p v-if="clamped" class="text-sm text-muted-foreground" data-testid="bots-clamped">
      {{ REQUESTS_COPY.ringClamped }}
    </p>

    <div v-if="q.isPending.value" class="grid gap-4 lg:grid-cols-3">
      <Skeleton class="h-64" />
      <Skeleton class="h-64 lg:col-span-2" />
    </div>
    <ErrorState v-else-if="q.isError.value" title="Die Bots lassen sich gerade nicht laden" :description="isRingBusy(q.error.value) ? REQUESTS_COPY.busy : errorMessage(q.error.value)" :retrying="q.isFetching.value" @retry="q.refetch()" />
    <template v-else-if="o">
      <div class="space-y-4">
        <Card class="min-w-0">
          <CardHeader>
            <div class="flex flex-wrap items-center gap-2">
              <CardTitle>Nach Art</CardTitle>
              <EstimateNote v-if="o.sample_rate < 1" :text="REQUESTS_COPY.sampled" />
            </div>
            <CardDescription>Die Art kommt aus dem, was der Bot über sich sagt.</CardDescription>
          </CardHeader>
          <CardContent>
            <p v-if="!categories.length" class="text-sm text-muted-foreground">
              {{ REQUESTS_COPY.noBots }}
            </p>
            <ul v-else class="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
              <li v-for="c in categories" :key="c.category" :data-category="c.category">
                <button
                  type="button"
                  class="w-full rounded-sm text-left focus-visible:outline-2 focus-visible:outline-ring"
                  :aria-pressed="activeCategory === c.category"
                  :title="`Nach ${botCategoryLabel(c.category)} filtern`"
                  @click="emit('filter', `bot_category:${c.category}`)"
                >
                  <span class="flex items-baseline justify-between gap-2">
                    <span class="truncate hover:underline" :class="activeCategory === c.category ? 'font-semibold' : ''">{{ botCategoryLabel(c.category) }}</span>
                    <span class="shrink-0 tabular-nums">{{ formatNumber(c.requests) }}</span>
                  </span>
                  <span class="mt-0.5 block h-1 rounded-full bg-muted" aria-hidden="true">
                    <span class="block h-1 rounded-full" :style="{ width: `${(c.requests / maxCat) * 100}%`, background: 'var(--tone-main)' }" />
                  </span>
                  <span class="text-xs text-muted-foreground">{{ formatBytes(c.bytes_out) }}<template v-if="c.bots"> · {{ c.bots }} {{ c.bots === 1 ? 'Bot' : 'Bots' }}</template></span>
                </button>
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card class="min-w-0">
          <CardHeader>
            <CardTitle>Bekannte Bots und KI-Crawler</CardTitle>
            <CardDescription>{{ REQUESTS_COPY.verificationNote }}</CardDescription>
          </CardHeader>
          <CardContent>
            <p v-if="!bots.length" class="text-sm text-muted-foreground">
              {{ REQUESTS_COPY.noBots }}
            </p>
            <div v-else class="overflow-x-auto">
              <table class="w-full min-w-[760px] text-sm tabular-nums" data-testid="bots-table">
                <caption class="sr-only">
                  Bots und KI-Crawler mit Anfragen, Datenmenge, zuletzt gesehen, Prüfung und robots.txt
                </caption>
                <thead class="text-xs text-muted-foreground">
                  <tr>
                    <th scope="col" class="pb-1.5 text-left font-medium">
                      Bot
                    </th>
                    <th scope="col" class="w-20 pb-1.5 text-right font-medium">
                      Anfragen
                    </th>
                    <th scope="col" class="w-20 pb-1.5 text-right font-medium">
                      Daten
                    </th>
                    <th scope="col" class="w-28 pb-1.5 pl-3 text-left font-medium">
                      Zuletzt
                    </th>
                    <th scope="col" class="pb-1.5 text-left font-medium">
                      Adresse
                    </th>
                    <th scope="col" class="w-56 pb-1.5 pl-3 text-left font-medium" title="Beachtet der Bot deine robots.txt?">
                      robots.txt: hält sich daran?
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y">
                  <tr v-for="x in bots" :key="x.b.id" :data-bot="x.b.id">
                    <th scope="row" class="py-1.5 pr-2 text-left font-normal">
                      <button
                        type="button"
                        class="rounded-sm text-left font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring"
                        :title="`Anfragen von ${x.b.name} ansehen`"
                        @click="emit('requests', { bot: x.b.id })"
                      >
                        {{ x.b.name }}
                      </button>
                      <span class="block text-xs text-muted-foreground">{{ x.b.operator }} · {{ botCategoryLabel(x.b.category) }}</span>
                    </th>
                    <td class="py-1.5 text-right">
                      {{ formatNumber(x.b.requests) }}
                      <span v-if="x.b.blocked || x.b.would_block" class="block text-xs whitespace-nowrap text-muted-foreground" :data-crawler-blocked="x.b.id">{{ x.b.blocked ? 'geblockt: ' : '' }}{{ blockedText(x.b) }}</span>
                    </td>
                    <td class="py-1.5 text-right text-muted-foreground">
                      {{ formatBytes(x.b.bytes_out) }}
                    </td>
                    <td class="py-1.5 pl-3 text-muted-foreground">
                      <RelativeTime :value="x.b.last_seen" />
                    </td>
                    <td class="py-1.5">
                      <span class="flex flex-wrap gap-1">
                        <button
                          v-for="s in x.states"
                          :key="s.k"
                          type="button"
                          class="rounded-full focus-visible:outline-2 focus-visible:outline-ring"
                          :title="`Diese Anfragen ansehen`"
                          @click="emit('requests', { bot: x.b.id, verification: s.k })"
                        >
                          <VerificationBadge :state="s.k" :name="x.b.name" :count="x.states.length > 1 ? s.n : undefined" />
                        </button>
                      </span>
                    </td>
                    <td class="py-1.5 pl-3 text-xs">
                      <template v-if="x.b.robots">
                        <span :class="x.b.robots.respects === 'no' ? 'font-medium' : ''" :data-robots="x.b.robots.respects">{{ robotsText(x.b.robots) }}</span>
                        <span class="block text-muted-foreground">
                          <template v-if="x.b.robots.read_at">gelesen <RelativeTime :value="x.b.robots.read_at" /></template>
                          <template v-else>nicht gelesen</template>
                          · {{ x.b.robots.token }}
                        </span>
                      </template>
                      <span v-else class="text-muted-foreground">–</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>

      <p class="text-xs text-muted-foreground" data-testid="bots-catalogue">
        Bot-Liste vom {{ o.catalogue_version.slice(0, 10).split('-').reverse().join('.') }} (Version {{ o.catalogue_version }})
        <template v-if="verifyText">
          · Geprüft über {{ verifyText }}
        </template>
        <template v-if="o.ranges.length">
          · Adresslisten:
          <span v-for="(r, i) in o.ranges" :key="r.id" :data-range="r.id" :class="r.stale ? 'font-medium text-foreground' : ''">{{ r.operator }} vom {{ fmtDay(r.fetched_at) }}<template v-if="r.stale"> (veraltet)</template><template v-if="i < o.ranges.length - 1">, </template></span>
          ({{ sources }})
        </template>
      </p>
      <p v-if="stale.length" class="text-xs text-muted-foreground">
        Älter als 30 Tage: {{ stale.map(r => r.operator).join(', ') }}. Deren Bots zeigt Schild als „Prüfliste veraltet“, bis eine neue Liste kommt.<template v-if="o.verification.ranges_fetch"> Schild fragt die Betreiber einmal am Tag. Bleibt das so, kommt die Liste beim Betreiber gerade nicht an.</template><template v-else> Die neue Liste kommt mit dem nächsten Update von Schild oder täglich mit bots.ranges_fetch.</template>
      </p>
    </template>
  </div>
</template>
