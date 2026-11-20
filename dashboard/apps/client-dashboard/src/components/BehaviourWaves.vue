<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { Wave, WaveQuery } from '@/api/distributed'
import { Button, EmptyState, ErrorState, MetaLine, RelativeTime, SegmentedControl, Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, Skeleton, StatusPill, Tag } from '@schild/ui'
import { Waves } from '@lucide/vue'
import { computed, onBeforeUnmount, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage } from '@/api/client'
import { useDistributedSettings, useWaves } from '@/api/distributed'
import SheetStepper from '@/components/SheetStepper.vue'
import WavePanel from '@/components/WavePanel.vue'
import { explainWave, remainingText, responseText, RESPONSES, stoppedText, waveOutcome, waveTitle } from '@/lib/distributed'

/** The "Wellen" tab: distributed attacks in plain German, the detail panel and the detector switches. */
const route = useRoute()
const router = useRouter()
function setQuery(patch: Record<string, string | undefined>) {
  const query = { ...route.query }
  for (const [k, v] of Object.entries(patch)) {
    if (!v) delete query[k]
    else query[k] = v
  }
  void router.replace({ query })
}

type Filter = 'all' | 'running'
const filter = computed<Filter>(() => route.query.filter === 'running' ? 'running' : 'all')
const filterModel = computed({ get: () => filter.value, set: (v: Filter) => setQuery({ filter: v === 'all' ? undefined : v }) })
const FILTERS: SegmentOption<Filter>[] = [
  { value: 'all', label: 'Alle', testid: 'waves-filter-all' },
  { value: 'running', label: 'Laufende Reaktionen', testid: 'waves-filter-running' },
]
const waveQuery = computed<WaveQuery>(() => filter.value === 'running' ? { active: true } : {})
const wavesQ = useWaves(waveQuery)
const waves = computed(() => wavesQ.data.value?.pages.flatMap(p => p.items) ?? [])
const settings = useDistributedSettings()
const s = computed(() => settings.data.value)

const now = ref(Date.now())
const timer = setInterval(() => (now.value = Date.now()), 30_000)
onBeforeUnmount(() => clearInterval(timer))

/** The second line: the running response, what it would have done, or how it ended. */
function responseLine(w: Wave): string {
  if (w.action === 'observe') return `Hätte reagiert mit: ${responseText({ ...w, until: null }, s.value)}`
  if (w.active) return responseText(w, s.value)
  return `${RESPONSES[w.response]}, ${stoppedText(w.stopped)}`
}

const detailId = computed(() => typeof route.query.wave === 'string' ? route.query.wave : null)
const detailOpen = computed({ get: () => !!detailId.value, set: v => !v && setQuery({ wave: undefined }) })
</script>

<template>
  <div class="space-y-8">
    <section class="space-y-4" aria-label="Wellen">
      <SegmentedControl v-model="filterModel" :options="FILTERS" label="Wellen filtern" />
      <ErrorState v-if="wavesQ.isError.value && !waves.length" title="Die Wellen lassen sich gerade nicht laden" :description="errorMessage(wavesQ.error.value)" @retry="wavesQ.refetch()" />
      <div v-else-if="wavesQ.isPending.value" class="space-y-2">
        <Skeleton v-for="i in 3" :key="i" class="h-20 w-full" />
      </div>
      <EmptyState
        v-else-if="!waves.length"
        :icon="Waves"
        :title="filter === 'running' ? 'Gerade läuft keine Reaktion' : 'Noch keine Wellen'"
        :description="filter === 'running' ? 'Reaktionen auf Wellen enden von selbst. Laufende stehen hier.' : 'Sobald viele Adressen gemeinsam eine Anmeldung, ein Konto oder dieselbe Anfrage ausprobieren, steht das hier, mit einer kurzen Erklärung.'"
        data-testid="waves-empty"
      />
      <template v-else>
        <ul class="divide-y rounded-xl border bg-card" aria-label="Wellen" data-testid="waves-list">
          <li v-for="w in waves" :key="w.id">
            <button
              type="button"
              class="grid w-full gap-1.5 p-4 text-left text-sm transition-colors outline-none hover:bg-muted/60 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
              data-testid="wave-item"
              :data-wave="w.id"
              @click="setQuery({ wave: w.id })"
            >
              <span class="flex flex-wrap items-center gap-2">
                <Tag tone="neutral">{{ waveTitle(w) }}</Tag>
                <StatusPill :tone="waveOutcome(w).tone" size="sm" data-testid="wave-outcome">{{ waveOutcome(w).label }}</StatusPill>
                <span v-if="w.active && w.until" class="text-xs text-muted-foreground tabular-nums" data-testid="wave-remaining">{{ remainingText(w.until, now) }}</span>
                <RelativeTime :value="w.time" class="ml-auto text-xs text-muted-foreground" />
              </span>
              <span class="font-semibold" data-testid="wave-explain">{{ explainWave(w) }}</span>
              <span class="text-muted-foreground" data-testid="wave-response">{{ responseLine(w) }}</span>
              <span v-if="waveOutcome(w, s?.learning_until).reason" class="text-muted-foreground" data-testid="wave-reason">{{ waveOutcome(w, s?.learning_until).reason }}</span>
              <MetaLine :items="[w.host ?? '', w.active ? stoppedText(w.stopped) : '']" />
            </button>
          </li>
        </ul>
        <div v-if="wavesQ.hasNextPage.value" class="flex justify-center">
          <Button variant="outline" size="sm" :disabled="wavesQ.isFetchingNextPage.value" @click="wavesQ.fetchNextPage()">
            {{ wavesQ.isFetchingNextPage.value ? 'Lädt …' : 'Mehr laden' }}
          </Button>
        </div>
      </template>
    </section>

    <Sheet v-model:open="detailOpen">
      <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-2xl xl:max-w-3xl" data-testid="wave-sheet">
        <SheetHeader class="border-b">
          <SheetTitle>Welle</SheetTitle>
          <SheetDescription>Was passiert ist, wie Schild reagiert und was du tun kannst.</SheetDescription>
          <SheetStepper :ids="waves.map(x => x.id)" :current="detailId" @select="id => setQuery({ wave: id })" />
        </SheetHeader>
        <WavePanel v-if="detailId" :id="detailId" />
      </SheetContent>
    </Sheet>
  </div>
</template>
