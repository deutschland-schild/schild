<script setup lang="ts">
import type { ColumnDef, SegmentOption } from '@schild/ui'
import type { BehaviourHit, HitQuery, LimitMode, RateLimit } from '@/api/behaviour'
import {
  Button,
  countryName,
  DataTable,
  EmptyState,
  ErrorState,
  MetaLine,
  NativeSelect,
  NativeSelectOption,
  PageHeader,
  RelativeTime,
  SegmentedControl,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  Skeleton,
  StatusPill,
  Tabs,
  TabsList,
  TabsTrigger,
  Tag,
  toast,
} from '@schild/ui'
import { Gauge, Pencil, Plus, Trash2 } from '@lucide/vue'
import { computed, h, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { errorMessage, problemOf } from '@/api/client'
import { useBehaviourHits, useDeleteRateLimit, useRateLimits, useUpdateBehaviourSettings } from '@/api/behaviour'
import BehaviourHitPanel from '@/components/BehaviourHitPanel.vue'
import RunningBlocks from '@/components/blocks/RunningBlocks.vue'
import StoppedRequests from '@/components/blocks/StoppedRequests.vue'
import BehaviourScenarios from '@/components/BehaviourScenarios.vue'
import BehaviourWaves from '@/components/BehaviourWaves.vue'
import DistributedDetectors from '@/components/DistributedDetectors.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import RateLimitDialog from '@/components/RateLimitDialog.vue'
import SheetStepper from '@/components/SheetStepper.vue'
import { BLOCKS_COPY } from '@/lib/blocks'
import { explainHit, hitOutcome, hitTitle, LIMIT_MODES, LIMIT_SOURCES, isIdlePreset, limitRecommendationChanges, limitText, limitUsageText, PRESETS } from '@/lib/behaviour'

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

// Two pages share this view (2026-11-18): "Szenarien und Limits" below Regeln, what schild can do across requests,
// and "Sperren", what it did: the addresses blocked now (D87), the stopped requests, the hits and the waves.
type Tab = 'addresses' | 'requests' | 'hits' | 'scenarios' | 'limits' | 'detectors'
const part = computed(() => route.meta.part === 'rules' ? 'rules' : 'blocks')
const TABS: Record<'rules' | 'blocks', { value: Tab, label: string }[]> = {
  rules: [{ value: 'scenarios', label: 'Szenarien' }, { value: 'limits', label: 'Limits' }, { value: 'detectors', label: 'Wellen' }],
  blocks: [{ value: 'addresses', label: BLOCKS_COPY.addresses }, { value: 'requests', label: BLOCKS_COPY.requests }, { value: 'hits', label: 'Verlauf' }],
}
const tabs = computed(() => TABS[part.value])
const tab = computed<Tab>(() => tabs.value.find(t => t.value === route.query.view)?.value ?? tabs.value[0]!.value)
const tabModel = computed({ get: () => tab.value, set: v => setQuery({ view: v === tabs.value[0]!.value ? undefined : String(v), hit: undefined }) })
const HEADER = {
  rules: { title: 'Szenarien und Limits', description: 'Was erst über mehrere Anfragen auffällt: Passwort-Raten, Suche nach Schwachstellen, zu viele Anfragen. Ein Szenario auf „Sperren“ sperrt die Adresse für eine Weile, ein Limit beantwortet zu viele Anfragen mit „zu viele Anfragen“.' },
  blocks: { title: BLOCKS_COPY.title, description: BLOCKS_COPY.lead },
} as const

// ---------------------------------------------------------------- hits
type Filter = 'all' | 'scenarios' | 'limits' | 'running'
const filter = computed<Filter>(() => (['scenarios', 'limits', 'running'].includes(String(route.query.filter)) ? route.query.filter as Filter : 'all'))
const filterModel = computed({ get: () => filter.value, set: (v: Filter) => setQuery({ filter: v === 'all' ? undefined : v }) })
const FILTERS: SegmentOption<Filter>[] = [
  { value: 'all', label: 'Alle', testid: 'hits-filter-all' },
  { value: 'scenarios', label: 'Szenarien', testid: 'hits-filter-scenarios' },
  { value: 'limits', label: 'Limits', testid: 'hits-filter-limits' },
  { value: 'running', label: 'Laufende Sperren', testid: 'hits-filter-running' },
]
const hitQuery = computed<HitQuery>(() => {
  switch (filter.value) {
    case 'scenarios': return { kind: 'scenario' }
    case 'limits': return { kind: 'rate_limit' }
    case 'running': return { active: true }
    default: return {}
  }
})
const hitsQ = useBehaviourHits(hitQuery)
const hits = computed(() => hitsQ.data.value?.pages.flatMap(p => p.items) ?? [])
const EMPTY: Record<Filter, { title: string, description: string }> = {
  all: { title: 'Noch keine Treffer', description: 'Sobald eine Adresse durch ihr Verhalten über mehrere Anfragen auffällt oder über einem Limit liegt, steht sie hier, mit einer kurzen Erklärung.' },
  scenarios: { title: 'Keine Treffer von Szenarien', description: 'Passwort-Raten, Suche nach Schwachstellen und ähnliche Muster erscheinen hier, sobald Schild sie sieht.' },
  limits: { title: 'Niemand über einem Limit', description: 'Wer mehr Anfragen schickt, als ein Limit erlaubt, erscheint hier.' },
  running: { title: 'Gerade läuft keine Sperre', description: 'Sperren wegen Verhalten oder Limits enden von selbst. Laufende stehen hier.' },
}

function hitMeta(hit: BehaviourHit) {
  return [
    hit.host ?? '',
    hit.preset ? PRESETS[hit.preset] : '',
    hit.geo ? `${countryName(hit.geo.country)}${hit.geo.as_org ? `, ${hit.geo.as_org}` : ''}` : '',
    hit.incident ? { text: hit.incident, mono: true } : '',
  ]
}

const detailId = computed(() => typeof route.query.hit === 'string' ? route.query.hit : null)
const detailOpen = computed({ get: () => !!detailId.value, set: v => !v && setQuery({ hit: undefined }) })

// ---------------------------------------------------------------- rate limits
const limitsQ = useRateLimits()
const limits = computed(() => limitsQ.data.value?.items ?? [])
const editOpen = ref(false)
const editing = ref<RateLimit | null>(null)
function addLimit() {
  editing.value = null
  editOpen.value = true
}
function editLimit(l: RateLimit) {
  editing.value = l
  editOpen.value = true
}
watch(() => route.query.new, (v) => {
  if (v === '1') {
    setQuery({ new: undefined, view: 'limits' })
    addLimit()
  }
}, { immediate: true })

const deleting = ref<RateLimit | null>(null)
const deleteError = ref<string | null>(null)
const deleteOpen = computed({
  get: () => !!deleting.value,
  set: (v) => {
    if (!v) {
      deleting.value = null
      deleteError.value = null
    }
  },
})
const del = useDeleteRateLimit()
async function doDelete() {
  const l = deleting.value
  if (!l) return
  deleteError.value = null
  try {
    await del.mutateAsync({ id: l.id })
    deleting.value = null
    toast(`Limit „${l.label ?? l.route}“ gelöscht`, { description: 'Für diese Route zählt Schild jetzt nur noch die anderen Limits.' })
  }
  catch (err) {
    deleting.value = null
    toast.error('Löschen hat nicht geklappt', { description: problemOf(err)?.code === 'config_limit' ? 'Dieses Limit steht in schild.yaml oder ist voreingestellt. Ändere es dort.' : errorMessage(err) })
  }
}

// Preset limits are switched one by one, each with its recommendation (D95). Own limits carry their switch in their form.
const LIMIT_MODE_ORDER: LimitMode[] = ['off', 'observe', 'block']
const switchLimits = useUpdateBehaviourSettings()
async function setPresetMode(l: RateLimit, mode: LimitMode) {
  if (mode === l.mode) return
  try {
    await switchLimits.mutateAsync({ preset_limit_modes: { [l.id]: mode } })
    toast.success(`${l.label ?? l.route}: ${LIMIT_MODES[mode].label}`)
  }
  catch (err) {
    toast.error('Umstellen hat nicht geklappt', { description: errorMessage(err) })
  }
}
const limitChanges = computed(() => limitRecommendationChanges(limits.value))
// Preset limits of systems that do not run here stay out of the way until asked for (D96).
const idleLimits = computed(() => limits.value.filter(isIdlePreset).length)
const showIdle = computed(() => route.query.all === '1')
const shownLimits = computed(() => showIdle.value ? limits.value : limits.value.filter(l => !isIdlePreset(l)))
const recommendOpen = ref(false)
const recommendError = ref<string | null>(null)
async function applyLimitRecommendation() {
  recommendError.value = null
  const n = limitChanges.value.length
  try {
    await switchLimits.mutateAsync({ preset_limit_modes: Object.fromEntries(limitChanges.value.map(c => [c.id, c.mode])) })
    recommendOpen.value = false
    toast.success(n === 1 ? '1 Limit umgestellt' : `${n} Limits umgestellt`)
  }
  catch (err) {
    recommendError.value = errorMessage(err)
  }
}

const columns: ColumnDef<RateLimit, unknown>[] = [
  {
    id: 'route',
    header: 'Route',
    accessorFn: l => l.label ?? l.route,
    enableHiding: false,
    meta: { label: 'Route', class: 'min-w-56 max-w-[24rem] whitespace-normal' },
    cell: ({ row }) => h('div', { class: 'min-w-0 py-0.5' }, [
      row.original.label ? h('p', { class: 'font-semibold' }, row.original.label) : null,
      h('p', { class: 'font-mono text-[13px] break-all' }, row.original.route),
      h(MetaLine, { items: [row.original.methods?.length ? row.original.methods.join(', ') : 'alle Methoden', row.original.site ?? '', row.original.confirm_site_wide ? 'ganze Website' : ''] }),
    ]),
  },
  {
    id: 'limit',
    header: 'Limit',
    accessorFn: l => l.limit,
    meta: { label: 'Limit' },
    cell: ({ row }) => h('span', { 'data-testid': 'limit-text' }, limitText(row.original)),
  },
  {
    id: 'mode',
    header: 'Schalter',
    accessorKey: 'mode',
    meta: { label: 'Schalter' },
    cell: ({ row }) => row.original.source === 'preset'
      ? h(NativeSelect, {
          'modelValue': row.original.mode,
          'aria-label': `Schalter für ${row.original.label ?? row.original.route}`,
          'data-testid': `limit-mode-${row.original.id}`,
          'disabled': switchLimits.isPending.value,
          'onUpdate:modelValue': (v: unknown) => setPresetMode(row.original, v as LimitMode),
        }, () => LIMIT_MODE_ORDER.map(m => h(NativeSelectOption, { value: m }, () => `${LIMIT_MODES[m].label}${m === row.original.recommended ? ' (empfohlen)' : ''}`)))
      : h(StatusPill, { tone: LIMIT_MODES[row.original.mode].tone, size: 'sm' }, () => LIMIT_MODES[row.original.mode].label),
  },
  {
    id: 'source',
    header: 'Herkunft',
    accessorKey: 'source',
    meta: { label: 'Herkunft', hideOnMobile: true },
    cell: ({ row }) => h('span', { class: 'text-muted-foreground' }, `${LIMIT_SOURCES[row.original.source]}${row.original.preset && row.original.preset !== 'generic' ? ` (${PRESETS[row.original.preset]})` : ''}`),
  },
  {
    id: 'counts',
    header: '24 h',
    accessorKey: 'exceeded_24h',
    meta: { label: '24 h', class: 'whitespace-normal' },
    cell: ({ row }) => h('span', { 'class': row.original.exceeded_24h ? '' : 'text-muted-foreground', 'data-testid': 'limit-counts' }, `${limitUsageText(row.original)}${row.original.exceeded_24h && row.original.mode === 'observe' ? ' (erkannt, Probelauf)' : ''}`),
  },
  {
    id: 'actions',
    header: () => h('span', { class: 'sr-only' }, 'Aktionen'),
    enableSorting: false,
    enableHiding: false,
    meta: { class: 'w-24 text-right' },
    cell: ({ row }) => row.original.source === 'dashboard'
      ? h('div', { class: 'flex justify-end gap-1' }, [
          h(Button, { 'variant': 'ghost', 'size': 'icon-sm', 'aria-label': `${row.original.label ?? row.original.route} ändern`, 'data-testid': 'limit-edit', 'onClick': () => editLimit(row.original) }, () => h(Pencil, { 'aria-hidden': 'true' })),
          h(Button, { 'variant': 'ghost', 'size': 'icon-sm', 'aria-label': `${row.original.label ?? row.original.route} löschen`, 'data-testid': 'limit-delete', 'onClick': () => (deleting.value = row.original) }, () => h(Trash2, { 'aria-hidden': 'true' })),
        ])
      : h('span', { class: 'text-xs text-muted-foreground', title: row.original.source === 'config' ? 'Steht in schild.yaml. Dort ändern.' : 'Voreinstellung. Route und Limit stehen fest, den Schalter stellst du in dieser Zeile.' }, row.original.source === 'config' ? 'yaml' : 'voreingestellt'),
  },
]
</script>

<template>
  <div>
    <PageHeader :title="HEADER[part].title" :description="HEADER[part].description">
      <template v-if="tab === 'limits'" #actions>
        <Button data-testid="limit-add" @click="addLimit">
          <Plus aria-hidden="true" /> Limit hinzufügen
        </Button>
      </template>
    </PageHeader>

    <Tabs v-model="tabModel" class="mb-5">
      <TabsList variant="line" aria-label="Ansicht">
        <TabsTrigger v-for="t in tabs" :key="t.value" :value="t.value" :data-testid="`tab-${t.value}`">
          {{ t.label }}
        </TabsTrigger>
      </TabsList>
    </Tabs>

    <RunningBlocks v-if="tab === 'addresses'" />
    <StoppedRequests v-else-if="tab === 'requests'" />

    <!-- Verlauf: the hits of scenarios and limits -->
    <section v-else-if="tab === 'hits'" class="space-y-4" aria-label="Treffer">
      <SegmentedControl v-model="filterModel" :options="FILTERS" label="Treffer filtern" />
      <ErrorState v-if="hitsQ.isError.value && !hits.length" title="Die Treffer lassen sich gerade nicht laden" :description="errorMessage(hitsQ.error.value)" @retry="hitsQ.refetch()" />
      <div v-else-if="hitsQ.isPending.value" class="space-y-2">
        <Skeleton v-for="i in 4" :key="i" class="h-20 w-full" />
      </div>
      <EmptyState v-else-if="!hits.length" :icon="Gauge" :title="EMPTY[filter].title" :description="EMPTY[filter].description" data-testid="hits-empty" />
      <template v-else>
        <ul class="divide-y rounded-xl border bg-card" aria-label="Treffer" data-testid="hits-list">
          <li v-for="hit in hits" :key="hit.id">
            <button
              type="button"
              class="grid w-full gap-1.5 p-4 text-left text-sm transition-colors outline-none hover:bg-muted/60 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring"
              data-testid="hit-item"
              :data-hit="hit.id"
              @click="setQuery({ hit: hit.id })"
            >
              <span class="flex flex-wrap items-center gap-2">
                <Tag :tone="hit.kind === 'rate_limit' ? 'info' : 'neutral'">{{ hitTitle(hit) }}</Tag>
                <StatusPill :tone="hitOutcome(hit).tone" size="sm" data-testid="hit-outcome">{{ hitOutcome(hit).label }}</StatusPill>
                <Tag v-if="hit.released && hit.reason !== 'released'" tone="success">freigegeben</Tag>
                <RelativeTime :value="hit.time" class="ml-auto text-xs text-muted-foreground" />
              </span>
              <span class="font-semibold" data-testid="hit-explain">{{ explainHit(hit) }}</span>
              <span v-if="hitOutcome(hit).reason" class="text-muted-foreground" data-testid="hit-reason">{{ hitOutcome(hit).reason }}</span>
              <MetaLine :items="hitMeta(hit)" />
            </button>
          </li>
        </ul>
        <div v-if="hitsQ.hasNextPage.value" class="flex justify-center">
          <Button variant="outline" size="sm" :disabled="hitsQ.isFetchingNextPage.value" @click="hitsQ.fetchNextPage()">
            {{ hitsQ.isFetchingNextPage.value ? 'Lädt …' : 'Mehr laden' }}
          </Button>
        </div>
      </template>
    </section>

    <!-- Szenarien -->
    <BehaviourScenarios v-else-if="tab === 'scenarios'" />

    <!-- Wellen (MVP-18) -->
    <!-- Wellen: the detectors of distributed attacks with their switches and thresholds, and the waves they found (D97) -->
    <section v-else-if="tab === 'detectors'" class="space-y-8" aria-label="Wellen">
      <p class="text-sm text-muted-foreground">
        Eine Welle ist ein Angriff über viele wechselnde Adressen, oft über Anschlüsse ahnungsloser Menschen. Schild erkennt sie am Ziel statt am Absender und reagiert nur auf die Route, das Konto oder die Anfrageform, nie auf einzelne Adressen.
      </p>
      <DistributedDetectors />
      <div class="space-y-4">
        <h2 class="text-base font-semibold">
          Erkannte Wellen
        </h2>
        <BehaviourWaves />
      </div>
    </section>

    <!-- Limits -->
    <section v-else-if="tab === 'limits'" class="space-y-4" aria-label="Limits">
      <p class="text-sm text-muted-foreground">
        Ein Limit begrenzt, wie viele Anfragen eine Adresse an eine Route schicken darf. Bei IPv6 zählt Schild das ganze /64-Netz zusammen, bei IPv4 nie mehr als ein /24-Netz. Voreingestellte Limits gelten für die üblichen Pfade von WordPress, Joomla, Drupal, Nextcloud, TYPO3 und Laravel. Jedes hat seinen eigenen Schalter, Route und Limit stehen fest. Ändern und löschen kannst du Limits, die du im Dashboard angelegt hast.
      </p>
      <div v-if="limitChanges.length" class="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border p-3" data-testid="limit-recommendation">
        <p class="min-w-48 flex-1 text-sm">
          {{ limitChanges.length === 1 ? '1 voreingestelltes Limit steht nicht auf der Empfehlung.' : `${limitChanges.length} voreingestellte Limits stehen nicht auf der Empfehlung.` }}
          <span class="text-muted-foreground">Empfohlen: Anmeldung, Passwort vergessen und XML-RPC begrenzen, Suche, Kontaktformulare und APIs beobachten.</span>
        </p>
        <Button size="sm" data-testid="limit-apply-recommendation" @click="recommendOpen = true">
          Empfehlung übernehmen
        </Button>
      </div>
      <ErrorState v-if="limitsQ.isError.value && !limits.length" title="Die Limits lassen sich gerade nicht laden" :description="errorMessage(limitsQ.error.value)" @retry="limitsQ.refetch()" />
      <DataTable
        v-else
        :columns="columns"
        :data="shownLimits"
        label="Limits"
        :loading="limitsQ.isPending.value"
        :get-row-id="(l: RateLimit) => l.id"
        cursor
        :estimate-row-height="72"
        empty-title="Noch keine Limits"
        empty-description="Leg ein Limit für eine Route an, z. B. für ein Kontaktformular. Starte mit „Beobachten“ und einem Probelauf."
        hide-column-menu
      />
      <p v-if="idleLimits" class="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-muted-foreground" data-testid="limits-idle">
        <template v-if="showIdle">
          {{ idleLimits === 1 ? '1 voreingestelltes Limit hatte' : `${idleLimits} voreingestellte Limits hatten` }} in 24 Stunden keine Anfrage an {{ idleLimits === 1 ? 'seinen' : 'ihren' }} Pfad.
        </template>
        <template v-else>
          {{ idleLimits === 1 ? '1 voreingestelltes Limit ist' : `${idleLimits} voreingestellte Limits sind` }} ausgeblendet: Sie stehen auf der Empfehlung und ihr Pfad hatte in 24 Stunden keine Anfrage. Sie gelten trotzdem.
        </template>
        <Button variant="link" size="sm" class="h-auto p-0" data-testid="limits-idle-toggle" @click="setQuery({ all: showIdle ? undefined : '1' })">
          {{ showIdle ? 'Nur genutzte zeigen' : 'Alle zeigen' }}
        </Button>
      </p>
    </section>

    <Sheet v-model:open="detailOpen">
      <SheetContent class="w-full gap-0 overflow-y-auto sm:max-w-2xl xl:max-w-3xl" data-testid="hit-sheet">
        <SheetHeader class="border-b">
          <SheetTitle>Treffer</SheetTitle>
          <SheetDescription>Was passiert ist und was du tun kannst.</SheetDescription>
          <SheetStepper :ids="hits.map(x => x.id)" :current="detailId" @select="id => setQuery({ hit: id })" />
        </SheetHeader>
        <BehaviourHitPanel v-if="detailId" :id="detailId" />
      </SheetContent>
    </Sheet>

    <RateLimitDialog v-model:open="editOpen" :limit="editing" />
    <ConfirmDialog
      v-model:open="recommendOpen"
      title="Empfehlung für die Limits übernehmen?"
      :confirm-label="limitChanges.length === 1 ? '1 Limit umstellen' : `${limitChanges.length} Limits umstellen`"
      :pending="switchLimits.isPending.value"
      :error="recommendError"
      @confirm="applyLimitRecommendation"
    >
      Wer über einem Limit auf „Begrenzen“ liegt, bekommt kurz die Antwort „zu viele Anfragen“. Limits wirken sofort, auch während Schild noch lernt. Deine eigenen Adressen sind ausgenommen.
      <template #details>
        <ul class="grid gap-1 text-sm" data-testid="limit-bulk-changes">
          <li v-for="c in limitChanges" :key="c.id">
            <span class="font-medium">{{ c.name }}:</span> {{ c.from }} → {{ c.to }}
          </li>
        </ul>
      </template>
    </ConfirmDialog>
    <ConfirmDialog
      v-model:open="deleteOpen"
      :title="`Limit „${deleting?.label ?? deleting?.route ?? ''}“ löschen?`"
      confirm-label="Löschen"
      :pending="del.isPending.value"
      :error="deleteError"
      @confirm="doDelete"
    >
      Schild zählt für diese Route dann nicht mehr mit diesem Limit. Andere Limits und Szenarien laufen weiter.
    </ConfirmDialog>
  </div>
</template>
