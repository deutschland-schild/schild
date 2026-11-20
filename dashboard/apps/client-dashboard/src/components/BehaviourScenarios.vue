<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { BehaviourMode, BehaviourSettingsPatch, ScenarioId, ScenarioSetting } from '@/api/behaviour'
import type { RecommendationChange } from '@/lib/behaviour'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, ErrorState, MetaLine, SegmentedControl, Skeleton, toast } from '@schild/ui'
import { CircleCheck, Ellipsis, Eye, Info, ShieldBan, SlidersHorizontal } from '@lucide/vue'
import { computed, ref } from 'vue'
import { errorMessage } from '@/api/client'
import { useBehaviourSettings, useUpdateBehaviourSettings } from '@/api/behaviour'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import ScenarioThresholdsDialog from '@/components/ScenarioThresholdsDialog.vue'
import Term from '@/components/Term.vue'
import { activeBlocksText, formatDay, isLearning, ladderText, RECOMMENDED_WHY, recommendationChanges, SCENARIO_MODES, SCENARIO_ORDER, SCENARIOS, scenarioCountsText, thresholdsChanged, thresholdsText } from '@/lib/behaviour'

/**
 * Per-scenario switches (Aus / Beobachten / Sperren), preset limits and the block ladder. Each switch marks its
 * recommended mode; "Empfehlung übernehmen" and the menu set several switches in one change, they are no mode
 * of their own (D92, D89).
 */
const q = useBehaviourSettings()
const s = computed(() => q.data.value)
const scenarios = computed(() => {
  const list = s.value?.scenarios ?? []
  return SCENARIO_ORDER.map(id => list.find(x => x.id === id)).filter((x): x is ScenarioSetting => !!x)
})
/** No scenario blocks: say that nothing gets blocked. */
const noneBlocking = computed(() => scenarios.value.length > 0 && !scenarios.value.some(x => x.effective_mode === 'block'))
const learning = computed(() => !!s.value && isLearning(s.value))

const RECOMMENDED = 'empfohlen'
const scenarioOptions = (sc: ScenarioSetting): SegmentOption<BehaviourMode>[] => (['off', 'observe', 'block'] as const).map(m => ({
  value: m,
  label: SCENARIO_MODES[m].label,
  tone: m === 'block' ? 'ink' : m === 'off' ? 'neutral' : 'signal',
  testid: `scenario-${sc.id}-${m}`,
  mark: m === sc.recommended ? RECOMMENDED : undefined,
}))

// ---------------------------------------------------------------- recommendation and "all at once" (D92)
const changes = computed(() => s.value ? recommendationChanges(s.value) : [])
const recommendedBlocking = computed(() => scenarios.value.filter(x => x.recommended === 'block').length)

function changesTo(mode: BehaviourMode): RecommendationChange[] {
  return scenarios.value.filter(x => x.mode !== mode).map(x => ({ kind: 'scenario', id: x.id, mode, name: SCENARIOS[x.id].name, from: SCENARIO_MODES[x.mode].label, to: SCENARIO_MODES[mode].label }))
}
function bulk(title: string, list: RecommendationChange[]) {
  if (!list.length) return
  pwError.value = null
  pending.value = { kind: 'bulk', title, changes: list }
}
const applyRecommendation = () => bulk('Empfehlung übernehmen?', changes.value)
const blockAll = () => bulk('Alle Szenarien auf „Sperren“ stellen?', changesTo('block'))
const observeAll = () => bulk('Alle Szenarien auf „Beobachten“ stellen?', changesTo('observe'))

// ---------------------------------------------------------------- one pending change at a time
type Pending = { kind: 'scenario', id: ScenarioId, mode: BehaviourMode } | { kind: 'bulk', title: string, changes: RecommendationChange[] }
const pending = ref<Pending | null>(null)
const pwError = ref<string | null>(null)
const update = useUpdateBehaviourSettings()
const pwOpen = computed({
  get: () => !!pending.value,
  set: (v) => {
    if (!v) {
      pending.value = null
      pwError.value = null
    }
  },
})

function modeOf(sc: ScenarioSetting): BehaviourMode {
  return pending.value?.kind === 'scenario' && pending.value.id === sc.id ? pending.value.mode : sc.mode
}
function setMode(sc: ScenarioSetting, mode: BehaviourMode) {
  if (mode === sc.mode) return
  pwError.value = null
  pending.value = { kind: 'scenario', id: sc.id, mode }
}

const dialog = computed(() => {
  const p = pending.value
  if (!p) return { title: '', confirm: 'Ändern', text: '' }
  if (p.kind === 'bulk') {
    const blocks = p.changes.some(c => c.mode === 'block')
    return {
      title: p.title,
      confirm: p.changes.length === 1 ? '1 Schalter ändern' : `${p.changes.length} Schalter ändern`,
      text: blocks ? 'Jede Sperre endet von selbst. Mobilfunk-, CGNAT- und Tor-Adressen und deine eigenen Adressen sperren Szenarien nie. Solange Schild den Normalzustand noch lernt oder im Testprofil läuft, zählen die Szenarien weiter nur mit.' : '',
    }
  }
  return {
    title: `„${SCENARIOS[p.id].name}“ auf „${SCENARIO_MODES[p.mode].label}“ stellen?`,
    confirm: 'Ändern',
    text: SCENARIO_MODES[p.mode].explain,
  }
})

function patchOf(p: Pending): BehaviourSettingsPatch {
  if (p.kind === 'scenario') return { scenarios: { [p.id]: p.mode } }
  const body: BehaviourSettingsPatch = {}
  for (const c of p.changes) body.scenarios = { ...body.scenarios, [c.id]: c.mode }
  return body
}
function successText(p: Pending): string {
  if (p.kind === 'scenario') return `${SCENARIOS[p.id].name}: ${SCENARIO_MODES[p.mode].label}`
  return p.changes.length === 1 ? '1 Schalter geändert' : `${p.changes.length} Schalter geändert`
}

// ---------------------------------------------------------------- thresholds (D93)
const thresholdsFor = ref<ScenarioId | null>(null)
const thresholdsScenario = computed(() => scenarios.value.find(x => x.id === thresholdsFor.value) ?? null)
const thresholdsOpen = computed({
  get: () => !!thresholdsFor.value,
  set: (v) => {
    if (!v) thresholdsFor.value = null
  },
})

async function confirm() {
  const p = pending.value
  if (!p) return
  pwError.value = null
  try {
    await update.mutateAsync(patchOf(p))
    pending.value = null
    toast.success(successText(p))
  }
  catch (err) {
    pwError.value = errorMessage(err)
  }
}
</script>

<template>
  <div class="space-y-6">
    <ErrorState v-if="q.isError.value && !s" title="Die Einstellungen lassen sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
    <div v-else-if="!s" class="space-y-3">
      <Skeleton v-for="i in 3" :key="i" class="h-28 w-full" />
    </div>
    <template v-else>
      <Card data-testid="scenarios-card">
        <CardHeader>
          <CardTitle>Szenarien</CardTitle>
          <CardDescription>
            Muster, die erst über mehrere Anfragen sichtbar werden. Schild zählt sie nur auf diesem Server. Nichts davon verlässt ihn.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-3">
          <div class="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border p-3" data-testid="recommendation">
            <CircleCheck v-if="!changes.length" class="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <p class="min-w-48 flex-1 text-sm" data-testid="recommendation-text">
              <template v-if="!changes.length">
                Alle Schalter stehen auf der Empfehlung.
              </template>
              <template v-else>
                <span class="font-medium">Empfehlung: {{ recommendedBlocking }} von {{ scenarios.length }} Szenarien sperren.</span>
                {{ changes.length === 1 ? '1 Schalter weicht davon ab.' : `${changes.length} Schalter weichen davon ab.` }}
              </template>
            </p>
            <div class="flex items-center gap-1">
              <Button v-if="changes.length" size="sm" data-testid="apply-recommendation" @click="applyRecommendation">
                Empfehlung übernehmen
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger as-child>
                  <Button size="icon-sm" variant="ghost" aria-label="Alle Szenarien auf einmal umstellen" data-testid="scenarios-more">
                    <Ellipsis aria-hidden="true" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem :disabled="!changesTo('block').length" data-testid="scenarios-block-all" @select="blockAll">
                    <ShieldBan aria-hidden="true" />
                    Alle Szenarien sperren
                  </DropdownMenuItem>
                  <DropdownMenuItem :disabled="!changesTo('observe').length" data-testid="scenarios-observe-all" @select="observeAll">
                    <Eye aria-hidden="true" />
                    Alle Szenarien beobachten
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
          <p v-if="learning && !noneBlocking" class="flex items-start gap-2 rounded-lg bg-muted p-2.5 text-sm" data-testid="scenarios-learning">
            <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span>Schild lernt noch<template v-if="s.learning_until"> bis {{ formatDay(s.learning_until) }}</template>, was auf diesem Server normal ist. Bis dahin sperrt kein Szenario, auch auf „Sperren“ nicht. Was es gesperrt hätte, steht unter <RouterLink to="/blocks?view=hits" class="underline underline-offset-4">Sperren › Verlauf</RouterLink> als „Erkannt“. Limits wirken sofort.</span>
          </p>
          <p v-if="noneBlocking" class="flex items-start gap-2 rounded-lg bg-muted p-2.5 text-sm" data-testid="scenarios-none-blocking">
            <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span>Gerade sperrt kein Szenario eine Adresse. Was auffällt, steht unter <RouterLink to="/blocks?view=hits" class="underline underline-offset-4">Sperren › Verlauf</RouterLink> als „Erkannt“. Gesperrt wird erst, wenn du ein Szenario auf „Sperren“ stellst.</span>
          </p>
          <ul class="divide-y rounded-xl border" aria-label="Szenarien">
            <li v-for="sc in scenarios" :key="sc.id" class="grid gap-3 p-4" data-testid="scenario-row" :data-scenario="sc.id">
              <div class="space-y-1">
                <p class="font-semibold">
                  {{ SCENARIOS[sc.id].name }}
                </p>
                <p class="text-sm text-muted-foreground">
                  {{ SCENARIOS[sc.id].description }}
                </p>
              </div>
              <div class="grid gap-1">
                <SegmentedControl :model-value="modeOf(sc)" :options="scenarioOptions(sc)" :label="`Schalter für ${SCENARIOS[sc.id].name}`" @update:model-value="(m: BehaviourMode) => setMode(sc, m)" />
                <p v-if="RECOMMENDED_WHY[sc.id]" class="text-xs text-muted-foreground" data-testid="scenario-recommended-why">
                  Empfohlen: {{ SCENARIO_MODES[sc.recommended].label }}. {{ RECOMMENDED_WHY[sc.id] }}
                </p>
              </div>
              <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                <MetaLine
                  :items="[
                    `Schwelle: ${thresholdsText(sc.id, sc.thresholds)}${thresholdsChanged(sc) ? ' (angepasst)' : ''}`,
                    `24 h: ${scenarioCountsText(sc)}`,
                    sc.blocks_active ? { text: activeBlocksText(sc.blocks_active), tone: 'warning' } : '',
                  ]"
                  data-testid="scenario-meta"
                />
                <Button size="sm" variant="ghost" :data-testid="`scenario-${sc.id}-thresholds`" @click="thresholdsFor = sc.id">
                  <SlidersHorizontal aria-hidden="true" />
                  Schwelle anpassen
                </Button>
              </div>
            </li>
          </ul>
        </CardContent>
      </Card>

      <div class="grid gap-4 text-sm md:grid-cols-3" data-testid="behaviour-rules">
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Sperren enden von selbst
          </p>
          <p class="mt-1 text-muted-foreground" data-testid="ladder">
            Wer wiederholt auffällt, wird länger gesperrt: {{ ladderText(s.block_steps_s, s.block_cap_s) }}. Jede Sperre endet von selbst.
          </p>
          <p v-if="s.hosting_block_steps_s?.length && s.hosting_block_cap_s" class="mt-1 text-muted-foreground" data-testid="ladder-hosting">
            Adressen aus Rechenzentren: {{ ladderText(s.hosting_block_steps_s, s.hosting_block_cap_s) }}. Sperren über einen Tag überstehen einen Neustart.
          </p>
        </div>
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Mobilfunk und geteilte Adressen
          </p>
          <p class="mt-1 text-muted-foreground">
            Adressen aus dem Mobilfunk, hinter <Term k="cgnat">CGNAT</Term> oder von Tor teilen sich viele Menschen. Szenarien und Limits sperren sie nie.
          </p>
        </div>
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Deine eigenen Adressen
          </p>
          <p class="mt-1 text-muted-foreground">
            Was unter „Eigene IPs“ steht, sperrt Schild nie. Die Regeln prüfen diese Anfragen weiter (außer bei „Filter überspringen“) und zeigen Treffer als „Erkannt“.
          </p>
        </div>
      </div>
    </template>

    <ScenarioThresholdsDialog v-model:open="thresholdsOpen" :scenario="thresholdsScenario" />

    <ConfirmDialog
      v-model:open="pwOpen"
      :title="dialog.title"
      :confirm-label="dialog.confirm"
      :pending="update.isPending.value"
      :error="pwError"
      @confirm="confirm"
    >
      {{ dialog.text }}
      <template v-if="pending?.kind === 'bulk'" #details>
        <ul class="grid gap-1 text-sm" data-testid="bulk-changes">
          <li v-for="c in pending.changes" :key="c.name">
            <span class="font-medium">{{ c.name }}:</span> {{ c.from }} → {{ c.to }}
          </li>
        </ul>
      </template>
    </ConfirmDialog>
  </div>
</template>
