<script setup lang="ts">
import type { ScenarioSetting, ScenarioThresholdsPatch } from '@/api/behaviour'
import type { WindowUnit } from '@/lib/behaviour'
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Input, NativeSelect, NativeSelectOption, toast } from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { errorMessage, fieldErrors } from '@/api/client'
import { useUpdateBehaviourSettings } from '@/api/behaviour'
import { formatDuration, SCENARIOS, splitWindow, THRESHOLD_BOUNDS, thresholdsChanged, thresholdsText, WINDOW_UNITS, windowSeconds } from '@/lib/behaviour'

/** Thresholds of one scenario (D93): how many, in which time. Saving the built-in values removes the override. */
const props = defineProps<{ scenario: ScenarioSetting | null }>()
const open = defineModel<boolean>('open', { default: false })

const count = ref(0)
const windowN = ref(1)
const windowUnit = ref<WindowUnit>('m')
const slowCount = ref(0)
const slowN = ref(1)
const slowUnit = ref<WindowUnit>('h')
const factor = ref(0)
const touched = ref(false)
const server = ref<Record<string, string>>({})
const failed = ref<string | null>(null)

const id = computed(() => props.scenario?.id ?? 'path_probing')
const meta = computed(() => SCENARIOS[id.value])
const bounds = computed(() => THRESHOLD_BOUNDS[id.value])
const hasSlow = computed(() => !!props.scenario?.defaults.slow_count)
const hasFactor = computed(() => !!props.scenario?.defaults.baseline_factor)

function fill(t: ScenarioSetting['thresholds']) {
  count.value = t.count
  ;({ n: windowN.value, unit: windowUnit.value } = splitWindow(t.window_s))
  slowCount.value = t.slow_count ?? 0
  ;({ n: slowN.value, unit: slowUnit.value } = splitWindow(t.slow_window_s ?? 3600))
  factor.value = t.baseline_factor ?? 0
}
watch(open, (v) => {
  if (!v || !props.scenario) return
  fill(props.scenario.thresholds)
  touched.value = false
  server.value = {}
  failed.value = null
}, { immediate: true })

const values = computed<ScenarioSetting['thresholds']>(() => ({
  count: count.value,
  window_s: windowSeconds(windowN.value, windowUnit.value),
  ...(hasSlow.value ? { slow_count: slowCount.value, slow_window_s: windowSeconds(slowN.value, slowUnit.value) } : {}),
  ...(hasFactor.value ? { baseline_factor: factor.value } : {}),
}))
const atDefaults = computed(() => !props.scenario || !thresholdsChanged({ thresholds: values.value, defaults: props.scenario.defaults }))

const whole = (v: number, min: number, max: number) => Number.isInteger(v) && v >= min && v <= max
const errors = computed(() => {
  const b = bounds.value
  const v = values.value
  const at = (f: string) => server.value[`thresholds/${id.value}/${f}`]
  const check = touched.value
  return {
    count: at('count') || (check && !whole(v.count, b.minCount, 100000)) ? `Eine ganze Zahl zwischen ${b.minCount} und 100.000.` : null,
    window: at('window_s') || (check && !whole(v.window_s, b.minWindowS, b.maxWindowS)) ? `Ein Zeitraum zwischen ${formatDuration(b.minWindowS)} und ${formatDuration(b.maxWindowS)}.` : null,
    slowCount: hasSlow.value && (at('slow_count') || (check && !whole(v.slow_count ?? 0, 2, 100000))) ? 'Eine ganze Zahl zwischen 2 und 100.000.' : null,
    slowWindow: hasSlow.value && (at('slow_window_s') || (check && !whole(v.slow_window_s ?? 0, 60, 86400))) ? 'Ein Zeitraum zwischen 1 Minute und 24 Stunden.' : null,
    factor: hasFactor.value && (at('baseline_factor') || (check && !((v.baseline_factor ?? 0) >= 2 && (v.baseline_factor ?? 0) <= 1000))) ? 'Eine Zahl zwischen 2 und 1.000.' : null,
  }
})

const update = useUpdateBehaviourSettings()
async function submit() {
  const sc = props.scenario
  if (!sc) return
  touched.value = true
  server.value = {}
  failed.value = null
  if (Object.values(errors.value).some(Boolean)) return
  const body: ScenarioThresholdsPatch = atDefaults.value ? {} : values.value
  try {
    await update.mutateAsync({ thresholds: { [sc.id]: body } })
    open.value = false
    toast.success(`Schwelle für „${meta.value.name}“ ${atDefaults.value ? 'steht wieder auf dem Werkswert' : 'geändert'}`, { description: `${thresholdsText(sc.id, values.value)}.` })
  }
  catch (err) {
    server.value = fieldErrors(err)
    if (!Object.keys(server.value).length) failed.value = errorMessage(err)
  }
}
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
      <form v-if="scenario" class="grid gap-5" novalidate data-testid="thresholds-form" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>Schwelle für „{{ meta.name }}“</DialogTitle>
          <DialogDescription>
            Ab wann das Szenario anschlägt. Eine niedrigere Schwelle schlägt früher an und trifft eher auch normale Besucher:innen. Sie gilt für alle Websites auf diesem Server.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-2">
          <span class="text-sm font-medium">Schwelle</span>
          <div class="flex flex-wrap items-center gap-2 text-sm">
            <span>mindestens</span>
            <Input v-model.number="count" type="number" :min="bounds.minCount" max="100000" class="w-24" :aria-label="`Anzahl: ${meta.many}`" :aria-invalid="!!errors.count" data-testid="thresholds-count" />
            <span>{{ meta.many }} in</span>
            <Input v-model.number="windowN" type="number" min="1" class="w-20" aria-label="Zeitraum" :aria-invalid="!!errors.window" data-testid="thresholds-window-n" />
            <NativeSelect v-model="windowUnit" aria-label="Einheit des Zeitraums" data-testid="thresholds-window-unit">
              <NativeSelectOption v-for="u in WINDOW_UNITS" :key="u.value" :value="u.value">
                {{ u.label }}
              </NativeSelectOption>
            </NativeSelect>
          </div>
          <p v-if="errors.count || errors.window" class="text-sm text-destructive" role="alert">
            {{ errors.count ?? errors.window }}
          </p>
        </div>

        <div v-if="hasSlow" class="grid gap-2">
          <span class="text-sm font-medium">Oder langsamer, über längere Zeit</span>
          <div class="flex flex-wrap items-center gap-2 text-sm">
            <span>mindestens</span>
            <Input v-model.number="slowCount" type="number" min="2" max="100000" class="w-24" :aria-label="`Anzahl über längere Zeit: ${meta.many}`" :aria-invalid="!!errors.slowCount" data-testid="thresholds-slow-count" />
            <span>{{ meta.many }} in</span>
            <Input v-model.number="slowN" type="number" min="1" class="w-20" aria-label="Längerer Zeitraum" :aria-invalid="!!errors.slowWindow" data-testid="thresholds-slow-window-n" />
            <NativeSelect v-model="slowUnit" aria-label="Einheit des längeren Zeitraums" data-testid="thresholds-slow-window-unit">
              <NativeSelectOption v-for="u in WINDOW_UNITS" :key="u.value" :value="u.value">
                {{ u.label }}
              </NativeSelectOption>
            </NativeSelect>
          </div>
          <p v-if="errors.slowCount || errors.slowWindow" class="text-sm text-destructive" role="alert">
            {{ errors.slowCount ?? errors.slowWindow }}
          </p>
        </div>

        <div v-if="hasFactor" class="grid gap-2">
          <span class="text-sm font-medium">Und deutlich mehr als üblich</span>
          <div class="flex flex-wrap items-center gap-2 text-sm">
            <span>mindestens das</span>
            <Input v-model.number="factor" type="number" min="2" max="1000" step="any" class="w-24" aria-label="Vielfaches des Üblichen" :aria-invalid="!!errors.factor" data-testid="thresholds-factor" />
            <span>-Fache dessen, was auf der Website üblich ist</span>
          </div>
          <p v-if="errors.factor" class="text-sm text-destructive" role="alert">
            {{ errors.factor }}
          </p>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl border bg-muted p-3 text-sm">
          <p data-testid="thresholds-defaults">
            <span class="font-medium">Ab Werk:</span> {{ thresholdsText(scenario.id, scenario.defaults) }}
          </p>
          <Button v-if="!atDefaults" type="button" variant="outline" size="sm" data-testid="thresholds-reset" @click="fill(scenario.defaults)">
            Werkswert einsetzen
          </Button>
        </div>

        <p v-if="failed" class="text-sm text-destructive" role="alert" data-testid="thresholds-error">
          {{ failed }}
        </p>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="update.isPending.value" data-testid="thresholds-submit">
            {{ update.isPending.value ? 'Wird gespeichert …' : 'Speichern' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
