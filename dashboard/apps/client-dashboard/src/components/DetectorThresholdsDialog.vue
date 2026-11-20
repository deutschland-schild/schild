<script setup lang="ts">
import type { DetectorSetting } from '@/api/distributed'
import type { WindowUnit } from '@/lib/behaviour'
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Input, NativeSelect, NativeSelectOption, toast } from '@schild/ui'
import { computed, ref, watch } from 'vue'
import { errorMessage, fieldErrors } from '@/api/client'
import { useUpdateDistributedSettings } from '@/api/distributed'
import { splitWindow, WINDOW_UNITS, windowSeconds } from '@/lib/behaviour'
import { DETECTOR_COUNTED, DETECTORS, detectorThresholdsChanged, detectorThresholdsText } from '@/lib/distributed'

/** Thresholds of one wave detector (D97): how many, in which time. Saving the built-in values removes the override. */
const props = defineProps<{ detector: DetectorSetting | null }>()
const open = defineModel<boolean>('open', { default: false })

// The config schema allows 30 seconds to 1 hour, so hours are no unit here.
const UNITS = WINDOW_UNITS.filter(u => u.value !== 'h')
const count = ref(0)
const windowN = ref(1)
const windowUnit = ref<WindowUnit>('m')
const factor = ref(0)
const touched = ref(false)
const server = ref<Record<string, string>>({})
const failed = ref<string | null>(null)

const id = computed(() => props.detector?.id ?? 'route_wave')
const hasFactor = computed(() => !!props.detector?.defaults.factor)

function fill(t: DetectorSetting['thresholds']) {
  count.value = t.count
  const w = splitWindow(t.window_s)
  // A whole hour reads as 60 minutes in this form.
  ;[windowN.value, windowUnit.value] = w.unit === 'h' ? [w.n * 60, 'm'] : [w.n, w.unit]
  factor.value = t.factor ?? 0
}
watch(open, (v) => {
  if (!v || !props.detector) return
  fill(props.detector.thresholds)
  touched.value = false
  server.value = {}
  failed.value = null
}, { immediate: true })

const values = computed<DetectorSetting['thresholds']>(() => ({
  count: count.value,
  window_s: windowSeconds(windowN.value, windowUnit.value),
  ...(hasFactor.value ? { factor: factor.value } : {}),
}))
const atDefaults = computed(() => !props.detector || !detectorThresholdsChanged({ thresholds: values.value, defaults: props.detector.defaults }))

const whole = (v: number, min: number, max: number) => Number.isInteger(v) && v >= min && v <= max
const errors = computed(() => {
  const v = values.value
  const at = (f: string) => server.value[`thresholds/${id.value}/${f}`]
  const check = touched.value
  return {
    count: at('count') || (check && !whole(v.count, 3, 100000)) ? 'Eine ganze Zahl zwischen 3 und 100.000.' : null,
    window: at('window_s') || (check && !whole(v.window_s, 30, 3600)) ? 'Ein Zeitraum zwischen 30 Sekunden und 60 Minuten.' : null,
    factor: hasFactor.value && (at('factor') || (check && !((v.factor ?? 0) >= 2 && (v.factor ?? 0) <= 1000))) ? 'Eine Zahl zwischen 2 und 1.000.' : null,
  }
})

const update = useUpdateDistributedSettings()
async function submit() {
  const d = props.detector
  if (!d) return
  touched.value = true
  server.value = {}
  failed.value = null
  if (Object.values(errors.value).some(Boolean)) return
  try {
    await update.mutateAsync({ thresholds: { [d.id]: atDefaults.value ? {} : values.value } })
    open.value = false
    toast.success(`Schwelle für „${DETECTORS[d.id].name}“ ${atDefaults.value ? 'steht wieder auf dem Werkswert' : 'geändert'}`, { description: `${detectorThresholdsText(d.id, values.value)}.` })
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
      <form v-if="detector" class="grid gap-5" novalidate data-testid="detector-thresholds-form" @submit.prevent="submit">
        <DialogHeader>
          <DialogTitle>Schwelle für „{{ DETECTORS[detector.id].name }}“</DialogTitle>
          <DialogDescription>
            Ab wann Schild eine Welle erkennt. Eine niedrigere Schwelle schlägt früher an und hält eher auch einen normalen Ansturm für einen Angriff. Sie gilt für alle Websites auf diesem Server.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-2">
          <span class="text-sm font-medium">Schwelle</span>
          <div class="flex flex-wrap items-center gap-2 text-sm">
            <span>mindestens</span>
            <Input v-model.number="count" type="number" min="3" max="100000" class="w-24" :aria-label="`Anzahl: ${DETECTOR_COUNTED[detector.id]}`" :aria-invalid="!!errors.count" data-testid="detector-thresholds-count" />
            <span>{{ DETECTOR_COUNTED[detector.id] }} in</span>
            <Input v-model.number="windowN" type="number" min="1" class="w-20" aria-label="Zeitraum" :aria-invalid="!!errors.window" data-testid="detector-thresholds-window-n" />
            <NativeSelect v-model="windowUnit" aria-label="Einheit des Zeitraums" data-testid="detector-thresholds-window-unit">
              <NativeSelectOption v-for="u in UNITS" :key="u.value" :value="u.value">
                {{ u.label }}
              </NativeSelectOption>
            </NativeSelect>
          </div>
          <p v-if="errors.count || errors.window" class="text-sm text-destructive" role="alert">
            {{ errors.count ?? errors.window }}
          </p>
        </div>

        <div v-if="hasFactor" class="grid gap-2">
          <span class="text-sm font-medium">Und deutlich mehr als üblich</span>
          <div class="flex flex-wrap items-center gap-2 text-sm">
            <span>mindestens das</span>
            <Input v-model.number="factor" type="number" min="2" max="1000" step="any" class="w-24" aria-label="Vielfaches des Üblichen" :aria-invalid="!!errors.factor" data-testid="detector-thresholds-factor" />
            <span>-Fache dessen, was auf dieser Route üblich ist</span>
          </div>
          <p v-if="errors.factor" class="text-sm text-destructive" role="alert">
            {{ errors.factor }}
          </p>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl border bg-muted p-3 text-sm">
          <p data-testid="detector-thresholds-defaults">
            <span class="font-medium">Ab Werk:</span> {{ detectorThresholdsText(detector.id, detector.defaults) }}
          </p>
          <Button v-if="!atDefaults" type="button" variant="outline" size="sm" data-testid="detector-thresholds-reset" @click="fill(detector.defaults)">
            Werkswert einsetzen
          </Button>
        </div>

        <p v-if="failed" class="text-sm text-destructive" role="alert">
          {{ failed }}
        </p>

        <DialogFooter>
          <Button type="button" variant="outline" @click="open = false">
            Abbrechen
          </Button>
          <Button type="submit" :disabled="update.isPending.value" data-testid="detector-thresholds-submit">
            {{ update.isPending.value ? 'Wird gespeichert …' : 'Speichern' }}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>
