<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { DetectorId, DetectorSetting, DistributedMode } from '@/api/distributed'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ErrorState, MetaLine, SegmentedControl, Skeleton, toast } from '@schild/ui'
import { Info, SlidersHorizontal } from '@lucide/vue'
import { computed, ref } from 'vue'
import { errorMessage } from '@/api/client'
import { useDistributedSettings, useUpdateDistributedSettings } from '@/api/distributed'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import DetectorThresholdsDialog from '@/components/DetectorThresholdsDialog.vue'
import { formatDuration } from '@/lib/behaviour'
import { DETECTOR_ORDER, DETECTORS, detectorThresholdsChanged, detectorThresholdsText, DISTRIBUTED_MODES, effectiveNote, FINGERPRINT_KINDS, formatDay, responseText, wavesCountText } from '@/lib/distributed'

/** Per-detector switches (Aus / Beobachten / Reagieren), their thresholds (D97) and the responses, read-only. */
const q = useDistributedSettings()
const s = computed(() => q.data.value)
const detectors = computed(() => {
  const list = s.value?.detectors ?? []
  return DETECTOR_ORDER.map(id => list.find(x => x.id === id)).filter((x): x is DetectorSetting => !!x)
})
const learning = computed(() => !!s.value?.learning_until && Date.parse(s.value.learning_until) > Date.now())

const options = (id: DetectorId): SegmentOption<DistributedMode>[] => (['off', 'observe', 'respond'] as const).map(m => ({
  value: m,
  label: DISTRIBUTED_MODES[m].label,
  tone: m === 'respond' ? 'ink' : m === 'off' ? 'neutral' : 'signal',
  testid: `detector-${id}-${m}`,
}))

// ---------------------------------------------------------------- one pending change at a time
const pending = ref<{ id: DetectorId, mode: DistributedMode } | null>(null)
const pwError = ref<string | null>(null)
const update = useUpdateDistributedSettings()
const pwOpen = computed({
  get: () => !!pending.value,
  set: (v) => {
    if (!v) {
      pending.value = null
      pwError.value = null
    }
  },
})
function modeOf(d: DetectorSetting): DistributedMode {
  return pending.value?.id === d.id ? pending.value.mode : d.mode
}
function setMode(d: DetectorSetting, mode: DistributedMode) {
  if (mode === d.mode) return
  pwError.value = null
  pending.value = { id: d.id, mode }
}
const dialog = computed(() => {
  const p = pending.value
  if (!p) return { title: '', text: '' }
  const later = p.mode === 'respond' && s.value && (s.value.gateway_observe || learning.value)
  return {
    title: `„${DETECTORS[p.id].name}“ auf „${DISTRIBUTED_MODES[p.mode].label}“ stellen?`,
    text: later
      ? `${DISTRIBUTED_MODES.respond.explain} ${s.value!.gateway_observe ? 'Im Testprofil beobachtet die Erkennung nur.' : 'Solange Schild noch lernt, beobachtet die Erkennung nur.'}`
      : DISTRIBUTED_MODES[p.mode].explain,
  }
})

// ---------------------------------------------------------------- thresholds (D97)
const thresholdsFor = ref<DetectorId | null>(null)
const thresholdsDetector = computed(() => detectors.value.find(x => x.id === thresholdsFor.value) ?? null)
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
    await update.mutateAsync({ detectors: { [p.id]: p.mode } })
    pending.value = null
    toast.success(`${DETECTORS[p.id].name}: ${DISTRIBUTED_MODES[p.mode].label}`)
  }
  catch (err) {
    pwError.value = errorMessage(err)
  }
}
</script>

<template>
  <div class="space-y-6">
    <ErrorState v-if="q.isError.value && !s" title="Die Erkennungen lassen sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />
    <div v-else-if="!s" class="space-y-3">
      <Skeleton v-for="i in 2" :key="i" class="h-28 w-full" />
    </div>
    <template v-else>
      <Card data-testid="detectors-card">
        <CardHeader>
          <CardTitle>Erkennungen</CardTitle>
          <CardDescription>
            Sie zählen nach Ziel, Fingerabdruck und Anfrageform statt nach Adresse. So fallen auch Angriffe auf, deren Adressen ständig wechseln. Gezählt wird nur auf diesem Server.
          </CardDescription>
        </CardHeader>
        <CardContent class="space-y-4">
          <p v-if="s.gateway_observe" class="flex items-start gap-2 rounded-lg bg-muted p-2.5 text-sm" data-testid="detectors-gateway-observe">
            <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span>Das Gateway läuft im Testprofil. Die Erkennungen zeigen nur, wie sie reagiert hätten.</span>
          </p>
          <p v-else-if="learning" class="flex items-start gap-2 rounded-lg bg-muted p-2.5 text-sm" data-testid="detectors-learning">
            <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span>Schild lernt bis {{ formatDay(s.learning_until!) }}, was auf dieser Website normal ist (mindestens {{ s.learning_days }} Tage). Wo der Normalzustand noch fehlt, beobachten die Erkennungen nur.</span>
          </p>
          <ul class="divide-y rounded-xl border" aria-label="Erkennungen">
            <li v-for="d in detectors" :key="d.id" class="grid gap-3 p-4" data-testid="detector-row" :data-detector="d.id">
              <div class="space-y-1">
                <p class="font-semibold">
                  {{ DETECTORS[d.id].name }}
                </p>
                <p class="text-sm text-muted-foreground">
                  {{ DETECTORS[d.id].description }}
                </p>
              </div>
              <SegmentedControl :model-value="modeOf(d)" :options="options(d.id)" :label="`Schalter für ${DETECTORS[d.id].name}`" @update:model-value="(m: DistributedMode) => setMode(d, m)" />
              <p v-if="effectiveNote(d, s)" class="flex items-start gap-2 text-sm" data-testid="detector-effective">
                <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span>{{ effectiveNote(d, s) }}</span>
              </p>
              <div class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                <MetaLine :items="[`Schwelle: ${detectorThresholdsText(d.id, d.thresholds)}${detectorThresholdsChanged(d) ? ' (angepasst)' : ''}`, `24 h: ${wavesCountText(d.waves_24h)}`]" data-testid="detector-meta" />
                <Button size="sm" variant="ghost" :data-testid="`detector-${d.id}-thresholds`" @click="thresholdsFor = d.id">
                  <SlidersHorizontal aria-hidden="true" />
                  Schwelle anpassen
                </Button>
              </div>
            </li>
          </ul>
        </CardContent>
      </Card>

      <div class="grid gap-4 text-sm md:grid-cols-2" data-testid="distributed-responses">
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Route einschränken
          </p>
          <p class="mt-1 text-muted-foreground" data-testid="response-route-tighten">
            Für {{ formatDuration(s.route_tighten.minutes * 60) }}, höchstens {{ formatDuration(s.route_tighten.max_minutes * 60) }}. {{ responseText({ response: 'route_tighten', route: '/login', until: null }, s) }}. Wer schon angemeldet ist, kommt durch.
          </p>
        </div>
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Konten verlangsamen
          </p>
          <p class="mt-1 text-muted-foreground" data-testid="response-account-slowdown">
            {{ responseText({ response: 'account_slowdown', route: '', until: null }, s) }}.
          </p>
        </div>
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Fingerabdruck
          </p>
          <p class="mt-1 text-muted-foreground" data-testid="fingerprint-kind">
            Schild nutzt hier {{ FINGERPRINT_KINDS[s.fingerprint_kind].label }}. {{ FINGERPRINT_KINDS[s.fingerprint_kind].explain }}
          </p>
        </div>
        <div class="rounded-xl border p-4">
          <p class="font-medium">
            Keine Sperre einzelner Adressen
          </p>
          <p class="mt-1 text-muted-foreground">
            Hinter wechselnden Adressen stecken oft Anschlüsse ahnungsloser Menschen. Darum gelten die Reaktionen nur für die Route, das Konto oder die Anfrageform und enden von selbst.
          </p>
        </div>
      </div>
      <p v-if="s.routes?.length" class="text-sm text-muted-foreground" data-testid="distributed-routes">
        Zusätzlich beobachtete Routen: <span class="font-mono">{{ s.routes.join(', ') }}</span>
      </p>
    </template>

    <DetectorThresholdsDialog v-model:open="thresholdsOpen" :detector="thresholdsDetector" />

    <ConfirmDialog
      v-model:open="pwOpen"
      :title="dialog.title"
      confirm-label="Ändern"
      :pending="update.isPending.value"
      :error="pwError"
      @confirm="confirm"
    >
      {{ dialog.text }}
    </ConfirmDialog>
  </div>
</template>
