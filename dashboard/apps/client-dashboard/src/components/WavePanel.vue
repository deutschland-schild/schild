<script setup lang="ts">
import { Button, ErrorState, formatDateTime, formatNumber, MetaLine, Skeleton, StatusPill, Tag, toast } from '@schild/ui'
import { KeyRound } from '@lucide/vue'
import { computed, onBeforeUnmount, ref } from 'vue'
import { errorMessage, problemOf } from '@/api/client'
import { useDistributedSettings, useEndWave, useWave } from '@/api/distributed'
import OutcomePill from '@/components/OutcomePill.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import { formatClock, formatDuration } from '@/lib/behaviour'
import { explainWave, FINGERPRINT_KINDS, remainingText, responseText, RESPONSES, shortSig, stoppedText, waveOutcome, waveTitle } from '@/lib/distributed'

/** One wave: what happened, the cluster, the response with its remaining time, recent requests and "Vorzeitig beenden". */
const props = defineProps<{ id: string }>()
const q = useWave(() => props.id)
const d = computed(() => q.data.value?.wave.id === props.id ? q.data.value : undefined)
const wave = computed(() => d.value?.wave)
const settings = useDistributedSettings()
const s = computed(() => settings.data.value)
const outcome = computed(() => wave.value ? waveOutcome(wave.value, s.value?.learning_until) : null)

const now = ref(Date.now())
const timer = setInterval(() => (now.value = Date.now()), 30_000)
onBeforeUnmount(() => clearInterval(timer))

const meta = computed(() => {
  const w = wave.value
  if (!w) return []
  return [formatDateTime(w.time), w.host ?? '', { text: w.route, mono: true }]
})

// ---------------------------------------------------------------- end early
const ending = ref(false)
const pwError = ref<string | null>(null)
const end = useEndWave()
const pwOpen = computed({
  get: () => ending.value,
  set: (v) => {
    ending.value = v
    if (!v) pwError.value = null
  },
})
async function confirmEnd() {
  const w = wave.value
  if (!w) return
  pwError.value = null
  try {
    const res = await end.mutateAsync({ id: w.id })
    ending.value = false
    toast.success('Reaktion beendet', { description: `${RESPONSES[res.response]}: aufgehoben. Die Erkennung läuft weiter.` })
  }
  catch (err) {
    ending.value = false
    if (problemOf(err)?.code === 'not_active') {
      toast('Diese Reaktion war schon beendet')
      void q.refetch()
      return
    }
    toast.error('Beenden hat nicht geklappt', { description: errorMessage(err) })
  }
}
</script>

<template>
  <div class="p-4 text-sm sm:p-5">
    <div v-if="!d && q.isPending.value" class="space-y-3">
      <Skeleton class="h-6 w-2/3" />
      <Skeleton class="h-4 w-full" />
      <Skeleton class="h-28 w-full" />
    </div>
    <ErrorState v-else-if="!d && q.isError.value" title="Diese Welle lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />

    <article v-else-if="d && wave && outcome" class="space-y-5" data-testid="wave-detail">
      <header class="space-y-2">
        <div class="flex flex-wrap items-center gap-2">
          <h2 class="text-base font-bold">
            {{ waveTitle(wave) }}
          </h2>
          <Tag tone="neutral">
            Welle
          </Tag>
          <StatusPill :tone="outcome.tone" size="sm" data-testid="wave-detail-outcome">
            {{ outcome.label }}
          </StatusPill>
        </div>
        <p class="text-[15px] leading-snug font-semibold" data-testid="wave-detail-explain">
          {{ explainWave(wave) }}.
        </p>
        <p v-if="outcome.reason" class="text-muted-foreground" data-testid="wave-detail-reason">
          {{ outcome.reason }}.
        </p>
        <MetaLine :items="meta" />
      </header>

      <section class="space-y-2 rounded-xl border p-4" aria-labelledby="wave-response" data-testid="wave-response">
        <h3 id="wave-response" class="font-semibold">
          {{ wave.action === 'observe' ? 'So hätte Schild reagiert' : 'Reaktion' }}
        </h3>
        <p data-testid="wave-response-text">
          {{ responseText(wave, s) }}.
        </p>
        <p v-if="wave.active && wave.until" class="tabular-nums text-muted-foreground" data-testid="wave-remaining">
          {{ remainingText(wave.until, now) }}, {{ stoppedText(wave.stopped) }}
        </p>
        <p v-else-if="wave.action === 'respond'" class="text-muted-foreground" data-testid="wave-ended">
          {{ wave.end_reason === 'operator' ? 'Vorzeitig beendet' : 'Abgelaufen' }}<template v-if="wave.ended_at">
            um {{ formatClock(wave.ended_at) }}
          </template>, {{ stoppedText(wave.stopped) }}
        </p>
        <p class="text-xs text-muted-foreground">
          Bei Wellen sperrt Schild keine Adressen. Die Reaktion gilt für die Route, das Konto oder die Anfrageform, für alle Absender gleich, und endet von selbst.
        </p>
        <Button v-if="wave.active" variant="outline" size="sm" data-testid="wave-end" @click="pwOpen = true">
          Vorzeitig beenden
        </Button>
      </section>

      <p v-if="wave.suggest_second_factor" class="flex items-start gap-2 rounded-xl bg-muted p-3" data-testid="wave-second-factor">
        <KeyRound class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span>Für Anmeldungen hilft auf Dauer am meisten: Passkeys oder ein zweiter Faktor in deiner Anwendung. Dann bringen auch richtig geratene Passwörter allein nichts.</span>
      </p>

      <section class="space-y-2" aria-labelledby="wave-cluster">
        <h3 id="wave-cluster" class="font-semibold">
          Was die Anfragen gemeinsam haben
        </h3>
        <dl class="grid gap-x-4 gap-y-2 rounded-xl border p-4 sm:grid-cols-[auto_1fr]" data-testid="wave-cluster">
          <dt class="text-muted-foreground">
            Absender
          </dt>
          <dd>{{ wave.senders === 1 ? '1 Adresse' : `${formatNumber(wave.senders)} verschiedene Adressen` }}</dd>
          <dt class="text-muted-foreground">
            Gezählt
          </dt>
          <dd>{{ formatNumber(wave.count) }} in {{ formatDuration(wave.window_s) }}, Schwelle {{ formatNumber(wave.threshold) }}</dd>
          <template v-if="wave.user_agents !== undefined">
            <dt class="text-muted-foreground">
              Browser-Angaben
            </dt>
            <dd>{{ wave.user_agents === 1 ? 'eine einzige' : `${formatNumber(wave.user_agents)} verschiedene` }}</dd>
          </template>
          <template v-if="wave.fingerprint">
            <dt class="text-muted-foreground">
              Fingerabdruck
            </dt>
            <dd class="space-y-1" data-testid="wave-fingerprint">
              <span class="font-mono">{{ wave.fingerprint }}</span>
              <template v-if="wave.fingerprint_kind">
                · {{ FINGERPRINT_KINDS[wave.fingerprint_kind].label }}
                <span class="block text-xs text-muted-foreground">{{ FINGERPRINT_KINDS[wave.fingerprint_kind].explain }} Die Kennung gilt nur auf diesem Server und nur für kurze Zeit.</span>
              </template>
            </dd>
          </template>
          <template v-if="wave.request_sig">
            <dt class="text-muted-foreground">
              Anfrageform
            </dt>
            <dd>
              <span class="font-mono">{{ shortSig(wave.request_sig) }}</span>
              <template v-if="wave.waf_rules?.length">
                · passt zu {{ wave.waf_rules.length === 1 ? 'Regel' : 'Regeln' }} <span class="font-mono">{{ wave.waf_rules.join(', ') }}</span>
              </template>
            </dd>
          </template>
        </dl>
        <p class="text-xs text-muted-foreground">
          Benutzernamen und Konten speichert Schild bei Wellen nicht.
        </p>
      </section>

      <section class="space-y-2" aria-labelledby="wave-requests">
        <h3 id="wave-requests" class="font-semibold">
          Letzte gespeicherte Anfragen an dieser Route
        </h3>
        <p v-if="!d.requests.length" class="text-muted-foreground">
          Zu dieser Welle sind keine einzelnen Anfragen gespeichert.
        </p>
        <ul v-else class="divide-y rounded-xl border" data-testid="wave-requests">
          <li v-for="r in d.requests" :key="r.id" class="grid gap-1 p-3 sm:grid-cols-[auto_1fr_auto] sm:items-center sm:gap-3">
            <time :datetime="r.time" class="text-xs text-muted-foreground tabular-nums">{{ formatClock(r.time) }}</time>
            <span class="min-w-0 font-mono text-[13px] break-all">{{ r.method }} {{ r.path }}<span v-if="r.status" class="text-muted-foreground"> → {{ r.status }}</span></span>
            <OutcomePill :outcome="r.outcome" />
          </li>
        </ul>
      </section>
    </article>

    <ConfirmDialog
      v-model:open="pwOpen"
      title="Reaktion vorzeitig beenden?"
      confirm-label="Beenden"
      :pending="end.isPending.value"
      :error="pwError"
      @confirm="confirmEnd"
    >
      Schild hebt die Einschränkung sofort auf. Die Erkennung läuft weiter und meldet sich, wenn wieder eine Welle kommt.
    </ConfirmDialog>
  </div>
</template>
