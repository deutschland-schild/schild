<script setup lang="ts">
import { incidentBlockText } from '@/lib/websites'
import type { ReleaseRequest } from '@/api/behaviour'
import {
  Button,
  countryName,
  ErrorState,
  formatDateTime,
  formatRelative,
  Label,
  MetaLine,
  NativeSelect,
  NativeSelectOption,
  Skeleton,
  StatusPill,
  Tag,
  toast,
} from '@schild/ui'
import { computed, ref, useId } from 'vue'
import { errorMessage } from '@/api/client'
import { useBehaviourHit, useBehaviourSettings, useRateLimits, useReleaseClient, useUpdateBehaviourSettings } from '@/api/behaviour'
import OutcomePill from '@/components/OutcomePill.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import Term from '@/components/Term.vue'
import { blockRunning, blockSourceText, canRelease, explainHit, formatClock, hitOutcome, hitTitle, PRESETS, SCENARIO_MODES, SCENARIOS } from '@/lib/behaviour'

/** One behaviour or rate limit hit: what happened, the recent requests, running blocks and the release actions. */
const props = defineProps<{ id: string }>()
const q = useBehaviourHit(() => props.id)
const d = computed(() => q.data.value?.hit.id === props.id ? q.data.value : undefined)
const hit = computed(() => d.value?.hit)
const outcome = computed(() => hit.value ? hitOutcome(hit.value) : null)
/** "Laufende Sperren" lists only blocks without ended_at (a block that ended, also with a restart, is gone). */
const runningBlocks = computed(() => (d.value?.blocks ?? []).filter(b => blockRunning(b)))
const limits = useRateLimits()
const limitLabel = (id: string) => limits.data.value?.items.find(l => l.id === id)?.label
/** "dieses Szenario" / "dieses Limit" with its name. */
const narrowName = computed(() => {
  const h = hit.value
  if (!h) return ''
  return h.kind === 'rate_limit' ? `das Limit „${h.limit_label ?? h.limit_id}“` : `das Szenario „${h.scenario ? SCENARIOS[h.scenario].name : ''}“`
})

const meta = computed(() => {
  const h = hit.value
  if (!h) return []
  return [
    formatDateTime(h.time),
    h.host ?? '',
    h.preset ? PRESETS[h.preset] : '',
    h.geo ? `${countryName(h.geo.country)}${h.geo.as_org ? `, ${h.geo.as_org}` : ''}` : '',
    // "Szenario", not "Modus": each scenario has its own switch (initiator 2026-11-12).
    h.kind === 'scenario' ? `Szenario: ${SCENARIO_MODES[h.mode].label}` : '',
  ]
})

// ---------------------------------------------------------------- why nothing was blocked
const settings = useBehaviourSettings()
const updateSettings = useUpdateBehaviourSettings()
/** The scenario only counted because its own switch stood on "Beobachten"; every other case has its reason line. */
const observed = computed(() => {
  const h = hit.value
  if (!h || h.kind !== 'scenario' || !h.scenario || h.mode !== 'observe' || h.action !== 'observe' || h.reason || h.released) return null
  return { id: h.scenario, name: SCENARIOS[h.scenario].name, now: settings.data.value?.scenarios.find(sc => sc.id === h.scenario)?.mode }
})
const blockOpen = ref(false)
const blockError = ref<string | null>(null)
async function switchToBlock() {
  const o = observed.value
  if (!o) return
  blockError.value = null
  try {
    await updateSettings.mutateAsync({ scenarios: { [o.id]: 'block' } })
    blockOpen.value = false
    toast.success(`${o.name}: ${SCENARIO_MODES.block.label}`)
  }
  catch (err) {
    blockError.value = errorMessage(err)
  }
}

// ---------------------------------------------------------------- release, exception, permanent 
type Purpose = 'none' | 'exception' | 'permanent'
const purpose = ref<Purpose | null>(null)
const ttl = ref<'24h' | '7d' | '30d'>('7d')
const pwError = ref<string | null>(null)
const ttlId = useId()
const release = useReleaseClient()
const pwOpen = computed({
  get: () => !!purpose.value,
  set: (v) => {
    if (!v) {
      purpose.value = null
      pwError.value = null
    }
  },
})
function ask(p: Purpose) {
  pwError.value = null
  ttl.value = '7d'
  purpose.value = p
}
const TTL_LABELS = { '24h': '24 Stunden', '7d': '7 Tage', '30d': '30 Tage' } as const
const dialog = computed(() => {
  const ip = hit.value?.ip ?? ''
  switch (purpose.value) {
    case 'exception': return {
      title: `Ausnahme für ${ip}?`,
      confirm: 'Ausnahme anlegen',
      text: `Schild beendet die laufenden Sperren dieser Adresse und lässt ${narrowName.value} für sie eine Weile aus. Alle anderen Szenarien, Limits und die Regeln des Filters gelten weiter.`,
    }
    case 'permanent': return {
      title: `${ip} dauerhaft erlauben?`,
      confirm: 'Dauerhaft erlauben',
      text: 'Schild trägt die Adresse bei „Eigene IPs“ ein (Nie sperren, ohne Ablauf). Szenarien und Limits sperren sie dann nie mehr. Die Regeln des Filters prüfen ihre Anfragen weiter. Das passt für eigene Rechner, das Büro oder Monitoring.',
    }
    default: return {
      title: `${ip} freigeben?`,
      confirm: 'Freigeben',
      text: 'Schild beendet die laufenden Sperren dieser Adresse und setzt ihre Zähler zurück. Fällt sie wieder auf, gilt alles wie vorher.',
    }
  }
})

async function confirm() {
  const h = hit.value
  if (!h?.ip || !purpose.value) return
  pwError.value = null
  const body: ReleaseRequest = {
    ip: h.ip,
    allow: purpose.value,
    ttl: ttl.value,
    ...(purpose.value === 'exception' ? (h.kind === 'rate_limit' ? { limit_id: h.limit_id } : { scenario: h.scenario }) : {}),
    ...(purpose.value === 'permanent' ? { label: `Erlaubt bei ${hitTitle(h)}`.slice(0, 64) } : {}),
  }
  const p = purpose.value
  try {
    const res = await release.mutateAsync(body)
    purpose.value = null
    const ended = res.blocks_ended === 1 ? '1 Sperre beendet.' : res.blocks_ended ? `${res.blocks_ended} Sperren beendet.` : 'Es lief keine Sperre.'
    if (p === 'exception') {
      toast.success(`Ausnahme für ${res.ip} angelegt`, { description: `${ended} ${res.exception_until ? `Gilt bis ${formatDateTime(res.exception_until)}.` : ''}`.trim() })
    }
    else if (p === 'permanent') {
      toast.success(`${res.ip} ist dauerhaft erlaubt`, { description: `${ended} Der Eintrag steht jetzt bei „Eigene IPs“.` })
    }
    else {
      toast.success(`${res.ip} ist freigegeben`, { description: ended })
    }
  }
  catch (err) {
    pwError.value = errorMessage(err)
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
    <ErrorState v-else-if="!d && q.isError.value" title="Dieser Treffer lässt sich gerade nicht laden" :description="errorMessage(q.error.value)" @retry="q.refetch()" />

    <article v-else-if="d && hit && outcome" class="space-y-5" data-testid="hit-detail">
      <header class="space-y-2">
        <div class="flex flex-wrap items-center gap-2">
          <h2 class="text-base font-bold">
            {{ hitTitle(hit) }}
          </h2>
          <Tag :tone="hit.kind === 'rate_limit' ? 'info' : 'neutral'">
            {{ hit.kind === 'rate_limit' ? 'Limit' : 'Szenario' }}
          </Tag>
          <StatusPill :tone="outcome.tone" size="sm" data-testid="hit-detail-outcome">
            {{ outcome.label }}
          </StatusPill>
        </div>
        <p class="text-[15px] leading-snug font-semibold" data-testid="hit-detail-explain">
          {{ explainHit(hit) }}.
        </p>
        <p v-if="outcome.reason" class="text-muted-foreground" data-testid="hit-detail-reason">
          {{ outcome.reason[0]!.toUpperCase() + outcome.reason.slice(1) }}.
          <Term v-if="hit.reason === 'net_class'" k="cgnat">Warum?</Term>
        </p>
        <MetaLine :items="meta" />
        <p v-if="hit.incident" class="text-xs text-muted-foreground">
          <Term k="incident">Vorfallnummer</Term>: <span class="font-mono">{{ hit.incident }}</span>
        </p>
      </header>

      <section v-if="observed" class="space-y-2 rounded-xl border bg-muted p-4" aria-labelledby="hit-observed" data-testid="hit-observed">
        <h3 id="hit-observed" class="font-semibold">
          Warum wurde hier nichts gesperrt?
        </h3>
        <p>
          Das Szenario „{{ observed.name }}“ stand auf „Beobachten“. Schild hat gezählt und gezeigt, was es gesperrt hätte. Jedes Szenario hat seinen eigenen Schalter.
        </p>
        <p v-if="observed.now && observed.now !== 'observe'" class="text-muted-foreground" data-testid="hit-observed-now">
          Inzwischen steht es auf „{{ SCENARIO_MODES[observed.now].label }}“.
        </p>
        <Button v-if="observed.now && observed.now !== 'block'" variant="outline" size="sm" data-testid="hit-observed-block" @click="blockOpen = true">
          Szenario auf „Sperren“ stellen
        </Button>
      </section>

      <section v-if="runningBlocks.length" class="space-y-2" aria-labelledby="hit-blocks">
        <h3 id="hit-blocks" class="font-semibold">
          Laufende Sperren dieser Adresse
        </h3>
        <ul class="divide-y rounded-xl border" data-testid="hit-blocks">
          <li v-for="b in runningBlocks" :key="b.source + b.until" class="flex flex-wrap items-center justify-between gap-2 p-3">
            <span>{{ blockSourceText(b.source, limitLabel) }}<span class="text-muted-foreground" data-testid="block-duration"> · {{ b.duration_s ? incidentBlockText(b) : `Stufe ${b.level}` }}</span></span>
            <span class="tabular-nums">bis {{ formatClock(b.until) }} <span class="text-muted-foreground">({{ formatRelative(b.until) }})</span></span>
          </li>
        </ul>
        <p class="text-xs text-muted-foreground">
          Jede Sperre endet von selbst. Wer gesperrt ist, sieht die Sperrseite mit Vorfallnummer und kann dich um Freigabe bitten.
        </p>
      </section>

      <section v-if="canRelease(hit)" class="space-y-3 rounded-xl border p-4" aria-labelledby="hit-actions" data-testid="hit-actions">
        <h3 id="hit-actions" class="font-semibold">
          Ist das jemand, den du kennst?
        </h3>
        <p v-if="d.allowlisted" class="text-muted-foreground" data-testid="hit-allowlisted">
          Diese Adresse steht schon bei „Eigene IPs“. Szenarien und Limits sperren sie nicht.
        </p>
        <ul class="grid gap-3">
          <li class="grid gap-1">
            <Button variant="outline" size="sm" class="justify-self-start" data-testid="hit-release" @click="ask('none')">
              Freigeben
            </Button>
            <span class="text-xs text-muted-foreground">Beendet laufende Sperren und setzt die Zähler zurück.</span>
          </li>
          <li class="grid gap-1">
            <Button variant="outline" size="sm" class="justify-self-start" data-testid="hit-exception" @click="ask('exception')">
              Ausnahme nur für {{ hit.kind === 'rate_limit' ? 'dieses Limit' : 'dieses Szenario' }}
            </Button>
            <span class="text-xs text-muted-foreground">Für 24 Stunden, 7 oder 30 Tage. Alles andere gilt weiter.</span>
          </li>
          <li v-if="!d.allowlisted" class="grid gap-1">
            <Button variant="outline" size="sm" class="justify-self-start" data-testid="hit-permanent" @click="ask('permanent')">
              Dauerhaft erlauben
            </Button>
            <span class="text-xs text-muted-foreground">Trägt die Adresse bei „Eigene IPs“ ein. Die Regeln des Filters gelten weiter.</span>
          </li>
        </ul>
      </section>
      <p v-else-if="hit.scope === 'site'" class="rounded-xl border bg-muted p-3 text-muted-foreground" data-testid="hit-site-scope">
        Diese Anfragen kamen von vielen verschiedenen Adressen. Es gibt keine einzelne Adresse, die du freigeben oder erlauben könntest. Bei solchen Wellen helfen die Limits für die Anmeldeseite.
      </p>

      <section class="space-y-2" aria-labelledby="hit-requests">
        <h3 id="hit-requests" class="font-semibold">
          Letzte gespeicherte Anfragen
        </h3>
        <p v-if="!d.requests.length" class="text-muted-foreground">
          Zu diesem Treffer sind keine einzelnen Anfragen gespeichert.
        </p>
        <p v-else-if="hit.kind === 'scenario'" class="text-xs text-muted-foreground" data-testid="hit-requests-hint">
          „Gesperrt“ heißt hier: Eine Regel des Filters hat diese eine Anfrage gestoppt. Die Adresse selbst sperrt nur ein Szenario oder ein Limit.
        </p>
        <ul v-if="d.requests.length" class="divide-y rounded-xl border" data-testid="hit-requests">
          <li v-for="r in d.requests" :key="r.id" class="grid gap-1 p-3 sm:grid-cols-[auto_1fr_auto] sm:items-center sm:gap-3">
            <time :datetime="r.time" class="text-xs text-muted-foreground tabular-nums">{{ formatClock(r.time) }}</time>
            <span class="min-w-0 font-mono text-[13px] break-all">{{ r.method }} {{ r.path }}<span v-if="r.status" class="text-muted-foreground"> → {{ r.status }}</span></span>
            <OutcomePill :outcome="r.outcome" />
          </li>
        </ul>
      </section>
    </article>

    <ConfirmDialog
      v-model:open="blockOpen"
      :title="`„${observed?.name ?? ''}“ auf „Sperren“ stellen?`"
      confirm-label="Auf „Sperren“ stellen"
      :pending="updateSettings.isPending.value"
      :error="blockError"
      @confirm="switchToBlock"
    >
      {{ SCENARIO_MODES.block.explain }} Das gilt ab jetzt für alle Adressen, die so auffallen. Jede Sperre endet von selbst. Solange Schild den Normalzustand der Website noch lernt oder im Testprofil läuft, zählt das Szenario weiter nur mit.
    </ConfirmDialog>
    <ConfirmDialog
      v-model:open="pwOpen"
      :title="dialog.title"
      :confirm-label="dialog.confirm"
      :pending="release.isPending.value"
      :error="pwError"
      @confirm="confirm"
    >
      {{ dialog.text }}
      <template v-if="purpose === 'exception'" #details>
        <div class="grid gap-2">
          <Label :for="ttlId">Wie lange?</Label>
          <NativeSelect :id="ttlId" v-model="ttl" class="w-full" data-testid="hit-exception-ttl">
            <NativeSelectOption v-for="(label, key) in TTL_LABELS" :key="key" :value="key">
              {{ label }}
            </NativeSelectOption>
          </NativeSelect>
        </div>
      </template>
    </ConfirmDialog>
  </div>
</template>
