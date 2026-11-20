<script setup lang="ts">
import type { SegmentOption } from '@schild/ui'
import type { RuleRepository, RuleRepositoryState } from '@/api/types'
import { Button, Card, CardContent, formatDuration, formatNumber, MetaLine, RelativeTime, SegmentedControl, toast } from '@schild/ui'
import { Info, RefreshCw, RotateCcw } from '@lucide/vue'
import { computed } from 'vue'
import { ruleError, useResetRuleRepository, useSyncRuleRepository, useUpdateRuleRepository } from '@/api/rules'
import { changeText, setText, skipText, updateText } from '@/lib/crowdsec'
import { countFacts, effectText, LOCAL_RULES, ownerText, REPOSITORIES, REPOSITORY_STATES, stateExplain, switchedText } from '@/lib/rules'

/**
 * The head of a repository page (D73): the one switch Aus / Erkennen / Sperren (no password, D39
 * amendment), what it does now, who set it, its counts and what only this repository has. The switch
 * always shows what was chosen; the line below it says when the test profile holds Sperren back.
 */
const props = defineProps<{ repo: RuleRepository }>()

const update = useUpdateRuleRepository()
const sync = useSyncRuleRepository()
const reset = useResetRuleRepository()

// The switch of the own rules moves the files of rules.d, not the exceptions on the same page.
const name = computed(() => props.repo.id === 'local' ? LOCAL_RULES : REPOSITORIES[props.repo.id].name)
const options: SegmentOption<RuleRepositoryState>[] = (['off', 'detect', 'block'] as const).map(value => ({ value, label: REPOSITORY_STATES[value].label }))
const effect = computed(() => effectText(props.repo))
const owner = computed(() => ownerText(props.repo))
const counts = computed(() => countFacts(props.repo))
const cs = computed(() => props.repo.crowdsec)
const crs = computed(() => props.repo.crs)
const every = (s: number) => s === 3600 ? 'prüft stündlich' : s === 86400 ? 'prüft täglich' : `prüft alle ${formatDuration(s)}`
const local = computed(() => props.repo.local)

/** CRS off or only detecting is what the Grundschutz reasons crs_off and crs_detect are about. */
const crsHint = computed(() => {
  if (props.repo.id !== 'crs') return null
  if (props.repo.state === 'off') return 'Solange OWASP CRS aus ist, ist der Grundschutz aus. Anfragen kommen ungeprüft durch.'
  if (props.repo.state === 'detect') return 'Solange OWASP CRS nur erkennt, ist der Grundschutz eingeschränkt. Bekannte Angriffsmuster kommen durch und stehen nur als „Erkannt“ in den Ereignissen.'
  return null
})

async function setState(state: RuleRepositoryState) {
  const before = props.repo.state
  if (state === before) return
  try {
    const r = await update.mutateAsync({ id: props.repo.id, body: { state } })
    toast.success(`${name.value}: ${REPOSITORY_STATES[r.state].label}`, {
      description: switchedText(r),
      action: { label: 'Rückgängig', onClick: () => void update.mutateAsync({ id: r.id, body: { state: before } }).catch(err => toast.error('Zurücknehmen hat nicht geklappt', { description: ruleError(err) })) },
    })
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: ruleError(err) })
  }
}

async function restoreConfig() {
  try {
    const r = await update.mutateAsync({ id: props.repo.id, body: { reset_state: true } })
    toast.success(`${name.value}: wieder wie in schild.yaml`, { description: `Der Schalter steht auf „${REPOSITORY_STATES[r.state].label}“.` })
  }
  catch (err) {
    toast.error('Das hat nicht geklappt', { description: ruleError(err) })
  }
}

async function doSync() {
  try {
    const r = await sync.mutateAsync(props.repo.id)
    if (r.id === 'local') toast.success('Eigene Regeln neu geladen', { description: `${formatNumber(r.counts.rules)} ${r.counts.rules === 1 ? 'Regel' : 'Regeln'} aus ${r.local?.files.length ?? 0} ${r.local?.files.length === 1 ? 'Datei' : 'Dateien'}.` })
    else toast.success('CrowdSec Hub geprüft', { description: (r.crowdsec && updateText(r.crowdsec)) ?? undefined })
  }
  catch (err) {
    toast.error(props.repo.id === 'local' ? 'Neu laden hat nicht geklappt' : 'Prüfen hat nicht geklappt', { description: ruleError(err) })
  }
}

async function doReset() {
  try {
    await reset.mutateAsync(props.repo.id)
    toast.success('Es laufen wieder die Regeln aus dem Image', { description: 'Neuere Regeln lädt Schild beim nächsten Prüfen wieder.' })
  }
  catch (err) {
    toast.error('Zurücksetzen hat nicht geklappt', { description: ruleError(err) })
  }
}
</script>

<template>
  <Card class="mb-4 min-w-0" :data-testid="`repository-${repo.id}`">
    <CardContent class="space-y-4 text-sm">
      <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
        <SegmentedControl
          :model-value="repo.state"
          :options="options"
          :label="`Schalter für ${name}`"
          :disabled="update.isPending.value"
          size="md"
          data-testid="repository-switch"
          @update:model-value="setState"
        />
        <p class="min-w-0 flex-1 basis-56 text-muted-foreground" data-testid="repository-explain">
          {{ stateExplain(repo) }}
        </p>
      </div>

      <p v-if="effect" class="flex items-start gap-3 rounded-xl border bg-muted p-3" role="status" data-testid="repository-effect">
        <Info class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span>{{ effect }}</span>
      </p>
      <p v-if="crsHint" class="flex items-start gap-3 rounded-xl border border-status-warning/40 bg-status-warning-subtle p-3" role="status" data-testid="repository-baseline">
        <Info class="mt-0.5 size-4 shrink-0 text-status-warning" aria-hidden="true" />
        <span>{{ crsHint }}</span>
      </p>

      <div v-if="owner || repo.differs" class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground" data-testid="repository-owner">
        <span>{{ owner }}<template v-if="repo.differs"> In schild.yaml steht „{{ REPOSITORY_STATES[repo.config_state].label }}“.</template></span>
        <Button v-if="repo.differs" size="xs" variant="outline" :disabled="update.isPending.value" data-testid="repository-restore" @click="restoreConfig">
          Wert aus schild.yaml wiederherstellen
        </Button>
      </div>

      <MetaLine :items="counts" data-testid="repository-counts" />

      <!-- OWASP CRS: the values of rules.crs in schild.yaml -->
      <section v-if="crs" class="border-t pt-4" data-testid="repository-crs">
        <dl class="grid grid-cols-[minmax(0,7.5rem)_1fr] gap-x-3 gap-y-1.5 sm:grid-cols-[minmax(0,11rem)_1fr]">
          <dt class="text-muted-foreground">
            Strenge (Paranoia-Level)
          </dt>
          <dd>Stufe {{ crs.paranoia_level }} von 4</dd>
          <dt class="text-muted-foreground">
            Sperrt ab
          </dt>
          <dd>{{ crs.inbound_anomaly_threshold }} Punkten</dd>
          <dt class="text-muted-foreground">
            Ausnahme für Livewire
          </dt>
          <dd>{{ crs.livewire_exception ? 'An' : 'Aus' }}</dd>
          <dt class="text-muted-foreground">
            Version
          </dt>
          <dd>{{ crs.version }}<template v-if="repo.licence">, Lizenz {{ repo.licence }}</template></dd>
        </dl>
        <p class="mt-2 text-xs text-muted-foreground">
          Diese Werte stehen in schild.yaml unter rules.crs. Die Regeln kommen mit Schild und ändern sich mit einem neuen Image.
        </p>
      </section>

      <!-- CrowdSec Hub: updates, the image snapshot, rules that did not load -->
      <section v-if="cs" class="space-y-3 border-t pt-4" data-testid="repository-crowdsec">
        <p v-if="updateText(cs)" class="text-pretty" data-testid="crowdsec-update">
          {{ updateText(cs) }}
        </p>
        <MetaLine
          :items="[
            setText(cs),
            changeText(cs) ? `letztes Update: ${changeText(cs)}` : null,
            cs.auto_update && cs.interval_s ? every(cs.interval_s) : null,
            cs.settling_s ? `Wartezeit für neue Regeln ${formatDuration(cs.settling_s)}` : null,
            cs.pin ? { text: `fester Stand ${cs.pin.slice(0, 12)}`, mono: true } : null,
          ]"
          data-testid="crowdsec-facts"
        />
        <div v-if="repo.state !== 'off'" class="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" :disabled="sync.isPending.value" data-testid="repository-sync" @click="doSync">
            <RefreshCw aria-hidden="true" :class="sync.isPending.value ? 'animate-spin' : ''" />
            Jetzt prüfen
          </Button>
          <Button v-if="cs.set_source === 'stored'" size="sm" variant="ghost" :disabled="reset.isPending.value" data-testid="repository-reset" @click="doReset">
            <RotateCcw aria-hidden="true" />
            Auf den Stand des Images zurücksetzen
          </Button>
        </div>
        <details v-if="cs.skipped.length" class="rounded-xl border" data-testid="crowdsec-skipped">
          <summary class="cursor-pointer px-3 py-2 font-semibold select-none">
            {{ cs.skipped.length === 1 ? '1 Regel aus dem Hub nicht geladen' : `${cs.skipped.length} Regeln aus dem Hub nicht geladen` }}
          </summary>
          <p class="border-t px-3 pt-2 text-xs text-muted-foreground">
            Der Rest läuft. Schild übernimmt nur Regeln, die seine Prüfungen bestehen.
          </p>
          <ul class="space-y-1 p-3 text-xs">
            <li v-for="r in cs.skipped" :key="r.name">
              <span class="font-mono">{{ r.name.replace('crowdsecurity/', '') }}</span>
              <span class="text-muted-foreground">: {{ skipText(r.code) }}</span>
            </li>
          </ul>
        </details>
      </section>

      <!-- Eigene Regeln: the files of rules.d -->
      <section v-if="local" class="space-y-3 border-t pt-4" data-testid="repository-local">
        <dl class="grid grid-cols-[minmax(0,7.5rem)_1fr] gap-x-3 gap-y-1.5 sm:grid-cols-[minmax(0,11rem)_1fr]">
          <dt class="text-muted-foreground">
            Ordner
          </dt>
          <dd class="font-mono text-xs break-all">
            {{ local.dir }}
          </dd>
          <dt class="text-muted-foreground">
            Dateien
          </dt>
          <dd>
            <ul v-if="local.files.length" class="space-y-0.5">
              <li v-for="f in local.files" :key="f.name">
                <span class="font-mono text-xs">{{ f.name }}</span>
                <span class="text-muted-foreground"> · {{ f.rules === 1 ? '1 Regel' : `${f.rules} Regeln` }}</span>
              </li>
            </ul>
            <span v-else class="text-muted-foreground">Noch keine. Leg eine Datei mit der Endung .conf an und lade neu.</span>
          </dd>
          <template v-if="local.last_reload_at">
            <dt class="text-muted-foreground">
              Zuletzt geladen
            </dt>
            <dd><RelativeTime :value="local.last_reload_at" /></dd>
          </template>
        </dl>
        <div v-if="local.last_error" class="space-y-1 rounded-xl border border-status-warning/40 bg-status-warning-subtle p-3" role="status" data-testid="local-error">
          <p>Beim letzten Neuladen hat Schild die Dateien nicht übernommen. Es laufen weiter die Regeln von vorher.</p>
          <p class="font-mono text-xs break-all text-muted-foreground">
            {{ local.last_error }}
          </p>
        </div>
        <Button size="sm" variant="outline" :disabled="sync.isPending.value" data-testid="repository-sync" @click="doSync">
          <RefreshCw aria-hidden="true" :class="sync.isPending.value ? 'animate-spin' : ''" />
          Neu laden
        </Button>
      </section>
    </CardContent>
  </Card>
</template>
