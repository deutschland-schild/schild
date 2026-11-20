<script setup lang="ts">
import type { RuleRepositoryId } from '@/api/types'
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  EffectFooter,
  ErrorState,
  formatDateTime,
  formatNumber,
  formatPercent,
  formatRelative,
  Label,
  MetaLine,
  Skeleton,
  Switch,
  Textarea,
  toast,
} from '@schild/ui'
import { Copy, Download, Filter } from '@lucide/vue'
import { computed, ref } from 'vue'
import { ruleError, useRule, useSetRuleDisabled } from '@/api/rules'
import { HUB_LABEL } from '@/lib/crowdsec'
import { ruleLinks } from '@/lib/explain'
import { decisionText, DISABLED_BY, limitText, REPOSITORIES, RULE_EFFECT, RULE_STATUS, ruleFileName, ruleMeta, ruleText } from '@/lib/rules'
import RuleLinks from '../RuleLinks.vue'
import RuleStatusPill from './RuleStatusPill.vue'

/**
 * One rule of one repository in plain language (D73): what it does now, where it comes from, switching it
 * off and on. A version that came with an update settles and then acts on its own (D89: no approvals).
 * Session and CSRF, no password.
 */
const props = defineProps<{ repository: RuleRepositoryId, id: string }>()
const q = useRule(() => props.repository, () => props.id)
const r = computed(() => q.data.value)
const text = computed(() => r.value ? ruleText(r.value) : null)

// ---------------------------------------------------------------- rule text: copy and download
async function copyText() {
  if (!r.value?.seclang) return
  try {
    await navigator.clipboard.writeText(r.value.seclang)
    toast.success('Regeltext kopiert')
  }
  catch {
    toast.error('Kopieren hat nicht geklappt', { description: 'Markiere den Text und kopiere ihn von Hand.' })
  }
}
function downloadText() {
  if (!r.value?.seclang) return
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([`${r.value.seclang}\n`], { type: 'text/plain' }))
  a.download = ruleFileName(r.value)
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
const hub = computed(() => r.value?.crowdsec)
const links = computed(() => r.value?.repository === 'crs' ? ruleLinks(r.value.id) : [])
/** Disabled in schild.yaml: only there can it change (409 config_limit). */
const configLocked = computed(() => r.value?.disabled_by === 'config')
const runs = computed(() => r.value?.status !== 'disabled')
/** An update that still settles: it only detects until its waiting time ends. */
const settling = computed(() => r.value?.origin === 'update' && r.value.status === 'settling')
const limit = computed(() => r.value ? limitText(r.value) : null)

const setDisabled = useSetRuleDisabled()

const offOpen = ref(false)
const offNote = ref('')

const ref_ = () => ({ repository: props.repository, id: props.id })

function onSwitch(on: boolean) {
  if (on) void enable()
  else offOpen.value = true
}

async function disable() {
  try {
    await setDisabled.mutateAsync({ ...ref_(), disabled: true, note: offNote.value.trim() || undefined })
    offOpen.value = false
    offNote.value = ''
    toast.success('Regel ausgeschaltet', {
      description: 'Sie prüft auf diesem Server nichts mehr.',
      action: { label: 'Rückgängig', onClick: () => void enable() },
    })
  }
  catch (err) {
    toast.error('Ausschalten hat nicht geklappt', { description: ruleError(err) })
  }
}

async function enable() {
  try {
    await setDisabled.mutateAsync({ ...ref_(), disabled: false })
    toast.success('Regel wieder eingeschaltet', { description: 'Sie wirkt wieder, so wie der Schalter ihrer Quelle steht.' })
  }
  catch (err) {
    toast.error('Einschalten hat nicht geklappt', { description: ruleError(err) })
  }
}
</script>

<template>
  <div>
    <div v-if="q.isPending.value" class="space-y-3 p-4">
      <Skeleton class="h-6 w-48" />
      <Skeleton class="h-20 w-full" />
    </div>
    <ErrorState v-else-if="q.isError.value" class="m-4" title="Diese Regel lässt sich nicht laden" :description="ruleError(q.error.value)" @retry="q.refetch()" />
    <div v-else-if="r && text" class="text-sm">
      <div class="space-y-6 p-4">
        <section class="space-y-2">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <p class="min-w-0 flex-1 basis-56 text-base font-bold" data-testid="rule-title">
              {{ text.title }}
            </p>
            <RuleStatusPill :status="r.status" size="md" />
          </div>
          <p v-if="text.explain" class="text-muted-foreground">
            {{ text.explain }}
          </p>
          <MetaLine :items="[...ruleMeta(r, { repository: true }), r.version && r.repository !== 'crs' ? `Version ${r.version}` : null]" />
          <p v-if="r.msg && !hub && r.msg !== text.title" class="font-mono text-xs break-all text-muted-foreground" lang="en">
            {{ r.msg }}
          </p>
        </section>

        <!-- An update settles and then acts on its own (D89). -->
        <p v-if="settling" class="rounded-xl border border-status-info/30 bg-status-info-subtle p-3" data-testid="rule-settling">
          Diese Version kam mit einem Update. Sie erkennt zuerst nur und sperrt<template v-if="hub?.settling_until"> {{ formatRelative(hub.settling_until) }}</template> von selbst. Soll sie nicht sperren, schalte sie unten aus.
        </p>

        <section class="space-y-2 rounded-xl border bg-muted p-3" data-testid="rule-now">
          <h3 class="font-bold">
            Was sie gerade tut
          </h3>
          <p v-if="!settling">
            {{ RULE_STATUS[r.status].explain }}
          </p>
          <dl class="grid grid-cols-[minmax(0,8rem)_1fr] gap-x-3 gap-y-1.5">
            <dt class="text-muted-foreground">
              Wirkung
            </dt>
            <dd data-testid="rule-effect">
              {{ RULE_EFFECT[r.effect].label }}<template v-if="limit">. {{ limit }}</template>
            </dd>
            <template v-if="r.disabled_by">
              <dt class="text-muted-foreground">
                Ausgeschaltet
              </dt>
              <dd>{{ DISABLED_BY[r.disabled_by] }}</dd>
            </template>
          </dl>
          <p v-if="r.repository === 'crs'" class="text-xs text-muted-foreground">
            Die Grundregeln sperren über Punkte: Jeder Treffer zählt, und erst ab der Schwelle sperrt Schild die Anfrage.
          </p>
        </section>

        <Label
          class="flex items-center justify-between gap-3 rounded-xl border p-3 leading-snug font-normal"
          :class="runs ? 'border-status-signal/50 bg-status-signal-subtle' : 'bg-muted'"
          data-testid="rule-switch"
        >
          <span>
            <span class="block font-semibold">Regel eingeschaltet</span>
            <span class="block text-xs text-muted-foreground">
              <template v-if="configLocked">In schild.yaml ausgeschaltet (rules.{{ r.repository }}.disabled_rules). Einschalten kannst du sie nur dort.</template>
              <template v-else-if="runs">Ausschalten wirkt sofort und nur auf diesem Server.</template>
              <template v-else>Ausgeschaltet. Einschalten lässt sie wieder wirken.</template>
            </span>
          </span>
          <Switch
            :model-value="runs"
            :disabled="configLocked || setDisabled.isPending.value"
            :data-testid="runs ? 'rule-disable' : 'rule-enable'"
            @update:model-value="(v: boolean) => onSwitch(v)"
          />
        </Label>

        <!-- Where it comes from -->
        <section v-if="hub" class="space-y-2" data-testid="rule-hub">
          <h3 class="font-bold">
            {{ HUB_LABEL }}
          </h3>
          <dl class="grid grid-cols-[minmax(0,8rem)_1fr] gap-x-3 gap-y-1.5">
            <dt class="text-muted-foreground">
              Name
            </dt>
            <dd class="font-mono text-xs break-all">
              {{ hub.name }}
            </dd>
            <dt class="text-muted-foreground">
              Version
            </dt>
            <dd>{{ hub.version }}</dd>
            <template v-if="hub.label">
              <dt class="text-muted-foreground">
                Titel im Hub
              </dt>
              <dd lang="en">
                {{ hub.label }}
              </dd>
            </template>
            <template v-if="hub.description">
              <dt class="text-muted-foreground">
                Text aus dem Hub
              </dt>
              <dd lang="en">
                {{ hub.description }}
              </dd>
            </template>
            <template v-if="hub.cves?.length">
              <dt class="text-muted-foreground">
                CVE
              </dt>
              <dd>{{ hub.cves.join(', ') }}</dd>
            </template>
            <template v-if="hub.cwes?.length">
              <dt class="text-muted-foreground">
                CWE
              </dt>
              <dd>{{ hub.cwes.join(', ') }}</dd>
            </template>
            <template v-if="hub.attack?.length">
              <dt class="text-muted-foreground">
                MITRE ATT&amp;CK
              </dt>
              <dd>{{ hub.attack.join(', ') }}</dd>
            </template>
            <template v-if="hub.changed_at">
              <dt class="text-muted-foreground">
                Im Hub geändert
              </dt>
              <dd>{{ formatDateTime(hub.changed_at) }}</dd>
            </template>
          </dl>
          <p v-if="hub.notes?.includes('raw_body_partial')" class="rounded-xl border bg-muted p-3" data-testid="rule-hub-partial">
            Diese Regel liest den rohen Inhalt einer Anfrage. Das geht hier bei Formularen und JSON. Bei XML, Datei-Uploads und reinem Text sieht sie den Inhalt nicht.
          </p>
        </section>
        <p v-else-if="r.repository === 'crs'" class="text-muted-foreground" data-testid="rule-source">
          Teil von OWASP CRS {{ r.version }}<template v-if="r.paranoia_level">, Strenge-Stufe {{ r.paranoia_level }}</template><template v-if="r.file">, Datei <span class="font-mono text-xs">{{ r.file }}</span></template>. Kommt mit Schild und läuft lokal.
        </p>
        <p v-else class="text-muted-foreground" data-testid="rule-source">
          {{ REPOSITORIES.local.one }}<template v-if="r.file"> aus der Datei <span class="font-mono text-xs">{{ r.file }}</span></template>. Ändern kannst du sie nur dort.
        </p>

        <section v-if="r.seclang" class="space-y-2" aria-labelledby="rule-seclang-title" data-testid="rule-seclang">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h3 id="rule-seclang-title" class="font-bold">
              Regeltext
            </h3>
            <div class="flex gap-2">
              <Button variant="outline" size="sm" data-testid="rule-seclang-copy" @click="copyText">
                <Copy aria-hidden="true" /> Kopieren
              </Button>
              <Button variant="outline" size="sm" data-testid="rule-seclang-download" @click="downloadText">
                <Download aria-hidden="true" /> Als Datei laden
              </Button>
            </div>
          </div>
          <pre class="max-h-96 overflow-auto rounded-xl border p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere]" tabindex="0">{{ r.seclang }}</pre>
          <p class="text-xs text-muted-foreground">
            So läuft die Regel im Filter, geschrieben in SecLang, der Regelsprache von ModSecurity und Coraza.
          </p>
        </section>

        <section v-if="r.decisions?.length" class="space-y-1.5" data-testid="rule-decisions">
          <h3 class="font-bold">
            Entscheidungen
          </h3>
          <ul class="space-y-1.5">
            <li v-for="(d, i) in r.decisions" :key="i">
              {{ decisionText(d) }}
              <span v-if="d.note" class="block text-muted-foreground">„{{ d.note }}“</span>
            </li>
          </ul>
        </section>

        <section v-if="links.length" class="space-y-1.5" data-testid="rule-references">
          <h3 class="font-bold">
            Mehr dazu
          </h3>
          <RuleLinks :links="links" />
        </section>
      </div>

      <EffectFooter>
        <strong>Letzte 24 Stunden:</strong>
        {{ r.hits_24h === 1 ? '1 Treffer' : `${formatNumber(r.hits_24h)} Treffer` }}<template v-if="r.match_share_24h">, {{ formatPercent(r.match_share_24h) }} aller Anfragen</template>.
        <template #actions>
          <Button as-child size="sm">
            <RouterLink :to="`/events?rule=${encodeURIComponent(r.id)}&time=7d`">
              <Filter aria-hidden="true" />
              Treffer ansehen
            </RouterLink>
          </Button>
        </template>
        <template #note>
          Jede Änderung hier gilt nur für diesen Server und steht im lokalen Ereignisprotokoll.
        </template>
      </EffectFooter>

      <Dialog v-model:open="offOpen">
        <DialogContent class="sm:max-w-md">
          <form class="grid gap-4" @submit.prevent="disable">
            <DialogHeader>
              <DialogTitle>Regel ausschalten?</DialogTitle>
              <DialogDescription>
                Die Regel prüft dann auf diesem Server nichts mehr, auch auf keiner Website. Du kannst sie jederzeit wieder einschalten.
              </DialogDescription>
            </DialogHeader>
            <div class="grid gap-2">
              <Label for="rule-off-note">Grund (optional, bleibt auf diesem Server)</Label>
              <Textarea id="rule-off-note" v-model="offNote" rows="2" maxlength="500" placeholder="z. B. stört das Kontaktformular" />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" @click="offOpen = false">
                Abbrechen
              </Button>
              <Button type="submit" :disabled="setDisabled.isPending.value" data-testid="rule-disable-confirm">
                Ausschalten
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  </div>
</template>
