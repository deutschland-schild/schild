<script setup lang="ts">
import type { AcceptedFinding, FindingAnnotation, HostFinding } from '@/api/hosts'
import { Button, CommandBlock, formatRelative, Input, MetaLine, Tag } from '@schild/ui'
import { CircleCheck, CircleSlash, TriangleAlert } from '@lucide/vue'
import { computed, ref, useId } from 'vue'
import { evidenceItems, fixConfigApply, needsText, SEVERITY, UNREADABLE_REASON } from '@/lib/hosts'

/**
 * One result of the server check: severity, German title and explanation, typed evidence with
 * the check time, and the copyable fix command. "ok" results render as one compact line,
 * "unreadable" ones say why the check could not read safely.
 *
 * Agent reports (annotation given, null = no gateway text for this id): title and explanation
 * come from the gateway's own catalogue; the agent's free text is shown marked "vom Agent
 * gemeldet". A fix command gets a copy button only when the gateway's own check produces exactly
 * that command for this finding (fix_verified); otherwise it is shown with a warning and no copy.
 *
 * fix_config (v0.5, D38): a config file as the fix (area logs), shown as path plus content with a copy
 * button and the step that applies it. The gateway only accepts fix_config rendered from its own
 * templates (host-check.md section 2), in agent reports too, so it is always offered for copying.
 *
 * Accepted findings (D102): an open finding can be marked as accepted with an optional note, for
 * example when a firewall in front of the server closes a port the check sees as open. `accepted`
 * given: the finding is shown as accepted, with the note and the way back. The check itself and
 * its report stay as they are.
 *
 * `flat`: the detail of a row in the findings list. The row already shows state and title, so the
 * heading and the card frame are left out here.
 */
const props = defineProps<{
  finding: HostFinding
  checkedAt: string
  annotation?: FindingAnnotation | null
  /** The acceptance in force for this finding. */
  accepted?: AcceptedFinding | null
  /** Offer "Als akzeptiert markieren" (open findings of a host the admin may change). */
  acceptable?: boolean
  /** A change for this finding is on its way. */
  busy?: boolean
  /** Detail under a list row: no heading, no card frame. */
  flat?: boolean
}>()
const emit = defineEmits<{ accept: [note: string], reopen: [] }>()
const asking = ref(false)
const note = ref('')
const noteId = useId()
function submit() {
  emit('accept', note.value.trim())
  asking.value = false
  note.value = ''
}
const f = computed(() => props.finding)
const fromAgent = computed(() => props.annotation !== undefined)
const title = computed(() => props.annotation?.title ?? f.value.title)
const explanation = computed(() => fromAgent.value && props.annotation?.explanation ? props.annotation.explanation : f.value.explanation)
/** The agent's own text, shown in addition when the heading comes from the catalogue. */
const agentText = computed(() => {
  if (!fromAgent.value || !props.annotation?.title) return null
  const t = f.value.title.replace(/\.$/, '')
  // Unreadable results repeat their title in the explanation; show it once.
  if (t === props.annotation.title || f.value.explanation.startsWith(t)) return f.value.explanation
  return `${t}. ${f.value.explanation}`
})
const fixVerified = computed(() => !fromAgent.value || props.annotation?.fix_verified === true)
const meta = computed(() => [...evidenceItems(f.value), `geprüft ${formatRelative(props.checkedAt)}`])
const fixConfig = computed(() => f.value.status === 'finding' ? f.value.fix_config ?? null : null)
const applyText = computed(() => fixConfig.value ? fixConfigApply(f.value, fixConfig.value) : '')
const unreadable = computed(() => {
  const u = f.value.unreadable
  if (!u) return 'Nicht lesbar.'
  return `Nicht lesbar: ${UNREADABLE_REASON[u.reason]}${u.needs ? `, ${needsText(u.needs)}` : ''}.`
})
</script>

<template>
  <div v-if="f.status === 'ok'" class="flex gap-2.5 py-2" data-testid="finding-ok">
    <CircleCheck v-if="!flat" class="mt-0.5 size-4 shrink-0 text-status-success" aria-hidden="true" />
    <div class="min-w-0">
      <p v-if="!flat" class="font-semibold">
        <span class="sr-only">In Ordnung: </span>{{ title }}
      </p>
      <p v-if="!agentText" class="text-muted-foreground">
        <span v-if="fromAgent" class="font-semibold">Vom Agent gemeldet: </span>{{ f.explanation }}
      </p>
      <p v-else class="text-muted-foreground" data-testid="agent-text">
        <span class="font-semibold">Vom Agent gemeldet: </span>{{ agentText }}
      </p>
      <MetaLine :items="meta" class="mt-0.5" />
    </div>
  </div>

  <div v-else-if="accepted" class="flex gap-2.5 py-2" data-testid="finding-accepted">
    <CircleSlash v-if="!flat" class="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
    <div class="min-w-0 flex-1">
      <p v-if="!flat" class="font-semibold">
        <span class="sr-only">Akzeptiert: </span>{{ title }}
        <Tag tone="neutral" class="ml-1 align-middle">
          <span class="sr-only">Stufe: </span>{{ SEVERITY[f.severity].label }}
        </Tag>
      </p>
      <p class="text-muted-foreground">
        {{ explanation }}
      </p>
      <p v-if="accepted.note" data-testid="accepted-note">
        <span class="font-semibold">Deine Notiz: </span>{{ accepted.note }}
      </p>
      <MetaLine :items="[...meta, `akzeptiert ${formatRelative(accepted.accepted_at)}`]" class="mt-0.5" />
    </div>
    <Button type="button" variant="ghost" size="sm" class="shrink-0" :disabled="busy" data-testid="reopen" @click="emit('reopen')">
      Wieder öffnen
    </Button>
  </div>

  <article
    v-else
    :class="['min-w-0 space-y-2', flat ? 'py-1' : 'rounded-xl border bg-card p-3.5']"
    :data-testid="f.status === 'unreadable' ? 'finding-unreadable' : 'finding'"
    :data-severity="f.severity"
    :aria-label="title"
  >
    <div v-if="!flat || (fromAgent && !annotation?.title)" class="flex flex-wrap items-start gap-x-2 gap-y-1">
      <template v-if="!flat">
        <Tag v-if="f.status === 'unreadable'" tone="neutral" class="mt-0.5">
          Nicht lesbar
        </Tag>
        <Tag v-else :tone="SEVERITY[f.severity].tone" class="mt-0.5">
          <span class="sr-only">Stufe: </span>{{ SEVERITY[f.severity].label }}
        </Tag>
        <h4 class="min-w-0 flex-1 basis-48 font-semibold">
          {{ title }}
        </h4>
      </template>
      <Tag v-if="fromAgent && !annotation?.title" tone="neutral" class="mt-0.5" data-testid="agent-tag">
        vom Agent gemeldet
      </Tag>
    </div>
    <p class="leading-snug text-pretty">
      {{ explanation }}
    </p>
    <p v-if="agentText" class="leading-snug text-pretty text-muted-foreground" data-testid="agent-text">
      <span class="font-semibold">Vom Agent gemeldet: </span>{{ agentText }}
    </p>
    <p v-if="f.status === 'unreadable'" class="text-muted-foreground" data-testid="unreadable-reason">
      {{ unreadable }} Der Check versucht es nicht mit mehr Rechten und ändert nichts.
    </p>
    <MetaLine :items="meta" />
    <div v-if="fixConfig" class="min-w-0 space-y-1" data-testid="fix-config">
      <p class="text-xs font-semibold text-muted-foreground">
        So behebst du es: Lege diese Datei an
      </p>
      <p class="font-mono text-xs break-all" data-testid="fix-config-path">
        {{ fixConfig.path }}
      </p>
      <CommandBlock
        :command="fixConfig.content"
        subject="Dateiinhalt"
        :copy-label="`Inhalt von ${fixConfig.path} kopieren`"
      />
      <p class="text-xs text-muted-foreground" data-testid="fix-config-apply">
        {{ applyText }}
      </p>
    </div>
    <CommandBlock
      v-if="f.fix_command && fixVerified"
      :command="f.fix_command"
      :caption="fixConfig ? 'Danach ausführen' : 'So behebst du es'"
      :copy-label="`Befehl kopieren: ${title}`"
    />
    <div v-else-if="f.fix_command" class="min-w-0" data-testid="unverified-fix">
      <p class="mb-1 flex items-start gap-1.5 text-xs font-semibold text-status-warning">
        <TriangleAlert class="mt-px size-3.5 shrink-0" aria-hidden="true" />
        Vom Agent gemeldeter Befehl, nicht geprüft: Das Gateway kennt diesen Befehl nicht. Lies ihn genau, bevor du etwas davon ausführst.
      </p>
      <pre class="min-w-0 rounded-lg border border-status-warning/40 bg-muted px-3 py-2 font-mono text-[12.5px] leading-relaxed break-all whitespace-pre-wrap text-muted-foreground"><code data-testid="unverified-fix-text">{{ f.fix_command }}</code></pre>
    </div>
    <template v-if="acceptable && f.status === 'finding'">
      <form v-if="asking" class="space-y-2 border-t pt-2.5" data-testid="accept-form" @submit.prevent="submit">
        <label :for="noteId" class="block text-xs font-semibold">Warum ist das für dich in Ordnung? (freiwillig)</label>
        <Input :id="noteId" v-model="note" maxlength="200" placeholder="z. B. Firewall des Hosters lässt den Port nicht durch" data-testid="accept-note" />
        <p class="text-xs text-muted-foreground">
          Der Befund zählt dann nicht mehr als offen und bleibt unter „Akzeptiert“ sichtbar. Meldet der Check ihn später mit einer höheren Stufe, ist er wieder offen.
        </p>
        <div class="flex flex-wrap gap-2">
          <Button type="submit" size="sm" :disabled="busy" data-testid="accept-confirm">
            Akzeptieren
          </Button>
          <Button type="button" variant="ghost" size="sm" @click="asking = false">
            Abbrechen
          </Button>
        </div>
      </form>
      <div v-else class="border-t pt-2">
        <Button type="button" variant="ghost" size="sm" class="h-auto px-0 text-muted-foreground" :disabled="busy" data-testid="accept-open" @click="asking = true">
          Als akzeptiert markieren
        </Button>
      </div>
    </template>
  </article>
</template>
