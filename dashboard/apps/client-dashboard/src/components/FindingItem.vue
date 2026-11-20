<script setup lang="ts">
import type { FindingAnnotation, HostFinding } from '@/api/hosts'
import { CommandBlock, formatRelative, MetaLine, Tag } from '@schild/ui'
import { CircleCheck, TriangleAlert } from '@lucide/vue'
import { computed } from 'vue'
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
 */
const props = defineProps<{ finding: HostFinding, checkedAt: string, annotation?: FindingAnnotation | null }>()
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
    <CircleCheck class="mt-0.5 size-4 shrink-0 text-status-success" aria-hidden="true" />
    <div class="min-w-0">
      <p class="font-semibold">
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

  <article
    v-else
    class="min-w-0 space-y-2 rounded-xl border bg-card p-3.5"
    :data-testid="f.status === 'unreadable' ? 'finding-unreadable' : 'finding'"
    :data-severity="f.severity"
    :aria-label="title"
  >
    <div class="flex flex-wrap items-start gap-x-2 gap-y-1">
      <Tag v-if="f.status === 'unreadable'" tone="neutral" class="mt-0.5">
        Nicht lesbar
      </Tag>
      <Tag v-else :tone="SEVERITY[f.severity].tone" class="mt-0.5">
        <span class="sr-only">Stufe: </span>{{ SEVERITY[f.severity].label }}
      </Tag>
      <h4 class="min-w-0 flex-1 basis-48 font-semibold">
        {{ title }}
      </h4>
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
  </article>
</template>
