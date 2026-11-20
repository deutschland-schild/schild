<script setup lang="ts">
import type { Signature } from '@/api/types'
import { RelativeTime } from '@schild/ui'
import { Check, Circle } from '@lucide/vue'
import { computed } from 'vue'

/**
 * k-of-n progress counted by distinct operators (two labs of one operator count once).
 * Shows who signed and how many co-signatures are still missing.
 */
const props = withDefaults(defineProps<{ signatures: Signature[], threshold: number, compact?: boolean, collecting?: boolean }>(), { compact: false, collecting: true })
const operators = computed(() => [...new Set(props.signatures.map(s => s.operator))])
const missing = computed(() => (props.collecting ? Math.max(0, props.threshold - operators.value.length) : 0))
const sameOperatorDupes = computed(() => props.signatures.length - operators.value.length)
</script>

<template>
  <div class="space-y-2">
    <div class="flex items-center gap-2" :class="compact ? 'whitespace-nowrap' : 'flex-wrap'">
      <div class="flex gap-1" aria-hidden="true">
        <span
          v-for="i in Math.max(threshold, operators.length)"
          :key="i"
          class="h-2 w-5 rounded-full"
          :class="i <= operators.length ? 'bg-status-signal ring-1 ring-status-signal-text ring-inset' : 'bg-muted ring-1 ring-input ring-inset'"
        />
      </div>
      <span class="text-sm tabular-nums">
        {{ operators.length }} von {{ threshold }}<template v-if="!compact"> Betreibern</template>
      </span>
      <span v-if="missing > 0" class="text-sm font-medium text-status-warning" data-testid="missing-signatures">
        <template v-if="compact">· fehlt {{ missing }}</template>
        <template v-else>· {{ missing === 1 ? 'noch 1 Mitzeichnung fehlt' : `noch ${missing} Mitzeichnungen fehlen` }}</template>
      </span>
    </div>
    <ul v-if="!compact" class="space-y-1 text-sm">
      <li v-for="s in signatures" :key="`${s.lab}-${s.keyid}`" class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <Check class="size-4 text-status-signal-text" aria-hidden="true" />
        <span class="font-medium">{{ s.lab }}</span>
        <span class="text-muted-foreground">Betreiber {{ s.operator }} · Schlüssel <code class="font-mono text-xs">{{ s.keyid }}</code> ·</span>
        <RelativeTime :value="s.at" class="text-muted-foreground" />
      </li>
      <li v-for="i in missing" :key="`missing-${i}`" class="flex items-center gap-2 text-muted-foreground">
        <Circle class="size-4" aria-hidden="true" />
        Mitzeichnung eines weiteren Betreibers offen
      </li>
    </ul>
    <p v-if="!compact && sameOperatorDupes > 0" class="text-xs text-muted-foreground">
      {{ sameOperatorDupes === 1 ? 'Eine Signatur stammt' : `${sameOperatorDupes} Signaturen stammen` }} vom selben Betreiber und zählt nicht extra.
    </p>
  </div>
</template>
