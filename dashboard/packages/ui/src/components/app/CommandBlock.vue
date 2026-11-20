<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { Button } from '@schild/ui/components/ui/button'
import { cn } from '@schild/ui/lib/utils'
import { Check, Copy } from '@lucide/vue'
import { useClipboard } from '@vueuse/core'
import { ref } from 'vue'

/**
 * One copyable shell command (fix commands, the enrolment line for an app VM), or the content of a
 * config file (fix_config, subject "Dateiinhalt").
 * The command wraps instead of scrolling (390 px), is selectable as a whole, and the
 * copy button announces "Kopiert" politely. Never runs anything itself.
 */
const props = withDefaults(defineProps<{
  command: string
  /** Accessible name of the copy button ("Befehl kopieren"). */
  copyLabel?: string
  /** Optional small caption above the command. */
  caption?: string
  /** What is copied, for the status texts: "Befehl" (default) or e.g. "Dateiinhalt" for a config file. */
  subject?: string
  class?: HTMLAttributes['class']
}>(), { copyLabel: 'Befehl kopieren', caption: undefined, subject: 'Befehl', class: undefined })
const emit = defineEmits<{ copied: [] }>()

const { copy, copied, isSupported } = useClipboard({ copiedDuring: 2000, legacy: true })
const failed = ref(false)
async function onCopy() {
  failed.value = false
  try {
    await copy(props.command)
    emit('copied')
  }
  catch {
    failed.value = true
  }
}
</script>

<template>
  <div data-slot="command-block" :class="cn('min-w-0', props.class)">
    <p v-if="caption" class="mb-1 text-xs font-semibold text-muted-foreground">
      {{ caption }}
    </p>
    <div class="flex items-start gap-1 rounded-lg border bg-muted py-1.5 pr-1.5 pl-3">
      <pre class="min-w-0 flex-1 py-1 font-mono text-[12.5px] leading-relaxed break-all whitespace-pre-wrap text-foreground select-all"><code data-testid="command-text">{{ command }}</code></pre>
      <Button
        v-if="isSupported"
        type="button"
        variant="ghost"
        size="icon-sm"
        class="shrink-0"
        :aria-label="copied ? 'Kopiert' : copyLabel"
        data-testid="command-copy"
        @click="onCopy"
      >
        <Check v-if="copied" class="text-status-success" aria-hidden="true" />
        <Copy v-else aria-hidden="true" />
      </Button>
    </div>
    <span class="sr-only" aria-live="polite">{{ copied ? `${subject} kopiert` : '' }}</span>
    <p v-if="failed" class="mt-1 text-xs text-muted-foreground" role="status">
      Kopieren hat nicht geklappt. Markiere den {{ subject }} und kopiere ihn von Hand.
    </p>
  </div>
</template>
