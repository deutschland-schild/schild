<script setup lang="ts">
import type { GapKind } from '@/lib/websites'
import { Popover, PopoverContent, PopoverTrigger } from '@schild/ui'
import { computed } from 'vue'
import { gapCopy, WEBSITE_COPY } from '@/lib/websites'

/**
 * Calm gap marker for a window schild did not fully count (contracts v0.5, partial: a restart, a gap or a
 * partial bucket). Separate from "Näherungswert" (exact = counted vs estimate). gap_kind tells an orderly
 * restart ("Neustart im Zeitraum") from real loss ("Messlücke im Zeitraum"); without it "Lücke im Zeitraum".
 */
const props = defineProps<{
  /** Extra sentence (e.g. the previous period has a gap too). */
  detail?: string
  kind?: GapKind
}>()
const copy = computed(() => gapCopy(props.kind))
</script>

<template>
  <Popover>
    <PopoverTrigger as-child>
      <button
        type="button"
        class="inline-flex cursor-help items-center rounded-full border border-dotted px-2 py-0.5 text-[11px] font-medium text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
        data-testid="gap-note"
        :data-gap-kind="kind ?? 'unknown'"
      >
        {{ copy.label }}<span class="sr-only">: {{ copy.text }}</span>
      </button>
    </PopoverTrigger>
    <PopoverContent class="w-72 text-sm" side="top">
      <p>{{ copy.text }}</p>
      <p class="mt-1 text-muted-foreground">
        {{ detail ?? WEBSITE_COPY.gapDetail }}
      </p>
    </PopoverContent>
  </Popover>
</template>
