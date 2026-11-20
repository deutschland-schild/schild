<script setup lang="ts">
import { Popover, PopoverContent, PopoverTrigger } from '@schild/ui'
import { estimateText } from '@/lib/monitoring'

/** "Näherungswert" marker with the bound on click or keyboard (works on touch). */
defineProps<{
  /** How far off the value can be at most, e.g. "25 %". */
  bound?: string
  /** Full sentence instead of the bound sentence. */
  text?: string
  /** Extra sentence (e.g. how the value is counted). */
  detail?: string
}>()
</script>

<template>
  <Popover>
    <PopoverTrigger as-child>
      <button
        type="button"
        class="inline-flex cursor-help items-center rounded-full border border-dashed px-2 py-0.5 text-[11px] font-medium text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
        data-testid="estimate"
      >
        Näherungswert<span class="sr-only">: {{ text ?? estimateText(bound ?? '') }}</span>
      </button>
    </PopoverTrigger>
    <PopoverContent class="w-72 text-sm" side="top">
      <p>{{ text ?? estimateText(bound ?? '') }}</p>
      <p v-if="detail" class="mt-1 text-muted-foreground">
        {{ detail }}
      </p>
    </PopoverContent>
  </Popover>
</template>
