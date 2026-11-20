<script setup lang="ts">
import type { GlossaryKey } from '@/lib/glossary'
import { Popover, PopoverContent, PopoverTrigger } from '@schild/ui'
import { computed } from 'vue'
import { GLOSSARY } from '@/lib/glossary'

/**
 * A term with a short explanation on click or keyboard (works on touch, unlike a hover tooltip).
 * Default slot overrides the visible text.
 */
const props = defineProps<{ k: GlossaryKey }>()
const entry = computed(() => GLOSSARY[props.k])
</script>

<template>
  <Popover>
    <PopoverTrigger as-child>
      <button
        type="button"
        class="cursor-help rounded-sm underline decoration-muted-foreground/60 decoration-dotted underline-offset-4 hover:decoration-foreground focus-visible:outline-2 focus-visible:outline-ring"
        data-testid="term"
      >
        <slot>{{ entry.term }}</slot><span class="sr-only"> (Erklärung)</span>
      </button>
    </PopoverTrigger>
    <PopoverContent class="w-72 text-sm" side="top">
      <p class="font-medium">
        {{ entry.term }}
      </p>
      <p class="mt-1 text-muted-foreground">
        {{ entry.text }}
      </p>
    </PopoverContent>
  </Popover>
</template>
