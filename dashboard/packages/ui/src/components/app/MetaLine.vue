<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import type { MetaItem } from './types'
import { cn } from '@schild/ui/lib/utils'
import { Check } from '@lucide/vue'
import { computed } from 'vue'

/**
 * Small slate meta line under a title, parts joined by " · " (website:
 * "Quelle: … · ✓ signiert von 3 von 4 Labs · 24 h: 97 Treffer").
 * Green with a check only for facts Schild has verified itself.
 * Long tokens (container log paths with 64-hex ids) wrap anywhere instead of widening the card.
 */
const props = defineProps<{ items: (MetaItem | false | null | undefined)[], class?: HTMLAttributes['class'] }>()
const parts = computed(() => props.items.filter(Boolean).map(i => typeof i === 'string' ? { text: i } : i as Exclude<MetaItem, string>))
const tone: Record<string, string> = {
  signal: 'text-status-signal-text',
  warning: 'text-status-warning',
  danger: 'text-status-danger',
}
</script>

<template>
  <p :class="cn('min-w-0 text-xs leading-relaxed text-muted-foreground [overflow-wrap:anywhere]', props.class)" data-slot="meta-line">
    <template v-for="(p, i) in parts" :key="i">
      <span v-if="i" aria-hidden="true"> · </span><span v-if="i" class="sr-only">, </span>
      <span :class="[p.tone ? tone[p.tone] : '', p.mono ? 'font-mono' : '']" :title="p.title"><Check v-if="p.tone === 'signal'" class="mr-0.5 inline size-3 -translate-y-px" aria-hidden="true" />{{ p.text }}</span>
    </template>
    <slot />
  </p>
</template>
