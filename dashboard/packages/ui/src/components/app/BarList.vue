<script setup lang="ts">
import { formatNumber } from '@schild/ui/lib/format'
import { computed } from 'vue'

/**
 * Horizontal bar list (top-N breakdowns such as attack categories or countries).
 * Text (label, hint, value) always sits on the card background, so muted hints keep their
 * 4.5:1 contrast; the magnitude is a thin bar below the text (chart colour, >= 3:1 non-text).
 * Rendered as a real list for screen readers.
 */
const props = withDefaults(defineProps<{
  items: { id: string, label: string, value: number, hint?: string }[]
  label: string
  color?: string
  format?: (n: number) => string
}>(), { color: 'var(--chart-1)', format: formatNumber })

const max = computed(() => Math.max(1, ...props.items.map(i => i.value)))
</script>

<template>
  <ul class="space-y-2" :aria-label="label">
    <li v-for="item in items" :key="item.id" class="px-2 py-1">
      <div class="flex items-center justify-between gap-3 text-sm">
        <span class="min-w-0 truncate">
          <slot name="label" :item="item">{{ item.label }}</slot>
          <span v-if="item.hint" class="ml-1 text-xs text-muted-foreground" data-slot="bar-hint">{{ item.hint }}</span>
        </span>
        <span class="font-medium tabular-nums">{{ format(item.value) }}</span>
      </div>
      <div class="mt-1 h-1.5 rounded-full bg-muted" aria-hidden="true" data-slot="bar-track">
        <div class="h-full rounded-full" :style="{ width: `${(item.value / max) * 100}%`, background: color }" data-slot="bar" />
      </div>
    </li>
  </ul>
</template>
