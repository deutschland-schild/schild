<script setup lang="ts">
import { Button } from '@schild/ui/components/ui/button'
import { cn } from '@schild/ui/lib/utils'
import { Check, Copy } from '@lucide/vue'
import { useClipboard } from '@vueuse/core'
import { computed } from 'vue'
import JsonNode from './JsonNode.vue'

/** Collapsible, copyable JSON tree (e.g. the exact signal payload that leaves the server). */
const props = withDefaults(defineProps<{ value: unknown, label?: string, expandDepth?: number, class?: string }>(), {
  label: 'JSON',
  expandDepth: 2,
  class: undefined,
})
const text = computed(() => JSON.stringify(props.value, null, 2))
const { copy, copied, isSupported } = useClipboard({ copiedDuring: 1500, legacy: true })
</script>

<template>
  <div :class="cn('relative rounded-lg border bg-muted/40 font-mono text-xs', props.class)">
    <div class="flex items-center justify-between border-b px-3 py-1.5 font-sans">
      <span class="text-xs font-medium text-muted-foreground">{{ label }}</span>
      <Button v-if="isSupported" variant="ghost" size="xs" @click="copy(text)">
        <Check v-if="copied" class="text-status-success" aria-hidden="true" />
        <Copy v-else aria-hidden="true" />
        {{ copied ? 'Kopiert' : 'Kopieren' }}
      </Button>
    </div>
    <div class="max-h-[28rem] overflow-auto py-2 pr-3 pl-7" role="tree" :aria-label="label">
      <JsonNode :value="value" :expand-depth="expandDepth" />
    </div>
  </div>
</template>
