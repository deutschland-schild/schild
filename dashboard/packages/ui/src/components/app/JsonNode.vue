<script setup lang="ts">
import { computed, ref } from 'vue'

defineOptions({ name: 'JsonNode' })
const props = withDefaults(defineProps<{ value: unknown, name?: string | number, depth?: number, expandDepth?: number, last?: boolean }>(), {
  name: undefined,
  depth: 0,
  expandDepth: 2,
  last: true,
})

const isArray = computed(() => Array.isArray(props.value))
const isObject = computed(() => props.value !== null && typeof props.value === 'object')
const entries = computed(() => isObject.value ? Object.entries(props.value as Record<string, unknown>) : [])
const open = ref(props.depth < props.expandDepth)
const kind = computed(() => {
  const v = props.value
  if (v === null) return 'null'
  return typeof v
})
const primitive = computed(() => kind.value === 'string' ? JSON.stringify(props.value) : String(props.value))
const valueClass: Record<string, string> = {
  string: 'text-status-success',
  number: 'text-status-info',
  boolean: 'text-status-warning',
  null: 'text-muted-foreground',
  undefined: 'text-muted-foreground',
}
</script>

<template>
  <div class="leading-6" role="treeitem" :aria-expanded="isObject ? open : undefined" :aria-level="depth + 1" :aria-selected="false">
    <template v-if="isObject">
      <button
        type="button"
        class="-ml-4 inline-flex items-center gap-1 rounded-sm text-left hover:bg-muted"
        :aria-expanded="open"
        @click="open = !open"
      >
        <!-- Accessible name = visible text plus the action (WCAG 2.5.3 label in name). -->
        <span aria-hidden="true" class="inline-block w-3 text-muted-foreground transition-transform" :class="open ? 'rotate-90' : ''">▸</span>
        <span v-if="name !== undefined" class="text-foreground">{{ typeof name === 'number' ? name : `"${name}"` }}<span class="text-muted-foreground">: </span></span>
        <span class="text-muted-foreground">{{ isArray ? '[' : '{' }}</span>
        <span v-if="!open" class="text-muted-foreground">{{ entries.length }} {{ isArray ? 'Einträge' : 'Felder' }} {{ isArray ? ']' : '}' }}{{ last ? '' : ',' }}</span>
        <span class="sr-only">{{ name === undefined ? 'Wurzel ' : '' }}{{ open ? 'zuklappen' : 'aufklappen' }}</span>
      </button>
      <div v-if="open" role="group" class="border-l border-border pl-4">
        <JsonNode
          v-for="([k, v], i) in entries"
          :key="k"
          :name="isArray ? i : k"
          :value="v"
          :depth="depth + 1"
          :expand-depth="expandDepth"
          :last="i === entries.length - 1"
        />
      </div>
      <span v-if="open" class="text-muted-foreground">{{ isArray ? ']' : '}' }}{{ last ? '' : ',' }}</span>
    </template>
    <template v-else>
      <span v-if="name !== undefined">{{ typeof name === 'number' ? name : `"${name}"` }}<span class="text-muted-foreground">: </span></span>
      <span :class="valueClass[kind]" class="break-all">{{ primitive }}</span><span class="text-muted-foreground">{{ last ? '' : ',' }}</span>
    </template>
  </div>
</template>
