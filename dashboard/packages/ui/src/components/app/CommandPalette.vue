<script setup lang="ts">
import type { CommandEntry } from './types'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from '@schild/ui/components/ui/command'
import { useEventListener } from '@vueuse/core'
import { computed } from 'vue'
import StatusDot from './StatusDot.vue'

/** Cmd+K / Ctrl+K palette for pages and actions. */
const props = withDefaults(defineProps<{ commands: CommandEntry[], placeholder?: string }>(), {
  placeholder: 'Seite oder Aktion suchen …',
})
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ navigate: [to: string] }>()

useEventListener(typeof window !== 'undefined' ? window : undefined, 'keydown', (e: KeyboardEvent) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    open.value = !open.value
  }
})

const groups = computed(() => {
  const map = new Map<string, CommandEntry[]>()
  for (const c of props.commands) {
    const g = c.group ?? 'Aktionen'
    if (!map.has(g)) map.set(g, [])
    map.get(g)!.push(c)
  }
  return [...map.entries()]
})

function run(c: CommandEntry) {
  open.value = false
  if (c.to) emit('navigate', c.to)
  c.run?.()
}
</script>

<template>
  <CommandDialog v-model:open="open" title="Befehle" description="Suche nach einer Seite oder Aktion.">
    <CommandInput :placeholder="placeholder" />
    <CommandList>
      <CommandEmpty>Nichts gefunden.</CommandEmpty>
      <CommandGroup v-for="[name, items] in groups" :key="name" :heading="name">
        <CommandItem v-for="c in items" :key="c.id" :value="c.id" @select="run(c)">
          <StatusDot v-if="c.dot" :tone="c.dot" class="mx-1" />
          <component :is="c.icon" v-else-if="c.icon" aria-hidden="true" />
          <span>{{ c.label }}</span>
          <span v-if="c.hint" class="ml-auto text-xs text-muted-foreground tabular-nums">{{ c.hint }}</span>
          <span v-if="c.keywords?.length" class="hidden">{{ c.keywords.join(' ') }}</span>
          <CommandShortcut v-if="c.shortcut">
            {{ c.shortcut }}
          </CommandShortcut>
        </CommandItem>
      </CommandGroup>
    </CommandList>
  </CommandDialog>
</template>
