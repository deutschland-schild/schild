<script setup lang="ts">
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@schild/ui'
import { computed } from 'vue'
import { listShortcuts } from '@/composables/useShortcuts'
import Kbd from './Kbd.vue'

const open = defineModel<boolean>('open', { default: false })
const groups = computed(() => {
  if (!open.value) return []
  const map = new Map<string, { keys: string, description: string }[]>()
  for (const s of listShortcuts()) {
    const g = s.group ?? 'Allgemein'
    if (!map.has(g)) map.set(g, [])
    if (!map.get(g)!.some(x => x.keys === s.keys)) map.get(g)!.push(s)
  }
  map.get('Allgemein')?.unshift({ keys: '⌘/Strg K', description: 'Suche und Befehle' })
  return [...map.entries()]
})
const parts = (keys: string) => (keys.startsWith('⌘') ? [keys] : keys.split(' '))
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>Tastenkürzel</DialogTitle>
        <DialogDescription>Kürzel wirken nicht in Eingabefeldern. Folgenreiche Schritte öffnen immer erst einen Dialog.</DialogDescription>
      </DialogHeader>
      <div class="max-h-[60vh] space-y-4 overflow-y-auto">
        <section v-for="[group, items] in groups" :key="group">
          <h2 class="mb-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {{ group }}
          </h2>
          <dl class="divide-y text-sm">
            <div v-for="s in items" :key="s.keys" class="flex items-center justify-between gap-4 py-1.5">
              <dt>{{ s.description }}</dt>
              <dd class="flex shrink-0 items-center gap-1">
                <template v-for="(k, i) in parts(s.keys)" :key="i">
                  <span v-if="i > 0" class="text-xs text-muted-foreground">dann</span>
                  <Kbd>{{ k }}</Kbd>
                </template>
              </dd>
            </div>
          </dl>
        </section>
      </div>
    </DialogContent>
  </Dialog>
</template>
