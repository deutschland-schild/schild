<script setup lang="ts">
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@schild/ui'
import { computed } from 'vue'
import { keyLabels, registry } from '@/composables/useShortcuts'

const open = defineModel<boolean>('open', { default: false })

const groups = computed(() => {
  const map = new Map<string, { keys: string, label: string }[]>()
  map.set('Überall', [
    { keys: '⌘/Strg K', label: 'Befehle und Seiten suchen' },
    { keys: 'j', label: 'Nächster Eintrag in der Detailansicht' },
    { keys: 'k', label: 'Vorheriger Eintrag in der Detailansicht' },
  ])
  for (const s of registry.items) {
    if (!map.has(s.group)) map.set(s.group, [])
    const list = map.get(s.group)!
    if (!list.some(x => x.keys === s.keys)) list.push({ keys: s.keys, label: s.label })
  }
  return [...map.entries()]
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent class="max-h-[85vh] overflow-y-auto sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>Tastenkürzel</DialogTitle>
        <DialogDescription>Funktionieren, solange du nicht in einem Eingabefeld schreibst.</DialogDescription>
      </DialogHeader>
      <div class="grid gap-6 sm:grid-cols-2">
        <section v-for="[name, items] in groups" :key="name">
          <h3 class="mb-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {{ name }}
          </h3>
          <dl class="space-y-1.5 text-sm">
            <div v-for="s in items" :key="s.keys" class="flex items-center justify-between gap-3">
              <dt>{{ s.label }}</dt>
              <dd class="flex shrink-0 gap-1">
                <template v-if="s.keys.startsWith('⌘')">
                  <kbd class="rounded border bg-muted px-1.5 py-0.5 font-mono text-xs">{{ s.keys }}</kbd>
                </template>
                <template v-else>
                  <kbd v-for="(k, i) in keyLabels(s.keys)" :key="i" class="min-w-6 rounded border bg-muted px-1.5 py-0.5 text-center font-mono text-xs">{{ k }}</kbd>
                </template>
              </dd>
            </div>
          </dl>
        </section>
      </div>
    </DialogContent>
  </Dialog>
</template>
