<script setup lang="ts">
import type { InventoryItem } from '@/api/hosts'
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow, Tag } from '@schild/ui'
import { computed } from 'vue'
import { eolState, formatDay, INVENTORY_KIND, sortInventory } from '@/lib/hosts'

/** Compact software inventory: name, kind, version and support end, ended support first and highlighted. */
const props = defineProps<{ items: InventoryItem[], now?: number }>()
const rows = computed(() => sortInventory(props.items, props.now).map(i => ({ item: i, eol: eolState(i.eol, props.now) })))
const ended = computed(() => rows.value.filter(r => r.eol === 'past').length)
</script>

<template>
  <div class="min-w-0" data-testid="inventory">
    <Table class="text-[13px]">
      <TableCaption class="mt-2 text-left text-xs">
        Nur Software, die für Sicherheitswarnungen zählt. Support-Ende aus der mitgelieferten EOL-Tabelle, ohne Abfrage im Netz.
        <template v-if="ended">
          {{ ended === 1 ? '1 Eintrag bekommt' : `${ended} Einträge bekommen` }} keine Updates mehr.
        </template>
      </TableCaption>
      <TableHeader>
        <TableRow>
          <TableHead>Software</TableHead>
          <TableHead class="hidden sm:table-cell">
            Art
          </TableHead>
          <TableHead>Version</TableHead>
          <TableHead>Support bis</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <TableRow v-for="{ item, eol } in rows" :key="`${item.kind}:${item.name}:${item.path ?? ''}`" :data-eol="eol" :class="eol === 'past' ? 'bg-status-danger-subtle/50' : ''">
          <TableCell class="max-w-48 whitespace-normal">
            <span :class="['block font-medium break-words', item.parent ? 'pl-3' : '']">
              <span v-if="item.parent" class="text-muted-foreground" aria-hidden="true">└ </span>{{ item.name }}
            </span>
            <span v-if="item.parent" class="block pl-3 text-xs text-muted-foreground">Plugin von {{ item.parent }}</span>
            <span v-else-if="item.path" class="block font-mono text-xs break-all text-muted-foreground">{{ item.path }}</span>
            <span class="block text-xs text-muted-foreground sm:hidden">{{ INVENTORY_KIND[item.kind] }}</span>
          </TableCell>
          <TableCell class="hidden text-muted-foreground sm:table-cell">
            {{ INVENTORY_KIND[item.kind] }}
          </TableCell>
          <TableCell class="max-w-40 font-mono text-xs break-all whitespace-normal">
            {{ item.version }}
          </TableCell>
          <TableCell class="whitespace-normal">
            <template v-if="item.eol">
              <span class="tabular-nums">{{ formatDay(item.eol) }}</span>
              <Tag v-if="eol === 'past'" tone="danger" class="ml-1">
                beendet
              </Tag>
              <Tag v-else-if="eol === 'soon'" tone="warning" class="ml-1">
                endet bald
              </Tag>
            </template>
            <span v-else class="text-muted-foreground">unbekannt</span>
          </TableCell>
        </TableRow>
      </TableBody>
    </Table>
  </div>
</template>
