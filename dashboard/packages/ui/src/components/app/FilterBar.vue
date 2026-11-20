<script setup lang="ts">
import type { FilterChip } from './types'
import { Button } from '@schild/ui/components/ui/button'
import { Input } from '@schild/ui/components/ui/input'
import { Search, X } from '@lucide/vue'
import { useId } from 'vue'

/**
 * Search field, filter controls (slot) and active filters as removable chips.
 * Filters live in one row above the content; on small screens they wrap.
 */
withDefaults(defineProps<{ searchPlaceholder?: string, searchLabel?: string, showSearch?: boolean }>(), {
  searchPlaceholder: 'Suchen …',
  searchLabel: 'Suchen',
  showSearch: true,
})
const search = defineModel<string>('search', { default: '' })
const chips = defineModel<FilterChip[]>('chips', { default: () => [] })
const emit = defineEmits<{ remove: [chip: FilterChip], clear: [] }>()
const searchId = useId()

function remove(chip: FilterChip) {
  chips.value = chips.value.filter(c => !(c.key === chip.key && c.value === chip.value))
  emit('remove', chip)
}
function clearAll() {
  chips.value = []
  search.value = ''
  emit('clear')
}
</script>

<template>
  <div class="space-y-3" role="search">
    <div class="flex flex-wrap items-center gap-2">
      <div v-if="showSearch" class="relative w-full min-w-48 sm:w-72">
        <label :for="searchId" class="sr-only">{{ searchLabel }}</label>
        <Search class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <Input :id="searchId" v-model="search" type="search" :placeholder="searchPlaceholder" class="pl-8" />
      </div>
      <slot />
      <div v-if="$slots.end" class="ml-auto flex items-center gap-2">
        <slot name="end" />
      </div>
    </div>
    <div v-if="chips.length" class="flex flex-wrap items-center gap-2" aria-label="Aktive Filter" role="group">
      <span
        v-for="chip in chips"
        :key="`${chip.key}:${chip.value}`"
        class="inline-flex items-center gap-1 rounded-full border bg-secondary py-0.5 pr-1 pl-2.5 text-xs text-secondary-foreground"
        data-testid="filter-chip"
      >
        <span class="text-muted-foreground">{{ chip.label }}:</span>
        <span class="font-medium">{{ chip.value }}</span>
        <button
          type="button"
          class="ml-0.5 inline-flex size-5 items-center justify-center rounded-full hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring"
          :aria-label="`Filter ${chip.label}: ${chip.value} entfernen`"
          @click="remove(chip)"
        >
          <X class="size-3" aria-hidden="true" />
        </button>
      </span>
      <Button variant="link" size="xs" class="text-muted-foreground" @click="clearAll">
        Alle Filter entfernen
      </Button>
    </div>
  </div>
</template>
