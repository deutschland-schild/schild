<script setup lang="ts">
import { Input } from '@schild/ui'
import { Search } from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { searchFilter } from '@/lib/websites'

/**
 * One field for an address or a part of the User-Agent (D64), above every tab of Zugriffe. An address
 * sets the filter ip, anything else user_agent; the tab stays. An empty field removes both.
 */
const props = defineProps<{ filters: string[] }>()
const emit = defineEmits<{ update: [filters: string[]] }>()

const valueOf = (dim: string) => props.filters.find(f => f.startsWith(`${dim}:`))?.slice(dim.length + 1) ?? ''
const current = computed(() => valueOf('ip') || valueOf('user_agent'))
const draft = ref(current.value)
watch(current, v => (draft.value = v))

function submit() {
  if (draft.value.trim() === current.value) return
  const expr = searchFilter(draft.value)
  const rest = props.filters.filter(f => !f.startsWith('ip:') && !f.startsWith('user_agent:'))
  emit('update', expr ? [...rest, expr].slice(-4) : rest)
}
</script>

<template>
  <div class="relative">
    <Search class="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
    <Input
      v-model="draft"
      type="search"
      class="w-64 pl-8"
      aria-label="IP-Adresse oder User-Agent"
      placeholder="IP oder User-Agent, z. B. bingbot"
      data-testid="request-search"
      @keydown.enter="submit"
      @blur="submit"
    />
  </div>
</template>
