<script setup lang="ts">
import type { GroupStatus } from '@/api/group'
import { NativeSelect, NativeSelectOption } from '@schild/ui'
import { useQueryClient } from '@tanstack/vue-query'
import { computed, useId, watch } from 'vue'
import { gateways } from '@/lib/group'
import { ALL_NODES, selectedNode, selectNode } from '@/lib/node-filter'

/**
 * Filter "Server" in the top bar of a cluster (MVP-27): the counters and charts of the whole dashboard show
 * every gateway added up ("Alle Server", the default) or one gateway alone. Hidden on a single gateway and in
 * a cluster of one. A gateway that left the cluster while it was chosen falls back to all.
 */
const props = defineProps<{ status: GroupStatus }>()
const uid = useId()
const client = useQueryClient()
const nodes = computed(() => props.status.mode === 'group' ? gateways(props.status) : [])
const shown = computed(() => nodes.value.length > 1)

watch([nodes, shown], () => {
  if (selectedNode.value !== ALL_NODES && !nodes.value.some(m => m.id === selectedNode.value)) selectNode(ALL_NODES)
}, { immediate: true })

const value = computed({
  get: () => selectedNode.value,
  set: (v: string) => {
    if (v === selectedNode.value) return
    selectNode(v)
    // Every number on screen is of the old choice: ask again.
    void client.invalidateQueries()
  },
})
</script>

<template>
  <div v-if="shown" class="flex items-center gap-1.5" data-testid="node-filter">
    <label :for="uid" class="hidden text-xs text-muted-foreground lg:inline">Zahlen von</label>
    <NativeSelect :id="uid" v-model="value" class="h-8 max-w-28 text-xs sm:max-w-44" aria-label="Zahlen und Diagramme von welchem Server" data-testid="node-filter-select">
      <NativeSelectOption :value="ALL_NODES">
        Alle Server
      </NativeSelectOption>
      <NativeSelectOption v-for="m in nodes" :key="m.id" :value="m.id">
        {{ m.name }}{{ m.state === 'self' ? ' (dieser Server)' : '' }}
      </NativeSelectOption>
    </NativeSelect>
  </div>
</template>
