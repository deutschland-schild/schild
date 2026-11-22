<script setup lang="ts">
import type { GroupStatus } from '@/api/group'
import { Button } from '@schild/ui'
import { useQueryClient } from '@tanstack/vue-query'
import { computed } from 'vue'
import { useMonitoringNow } from '@/api/monitoring'
import { gateways } from '@/lib/group'
import { ALL_NODES, partialNodesText, selectedNode, selectNode } from '@/lib/node-filter'

/**
 * Note above every page of a cluster (MVP-27) when the numbers are not those of the whole cluster: one
 * gateway is chosen in the filter "Server", or a gateway's history ends early because it was not reached.
 * Nothing is shown while every gateway is in and all are chosen.
 */
const props = defineProps<{ status: GroupStatus }>()
const client = useQueryClient()
const inGroup = computed(() => props.status.mode === 'group' && gateways(props.status).length > 1)
const now = useMonitoringNow(undefined, inGroup)
const chosen = computed(() => selectedNode.value === ALL_NODES ? undefined : gateways(props.status).find(m => m.id === selectedNode.value))
const missing = computed(() => partialNodesText(now.data.value?.cluster))

function showAll() {
  selectNode(ALL_NODES)
  void client.invalidateQueries()
}
</script>

<template>
  <div v-if="inGroup && (chosen || missing)" class="mb-6 space-y-2" data-testid="cluster-data-banner">
    <div v-if="chosen" class="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-status-info/30 bg-status-info-subtle px-4 py-2.5 text-sm" role="note" data-testid="cluster-node-note">
      <p class="min-w-0 flex-1">
        <strong class="font-medium">Zahlen und Diagramme zeigen nur {{ chosen.name }}.</strong>
        Die Listen der Ereignisse und Anfragen zeigen weiter alle Server.
      </p>
      <Button variant="outline" size="sm" data-testid="cluster-node-all" @click="showAll">
        Alle Server zeigen
      </Button>
    </div>
    <p v-if="missing" class="rounded-xl border border-status-warning/30 bg-status-warning-subtle px-4 py-2.5 text-sm" role="note" data-testid="cluster-partial-note">
      {{ missing }}
    </p>
  </div>
</template>
