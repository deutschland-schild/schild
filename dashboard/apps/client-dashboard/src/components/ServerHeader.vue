<script setup lang="ts">
import type { StatusTone } from '@schild/ui'
import { PageHeader, StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { useWebsites } from '@/api/websites'
import { STATUS } from '@/lib/websites'

/**
 * Title of the server views (Überblick, Auslastung, Server-Check): the node name from the API with the
 * server's state in words. The sidebar switches between the views. One gateway is one server; the
 * Server-Check of an agent passes its host name and state instead.
 */
const props = defineProps<{ description: string, title?: string, status?: { tone: StatusTone, label: string } }>()
const q = useWebsites()
const node = computed(() => props.title ?? q.data.value?.node ?? 'Server')
const server = computed(() => q.data.value?.server)
</script>

<template>
  <PageHeader :title="node" :description="description">
    <template v-if="status || server" #meta>
      <StatusPill v-if="status" :tone="status.tone" size="sm" data-testid="server-status">
        {{ status.label }}
      </StatusPill>
      <StatusPill v-else-if="server" :tone="STATUS[server.status].tone" size="sm" data-testid="server-status">
        Server {{ STATUS[server.status].label }}
      </StatusPill>
    </template>
    <template v-if="$slots.actions" #actions>
      <slot name="actions" />
    </template>
  </PageHeader>
</template>
