<script setup lang="ts">
import type { GroupStatus } from '@/api/group'
import { StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { modeView } from '@/lib/group'
import { GROUP_PATH } from '@/lib/nav'

/**
 * The group this gateway is a node of, in the top bar of every page (MVP-27): "Cluster · 3 Server", coloured
 * by the state of the group, never by colour alone. It leads to the page of the group. A gateway that runs
 * alone shows nothing; alone with a cluster switched on it shows "Kein Cluster" and leads to the server page.
 */
const props = defineProps<{ status: GroupStatus }>()
const v = computed(() => modeView(props.status))
</script>

<template>
  <RouterLink v-if="v" :to="status.mode === 'group' ? GROUP_PATH : '/server'" class="rounded-full focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none" :title="v.title" data-testid="group-mode" :data-mode="status.mode" :data-state="status.state ?? ''">
    <StatusPill :tone="v.tone" size="sm">
      <span class="sm:hidden">{{ v.short }}</span>
      <span class="hidden sm:inline">{{ v.label }}</span>
      <span class="sr-only">. {{ v.title }}</span>
    </StatusPill>
  </RouterLink>
</template>
