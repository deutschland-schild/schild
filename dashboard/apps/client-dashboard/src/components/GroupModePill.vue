<script setup lang="ts">
import type { GroupStatus } from '@/api/group'
import { StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { modeView } from '@/lib/group'

/**
 * The mode this gateway runs in, in the top bar of every page (MVP-27): "Einzelner Server" or
 * "Gruppe · 3 Server", coloured by the state of the group, never by colour alone. It leads to the card
 * "Gruppe" on the server page.
 */
const props = defineProps<{ status: GroupStatus }>()
const v = computed(() => modeView(props.status))
</script>

<template>
  <RouterLink to="/server" class="rounded-full focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none" :title="v.title" data-testid="group-mode" :data-mode="status.mode" :data-state="status.state ?? ''">
    <StatusPill :tone="v.tone" size="sm">
      <span class="sm:hidden">{{ v.short }}</span>
      <span class="hidden sm:inline">{{ v.label }}</span>
      <span class="sr-only">. {{ v.title }}</span>
    </StatusPill>
  </RouterLink>
</template>
