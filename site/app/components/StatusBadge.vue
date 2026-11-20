<script setup lang="ts">
import { STATUS_LABEL, type HubStatus } from '~/utils/hub'

// Marks a part of Deutschland-Schild as usable today (the gateway) or planned (labs, relays, Managed Schild).
defineProps<{ status: HubStatus, short?: boolean }>()
</script>

<template>
  <span
    class="inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-xs leading-none font-semibold tracking-normal normal-case"
    :class="status === 'live' ? 'bg-signal-tint text-signal-deep' : 'bg-mist text-slate ring-1 ring-mist-line'"
  >
    <span v-if="status === 'live'" class="size-1.5 rounded-full bg-signal" aria-hidden="true" />
    {{ short && status === 'live' ? 'Verfügbar' : STATUS_LABEL[status] }}
  </span>
</template>
