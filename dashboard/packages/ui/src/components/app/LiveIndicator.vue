<script setup lang="ts">
import type { LiveState, StatusTone } from './types'
import { computed } from 'vue'
import StatusPill from './StatusPill.vue'

const props = withDefaults(defineProps<{ state?: LiveState, label?: string }>(), { state: 'live', label: undefined })

const meta: Record<LiveState, { tone: StatusTone, text: string, pulse: boolean }> = {
  live: { tone: 'signal', text: 'Live', pulse: true },
  connecting: { tone: 'info', text: 'Verbinde …', pulse: true },
  paused: { tone: 'neutral', text: 'Pausiert', pulse: false },
  offline: { tone: 'warning', text: 'Keine Verbindung', pulse: false },
}
const current = computed(() => meta[props.state])
</script>

<template>
  <StatusPill :tone="current.tone" :pulse="current.pulse" size="sm" role="status" aria-live="polite" :data-state="state">
    {{ label ?? current.text }}
  </StatusPill>
</template>
