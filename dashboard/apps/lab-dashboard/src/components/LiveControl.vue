<script setup lang="ts">
import type { LiveState } from '@schild/ui'
import { Button, LiveIndicator, Tooltip, TooltipContent, TooltipTrigger } from '@schild/ui'
import { Pause, Play } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed } from 'vue'
import { useHealth } from '@/api/queries'
import { live, setPaused } from '@/lib/live'

/** Live state of the dashboard plus pause/resume (pausing freezes the view, e.g. while reading at night). */
const qc = useQueryClient()
const health = useHealth()
const state = computed<LiveState>(() => {
  if (live.paused) return 'paused'
  if (health.isError.value && !health.isFetching.value) return 'offline'
  if (live.mode === 'connecting' && !health.data.value) return 'connecting'
  return 'live'
})
const label = computed(() => (state.value === 'live' && live.mode !== 'stream' ? 'Live (Abfrage)' : undefined))
const explain = computed(() => {
  if (live.paused) return 'Aktualisierung pausiert. Die Ansicht bleibt stehen, bis du fortsetzt.'
  if (live.mode === 'stream') return 'Änderungen kommen sofort über einen Live-Stream.'
  return 'Kein Live-Stream verfügbar. Das Dashboard fragt in ruhigen Abständen nach.'
})
</script>

<template>
  <div class="flex items-center gap-1">
    <Tooltip>
      <TooltipTrigger as-child>
        <span tabindex="0" class="rounded-full focus-visible:outline-2 focus-visible:outline-ring">
          <LiveIndicator :state="state" :label="label" />
        </span>
      </TooltipTrigger>
      <TooltipContent>{{ explain }}</TooltipContent>
    </Tooltip>
    <Button
      variant="ghost"
      size="icon-sm"
      :aria-label="live.paused ? 'Aktualisierung fortsetzen' : 'Aktualisierung pausieren'"
      :aria-pressed="live.paused"
      @click="setPaused(qc, !live.paused)"
    >
      <Play v-if="live.paused" aria-hidden="true" />
      <Pause v-else aria-hidden="true" />
    </Button>
  </div>
</template>
