<script setup lang="ts">
import type { EntryCheck } from '@/lib/logverify'
import { StatusPill } from '@schild/ui'

defineProps<{ result: EntryCheck | null | undefined }>()
const META: Record<EntryCheck, { tone: 'success' | 'danger' | 'neutral' | 'warning', text: string }> = {
  ok: { tone: 'success', text: 'Prüfsumme passt' },
  mismatch: { tone: 'danger', text: 'Prüfsumme weicht ab' },
  no_envelope: { tone: 'neutral', text: 'Ohne Umschlag' },
  error: { tone: 'warning', text: 'Nicht prüfbar' },
}
</script>

<template>
  <StatusPill v-if="result" :tone="META[result].tone" size="sm">
    {{ META[result].text }}
  </StatusPill>
  <span v-else class="text-xs text-muted-foreground">nicht geprüft</span>
</template>
