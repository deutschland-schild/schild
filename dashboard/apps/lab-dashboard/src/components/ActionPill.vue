<script setup lang="ts">
import type { MaxAction } from '@/api/types'
import { StatusPill } from '@schild/ui'
import { ACTION_LABEL, ACTION_TONE } from '@/lib/labels'

defineProps<{ action: MaxAction | null | undefined, size?: 'sm' | 'md' }>()
</script>

<template>
  <StatusPill v-if="action" :tone="ACTION_TONE[action]" :size="size ?? 'sm'">
    {{ ACTION_LABEL[action] }}
  </StatusPill>
  <StatusPill v-else tone="neutral" :size="size ?? 'sm'" :dot="false">
    Noch keine
  </StatusPill>
</template>
