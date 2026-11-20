<script setup lang="ts">
import type { Health } from '@/api/types'
import { StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { HEALTH } from '@/lib/labels'

const props = withDefaults(defineProps<{ status?: Health, size?: 'sm' | 'md' }>(), { status: 'unknown', size: 'sm' })
const meta = computed(() => HEALTH[props.status])
</script>

<template>
  <StatusPill :tone="meta.tone" :size="size">
    {{ meta.label }}
  </StatusPill>
</template>
