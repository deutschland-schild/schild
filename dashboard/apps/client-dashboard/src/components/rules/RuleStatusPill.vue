<script setup lang="ts">
import type { RuleStatus } from '@/api/types'
import { StatusPill } from '@schild/ui'
import { computed } from 'vue'
import { RULE_STATUS } from '@/lib/rules'

const props = withDefaults(defineProps<{ status: RuleStatus, size?: 'sm' | 'md' }>(), { size: 'sm' })
const meta = computed(() => RULE_STATUS[props.status] ?? { label: props.status, tone: 'neutral' as const, explain: '' })
</script>

<template>
  <StatusPill :tone="meta.tone" :size="size" :title="meta.explain">
    {{ meta.label }}
  </StatusPill>
</template>
