<script setup lang="ts">
import type { StatusTone } from './types'
import { Card } from '@schild/ui/components/ui/card'
import { Skeleton } from '@schild/ui/components/ui/skeleton'
import { formatNumber, formatPercent } from '@schild/ui/lib/format'
import { cn } from '@schild/ui/lib/utils'
import { ArrowDownRight, ArrowUpRight, Minus } from '@lucide/vue'
import { computed } from 'vue'
import Sparkline from './Sparkline.vue'

const props = withDefaults(defineProps<{
  label: string
  value: number | string | null
  /** Unit or suffix shown after the value. */
  unit?: string
  /** Relative change vs. previous period (0.12 = +12 %). */
  delta?: number | null
  /** Whether "up" is good (default) or bad (e.g. blocked attacks rising is neutral/bad). */
  deltaPositive?: 'up' | 'down' | 'neutral'
  hint?: string
  /** Trend for the sparkline; null is a gap. */
  trend?: (number | null)[]
  trendLabel?: string
  tone?: StatusTone
  loading?: boolean
}>(), {
  unit: undefined,
  delta: null,
  deltaPositive: 'up',
  hint: undefined,
  trend: undefined,
  trendLabel: undefined,
  tone: 'neutral',
  loading: false,
})

const display = computed(() => typeof props.value === 'number' ? formatNumber(props.value) : (props.value ?? '–'))
const deltaDir = computed(() => props.delta == null ? null : props.delta > 0 ? 'up' : props.delta < 0 ? 'down' : 'flat')
const deltaTone = computed(() => {
  if (deltaDir.value === null || deltaDir.value === 'flat' || props.deltaPositive === 'neutral') return 'text-muted-foreground'
  return deltaDir.value === props.deltaPositive ? 'text-status-success' : 'text-status-warning'
})
const deltaText = computed(() => {
  if (props.delta == null) return ''
  const sign = props.delta > 0 ? '+' : ''
  return `${sign}${formatPercent(props.delta)}`
})
const sparkColor: Record<StatusTone, string> = {
  signal: 'var(--signal-text)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger: 'var(--danger)',
  info: 'var(--info)',
  neutral: 'var(--tone-main)',
}
const accent: Record<StatusTone, string> = {
  signal: 'before:bg-status-signal',
  success: 'before:bg-status-success',
  warning: 'before:bg-status-warning',
  danger: 'before:bg-status-danger',
  info: 'before:bg-status-info',
  neutral: 'before:bg-transparent',
}
</script>

<template>
  <Card
    :class="cn('relative gap-2 overflow-hidden px-5 py-4 before:absolute before:inset-y-0 before:left-0 before:w-1', accent[tone])"
    :aria-busy="loading"
  >
    <div class="flex items-start justify-between gap-3">
      <p class="text-[13px] font-semibold text-muted-foreground">
        {{ label }}
      </p>
      <slot name="icon" />
    </div>
    <div v-if="loading" class="space-y-2">
      <Skeleton class="h-8 w-24" />
      <Skeleton class="h-4 w-32" />
    </div>
    <template v-else>
      <div class="flex items-end justify-between gap-3">
        <p class="text-3xl font-bold tracking-tight tabular-nums" data-testid="stat-value">
          {{ display }}<span v-if="unit" class="ml-1 text-base font-normal text-muted-foreground">{{ unit }}</span>
        </p>
        <Sparkline v-if="trend && trend.filter(v => v !== null).length > 1" :values="trend" :label="trendLabel ?? label" :color="sparkColor[tone]" :width="96" :height="32" />
      </div>
      <p class="flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
        <span v-if="deltaDir" :class="cn('inline-flex items-center gap-0.5 font-medium tabular-nums', deltaTone)">
          <ArrowUpRight v-if="deltaDir === 'up'" class="size-3.5" aria-hidden="true" />
          <ArrowDownRight v-else-if="deltaDir === 'down'" class="size-3.5" aria-hidden="true" />
          <Minus v-else class="size-3.5" aria-hidden="true" />
          {{ deltaText }}
        </span>
        <span v-if="hint">{{ hint }}</span>
      </p>
    </template>
  </Card>
</template>
